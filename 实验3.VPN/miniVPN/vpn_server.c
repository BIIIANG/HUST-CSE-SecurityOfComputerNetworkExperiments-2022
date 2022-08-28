#include <arpa/inet.h>
#include <crypt.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <shadow.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "vpn.h"

/* define HOME to be dir for key and cert files... */
#define HOME "./cert_server/"

/* Make these what you want for cert & key files */
#define CERTF HOME "server.crt"
#define KEYF HOME "server.key"
#define CACERT HOME "ca.crt"

#define BUF_SIZE 65536

typedef struct {
    char* pathname;
    SSL* ssl;
} PIPE_SSL;

SSL* setupTLSServer() {
    int ret;

    // Step 0: OpenSSL library initialization
    SSL_library_init();
    SSL_load_error_strings();

    // Step 1: SSL context initialization
    const SSL_METHOD* meth = SSLv23_server_method();
    SSL_CTX* ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    ret = SSL_CTX_load_verify_locations(ctx, CACERT, NULL);
    CHK_SSL_STR_EXIT(ret != 1, "[-] Load verify location failed\n", SETUP_TLS_ERROR);

    // Step 2: Set up the server certificate and private key
    ret = SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM);
    CHK_SSL_EXIT(ret <= 0, SETUP_TLS_ERROR);
    ret = SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM);
    CHK_SSL_EXIT(ret <= 0, SETUP_TLS_ERROR);
    ret = SSL_CTX_check_private_key(ctx);
    CHK_SSL_STR_EXIT(ret != 1, "[-] Private key does not match the certificate public key!\n", SETUP_TLS_ERROR);

    // Step 3: Create a new SSL structure for a connection
    SSL* ssl = SSL_new(ctx);
    CHK_SSL_EXIT(ssl == NULL, SETUP_TLS_ERROR);

    printf("[+] Setup TLS server done!\n");
    return ssl;
}

int setupTCPServer() {
    int ret;

    int listen_sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_EXP_STR_EXIT(listen_sock == -1, "[-] Create TCP socket failed! (%d: %s)\n", SETUP_TCP_ERROR, errno, strerror(errno));

    struct sockaddr_in sa_server;
    memset(&sa_server, 0, sizeof(sa_server));
    sa_server.sin_family = AF_INET;
    sa_server.sin_addr.s_addr = INADDR_ANY;
    sa_server.sin_port = htons(VPN_SERVER_PORT);

    ret = bind(listen_sock, (struct sockaddr*)&sa_server, sizeof(sa_server));
    CHK_EXP_STR_EXIT(ret == -1, "[-] Bind failed! (%d: %s)\n", SETUP_TCP_ERROR, errno, strerror(errno));

    ret = listen(listen_sock, 5);
    CHK_EXP_STR_EXIT(ret == -1, "[-] Listen failed! (%d: %s)\n", SETUP_TCP_ERROR, errno, strerror(errno));

    printf("[+] Setup TCP server done!\n");
    return listen_sock;
}

int createTunDevice() {
    int ret;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

    int tunfd = open("/dev/net/tun", O_RDWR);
    CHK_EXP_STR_EXIT(tunfd == -1, "[-] Open /dev/net/tun failed! (%d: %s)\n", TUN_DEVICE_ERROR, errno, strerror(errno));

    ret = ioctl(tunfd, TUNSETIFF, &ifr);
    CHK_EXP_STR_EXIT(ret == -1, "[-] Setup TUN interface by ioctl failed! (%d: %s)\n", TUN_DEVICE_ERROR, errno, strerror(errno));

    printf("[+] Setup TUN interface done!\n");
    return tunfd;
}

int login(char* username, char* password) {
    struct spwd* pw = getspnam(username);
    CHK_EXP_STR_RET_VAL(pw == NULL, "[-] Login failed: no such user.\n", AUTHENTICATION_ERROR);

    printf("[~] Username : %s\n", pw->sp_namp);
    printf("[~] Password [Enc] : %s\n", pw->sp_pwdp);
    char* epasswd = crypt(password, pw->sp_pwdp);
    CHK_EXP_STR_RET_STR(strcmp(epasswd, pw->sp_pwdp), "[-] Login failed: wrong password.\n", AUTHENTICATION_ERROR, "[+] Login done!\n");

    return NO_ERROR;
}

void* TUN2PIPE(void* tunfd_a) {
    int tunfd = *((int*)tunfd_a);
    char buf[BUF_SIZE];
    while (1) {
        fd_set readFDSet;
        FD_ZERO(&readFDSet);
        FD_SET(tunfd, &readFDSet);
        select(tunfd + 1, &readFDSet, NULL, NULL, NULL);
        if (FD_ISSET(tunfd, &readFDSet)) {
            int len = read(tunfd, buf, BUF_SIZE);
            if (len != -1) {
                // Check if this packet has an unbroken IPv4 header.
                if (len > 0 && buf[0] == 0x45 && len >= 20) {
                    unsigned int dstIP = (unsigned char)buf[19];
                    char pipeFileName[64];
                    // printf("[+] Receive from TUN, IP.DST = " VPN_VIRTUAL_IP_POOL "%u!\n", dstIP);
                    // Write data to pipe.
                    snprintf(pipeFileName, 64, "./pipe/" VPN_VIRTUAL_IP_POOL "%u", dstIP);
                    int pipefd = open(pipeFileName, O_WRONLY);
                    if (pipefd != -1) {
                        write(pipefd, buf, len);
                        printf("[o] TUN => ./pipe/" VPN_VIRTUAL_IP_POOL "%u.\n", dstIP);
                    } else {
                        printf("[-] Write packet to pipe file ./pipe/" VPN_VIRTUAL_IP_POOL "%u failed! (%d: %s)\n", dstIP, errno, strerror(errno));
                    }
                } else {
                    // printf("[-] Receive from TUN done, but a wrong packet!\n");
                }
            } else {
                printf("[-] Receive from TUN failed! (%d: %s)\n", errno, strerror(errno));
            }
        }
    }
}

void* PIPE2SSL(void* pipe_ssl_a) {
    PIPE_SSL* pipe_ssl = (PIPE_SSL*)pipe_ssl_a;

    // Open pipe.
    int pipefd = open(pipe_ssl->pathname, O_RDONLY);
    CHK_EXP_STR_EXIT(pipefd == -1, "[-] Open pipe %s failed! (%d: %s)\n", PIPE_ERROR, pipe_ssl->pathname, errno, strerror(errno));

    // Read data from pipe and send it to user matchine by SSL connection.
    char buf[BUF_SIZE];
    int len;
    do {
        len = read(pipefd, buf, BUF_SIZE - 1);
        CHK_EXP_STR_EXIT(len <= 0, "[-] Read data from pipe %s failed! (%d: %s)\n", PIPE_ERROR, pipe_ssl->pathname, errno, strerror(errno));
        printf("[o] PIPE %s => SSL: \n", pipe_ssl->pathname);
        printPrintable(buf, len);
        SSL_write(pipe_ssl->ssl, buf, len);
    } while (len > 0);

    printf("[+] Pipe %s close!", pipe_ssl->pathname);
}

void SSL2TUN(SSL* ssl, int tunfd) {
    int len;
    char buf[BUF_SIZE] = {0};
    do {
        len = SSL_read(ssl, buf, BUF_SIZE - 1);
        CHK_SSL_STR_RET(len <= 0, "[-] SSL read data failed!\n");

        int ret = write(tunfd, buf, len);
        CHK_EXP_STR_RET(ret == -1, "[-] Write data to TUN failed!\n")

        printf("[i] SSL => TUN: \n");
        printPrintable(buf, len);
    } while (len > 0);

    printf("[+] SSL close.\n");
}

int main() {
    int ret;

    /* TLS initialization */
    SSL* ssl = setupTLSServer();

    /* Create a TCP listen */
    int listen_sock = setupTCPServer();
    printf("[~] listen_sock = %d.\n", listen_sock);

    /* Create TUN and add route */
    int tunfd = createTunDevice();
    printf("[~] Creating and upping TUN ...\n");
    system("sudo ifconfig tun0 " VPN_SERVER_VIRTUAL_IP "/24 up");
    printf("[+] Creating and upping TUN done!\n");
    printf("[~] Set ip_forward and clear firewall ...\n");
    system("sudo sysctl net.ipv4.ip_forward=1 > /dev/null");
    system("sudo iptables -F");
    printf("[+] Set ip_forward and clear firewall done!\n");

    /* Create Named Pipe Dir */
    system("rm -rf pipe");
    mkdir("pipe", 0666);

    /* Create a Thread For listening to the TUN */
    pthread_t TUNThread;
    pthread_create(&TUNThread, NULL, TUN2PIPE, (void*)&tunfd);

    /* Accept the connection from client */
    struct sockaddr_in sa_client;
    size_t client_len = sizeof(sa_client);
    while (1) {
        int sock = accept(listen_sock, (struct sockaddr*)&sa_client, &client_len);
        printf("[~] Accept sock = %d.\n", sock);
        if (sock == -1) {
            printf("[-] Accept TCP connect failed! (%d: %s)\n", errno, strerror(errno));
            continue;
        }

        if (fork() == 0) {  // The child process
            close(listen_sock);

            // Get real IP of client.
            char clientRealIP[128] = {0};
            const char* retp = inet_ntop(AF_INET, &sa_client.sin_addr, clientRealIP, sizeof(clientRealIP));
            CHK_EXP_STR_EXIT(retp == NULL, "[-] Get client real IP failed!\n", INET_FUNC_ERROR);
            printf("[+] Client real IP: %s.\n", clientRealIP);

            // Establish connection with client.
            ret = SSL_set_fd(ssl, sock);
            CHK_SSL_STR_EXIT_STR(ret <= 0, "[-] SSL set fd failed!\n", SSL_CONNECTION_ERROR, "[+] SSL set fd done!\n");
            ret = SSL_accept(ssl);
            CHK_SSL_STR_EXIT_STR(ret <= 0, "[-] SSL accept failed!\n", SSL_CONNECTION_ERROR, "[+] SSL accept done!\n");
            printf("[+] SSL connection established!\n");

            // Get the login username & password to authenticate.
            char username[256] = {0}, password[256] = {0};
            ret = SSL_read(ssl, username, sizeof(username) - 1);
            CHK_SSL_STR_EXIT_STR(ret <= 0, "[-] SSL read username failed!\n", SSL_CONNECTION_ERROR, "[+] SSL read username done!\n");
            ret = SSL_read(ssl, password, sizeof(password) - 1);
            CHK_SSL_STR_EXIT_STR(ret <= 0, "[-] SSL read password failed!\n", SSL_CONNECTION_ERROR, "[+] SSL read password done!\n");

            int expectedIP = -1;
            if (login(username, password) != AUTHENTICATION_ERROR) {
                // Send authentication information.
                char authInfo[] = "[+] Login successfully!";
                ret = SSL_write(ssl, authInfo, strlen(authInfo));
                CHK_SSL_STR_EXIT_STR(ret <= 0, "[-] SSL send authentication information failed!\n", SSL_CONNECTION_ERROR, "[+] SSL send authentication information done!\n");

                // Negotiate the IP address and create pipe.
                char buf[256] = {0}, pipeFile[64] = {0};
                ret = SSL_read(ssl, buf, sizeof(buf) - 1);
                CHK_SSL_STR_EXIT_STR(ret <= 0, "[-] SSL read expected IP failed!\n", SSL_CONNECTION_ERROR, "[+] Send read expected IP done!\n");
                expectedIP = atoi(buf);
                if (expectedIP > 1 && expectedIP < 255) {
                    printf("[+] The IP client expected is " VPN_VIRTUAL_IP_POOL "%d!\n", expectedIP);
                    snprintf(pipeFile, sizeof(pipeFile), "./pipe/" VPN_VIRTUAL_IP_POOL "%d", expectedIP);
                    ret = mkfifo(pipeFile, 0666);
                    if (ret == -1) {
                        printf("[-] Make pipe failed! (%d: %s)\n", errno, strerror(errno));
                        expectedIP = -1;
                    }
                } else {
                    printf("[-] The IP client expected is invalid " VPN_VIRTUAL_IP_POOL "%d!\n", expectedIP);
                    expectedIP = -1;
                }

                if (expectedIP == -1) {
                    printf("[~] Try to alloc free IP ...\n");
                    for (expectedIP = 2; expectedIP <= 254; expectedIP++) {
                        snprintf(pipeFile, sizeof(pipeFile), "./pipe/" VPN_VIRTUAL_IP_POOL "%d", expectedIP);
                        if ((ret = mkfifo(pipeFile, 0666)) != -1) { break; }
                    }
                }

                if (ret == -1) {
                    printf("[-] Alloc IP failed!\n");
                    expectedIP = -1;
                    snprintf(buf, sizeof(buf), "%d", expectedIP);
                    SSL_write(ssl, buf, strlen(buf));
                    CHK_SSL_STR_EXIT_STR(ret <= 0, "[-] Send negotiate virtual IP failed!\n", SSL_CONNECTION_ERROR, "[+] Send negotiate virtual IP done!\n");
                } else {
                    printf("[+] Make pipe ./pipe/" VPN_VIRTUAL_IP_POOL "%d done!\n", expectedIP);
                    snprintf(buf, sizeof(buf), "%d", expectedIP);
                    ret = SSL_write(ssl, buf, strlen(buf));
                    if (ret <= 0) {
                        printf("[-] Send negotiate virtual IP failed!\n");
                    } else {
                        printf("[+] Send negotiate virtual IP done!\n");
                        printf("[+] %s's virtual IP: " VPN_VIRTUAL_IP_POOL "%d\n", clientRealIP, expectedIP);
                        PIPE_SSL pipe_ssl = {pipeFile, ssl};
                        pthread_t pipeThread;
                        pthread_create(&pipeThread, NULL, PIPE2SSL, (void*)&pipe_ssl);
                        SSL2TUN(ssl, tunfd);
                        pthread_cancel(pipeThread);
                    }
                    remove(pipeFile);
                    printf("[+] Remove pipe file %s done!\n", pipeFile);
                }

            } else {
                // Send authentication information.
                char authInfo[] = "[-] Login failed!";
                ret = SSL_write(ssl, authInfo, strlen(authInfo));
                CHK_SSL_STR_EXIT_STR(ret <= 0, "[-] Send authentication information failed!\n", SSL_CONNECTION_ERROR, "[+] Send authentication information done!\n");
            }

            // Disconnect with client and free resource.
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sock);
            if (expectedIP == -1) {
                printf("[+] Connection with %s (No virtual IP) closed!\n", clientRealIP);
            } else {
                printf("[+] Connection with %s (" VPN_VIRTUAL_IP_POOL "%d) closed!\n", clientRealIP, expectedIP);
            }
            return 0;

        } else {  // The parent process
            close(sock);
        }
    }
}
