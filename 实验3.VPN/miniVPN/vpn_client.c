#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "vpn.h"

/* define HOME to be dir for key and cert files... */
#define HOME "./cert_client/"

/* Make these what you want for cert & key files */
#define CERTF HOME "client.crt"
#define KEYF HOME "client.key"
#define CACERT HOME "ca.crt"

#define BUF_SIZE 65536

typedef struct {
    int tunfd;
    SSL* ssl;
} TUN_SSL;

int verify_callback(int preverify_ok, X509_STORE_CTX* x509_ctx) {
    char buf[300];

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME_oneline(X509_get_subject_name(cert), buf, 300);
    printf("[~] subject: %s.\n", buf);

    if (preverify_ok == 1) {
        printf("[+] Verification passed.\n");
    } else {
        int err = X509_STORE_CTX_get_error(x509_ctx);
        printf("[~] Verification error: %s.\n", X509_verify_cert_error_string(err));
        switch (err) {
            // case X509_V_ERR_CERT_NOT_YET_VALID:
            // case X509_V_ERR_CERT_HAS_EXPIRED:
            case X509_V_ERR_HOSTNAME_MISMATCH:
                printf("[+] Verification error ignored!\n");
                preverify_ok = 1;
                break;
            default:
                printf("[-] Verification failed: %s.\n", X509_verify_cert_error_string(err));
        }
    }

    return preverify_ok;
}

SSL* setupTLSClient(const char* hostname) {
    int ret;

    // Step 0: OpenSSL library initialization
    SSL_library_init();
    SSL_load_error_strings();

    // Step 1: SSL context initialization
    const SSL_METHOD* meth = SSLv23_client_method();
    SSL_CTX* ctx = SSL_CTX_new(meth);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
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

    X509_VERIFY_PARAM* vpm = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set1_host(vpm, hostname, 0);

    printf("[+] Setup TLS client done!\n");
    return ssl;
}

int setupTCPClient(const char* hostname, int port) {
    int ret;

    struct hostent* hp = gethostbyname(hostname);
    CHK_EXP_STR_EXIT(hp == NULL, "[-] Connect to destination failed! (%d: %s)\n", SETUP_TCP_ERROR, h_errno, hstrerror(h_errno));

    int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    CHK_EXP_STR_EXIT(sockfd == -1, "[-] Create TCP socket failed! (%d: %s)\n", SETUP_TCP_ERROR, errno, strerror(errno));

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    memcpy(&(server_addr.sin_addr.s_addr), hp->h_addr, hp->h_length);
    server_addr.sin_port = htons(port);
    server_addr.sin_family = AF_INET;

    ret = connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    CHK_EXP_STR_EXIT(ret == -1, "[-] Connect to destination failed! (%d: %s)\n", SETUP_TCP_ERROR, errno, strerror(errno));

    printf("[+] Setup TCP client done!\n");
    return sockfd;
}

void sendAuthentication(SSL* ssl, const char* username, const char* password) {
    int ret;

    // Send username & password.
    ret = SSL_write(ssl, username, strlen(username));
    CHK_SSL_STR_EXIT(ret <= 0, "[-] SSL write username failed!\n", AUTHENTICATION_ERROR);
    ret = SSL_write(ssl, password, strlen(password));
    CHK_SSL_STR_EXIT(ret <= 0, "[-] SSL write password failed!\n", AUTHENTICATION_ERROR);
    printf("[+] SSL write authentication done!\n");

    // Receive the authentication result.
    char buf[BUF_SIZE] = {0};
    ret = SSL_read(ssl, buf, BUF_SIZE - 1);
    CHK_SSL_STR_EXIT(ret <= 0, "[-] SSL authentication failed!\n", AUTHENTICATION_ERROR);
    printf("[+] Authentication result: %s\n", buf);
    CHK_SSL_STR_EXIT(ret > 2 && buf[1] == '-', "[-] Authentication failed, connection shutdown!\n", AUTHENTICATION_ERROR);
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

void SSL2TUN(TUN_SSL tun_ssl) {
    char buf[BUF_SIZE] = {0};
    int len = SSL_read(tun_ssl.ssl, buf, BUF_SIZE - 1);
    CHK_SSL_STR_RET(len <= 0, "[-] SSL read data failed!\n");

    int ret = write(tun_ssl.tunfd, buf, len);
    CHK_EXP_STR_RET(ret == -1, "[-] Write data to TUN failed!\n")

    printf("[i] SSL => TUN: \n");
    printPrintable(buf, len);
}

void TUN2SSL(TUN_SSL tun_ssl) {
    char buf[BUF_SIZE] = {0};
    int len = read(tun_ssl.tunfd, buf, BUF_SIZE - 1);
    CHK_EXP_STR_RET(len == -1, "[-] Read data from TUN failed!\n")
    // CHK_EXP_STR_RET(len < 20 || buf[0] != 0x45, "[-] Read data from TUN: wrong packet!\n");

    if (len >= 20 && buf[0] == 0x45) {
        int ret = SSL_write(tun_ssl.ssl, buf, len);
        CHK_SSL_STR_RET(ret <= 0, "[-] SSL write data failed!\n");

        printf("[o] TUN => SSL: \n");
        printPrintable(buf, len);
    }
}

int main(int argc, char* argv[]) {
    int ret;
    srand(time(NULL));

    int port = 0;
    char hostname[128] = {0}, portStr[128] = {0};
    printf("[~] Server IP: ");
    scanf("%127s", hostname);
    printf("[~] Server PORT: ");
    scanf("%d", &port);

    /* TLS initialization */
    SSL* ssl = setupTLSClient(hostname);

    /* Create a TCP connection */
    int sockfd = setupTCPClient(hostname, port);

    /* TLS handshake */
    SSL_set_fd(ssl, sockfd);
    CHK_SSL_STR_EXIT(ssl == NULL, "[-] SSL set fd failed.\n", SETUP_TLS_ERROR);
    ret = SSL_connect(ssl);
    CHK_SSL_STR_EXIT(ret <= 0, "[-] SSL connect failed.\n", SETUP_TLS_ERROR);
    printf("[+] SSL connection done, using %s.\n", SSL_get_cipher(ssl));

    /* Authenticate */
    // getconf LOGIN_NAME_MAX => 256
    char username[256] = {0};
    printf("[~] Username: ");
    ret = scanf("%255s", username);
    CHK_EXP_STR_EXIT(ret <= 0, "[-] Scanf username failed!\n", AUTHENTICATION_ERROR);
    char* password = getpass("[~] Password(No Echoing): ");
    CHK_EXP_STR_EXIT(password == NULL, "[-] Scanf password failed!\n", AUTHENTICATION_ERROR);
    sendAuthentication(ssl, username, password);

    /* Negotiate virtual IP */
    int virtualIP = 0;
    printf("[~] Your expected IP: " VPN_VIRTUAL_IP_POOL);
    scanf("%d", &virtualIP);
    char virtualIPStr[256] = {0};
    snprintf(virtualIPStr, sizeof(virtualIPStr), "%d", virtualIP);
    ret = SSL_write(ssl, virtualIPStr, strlen(virtualIPStr));
    CHK_SSL_STR_EXIT(ret <= 0, "[-] SSL send expected IP failed!\n", SSL_CONNECTION_ERROR);
    printf("[+] SSL send expected IP " VPN_VIRTUAL_IP_POOL "%d done!\n", virtualIP);

    memset(virtualIPStr, 0, sizeof(virtualIPStr));
    ret = SSL_read(ssl, virtualIPStr, sizeof(virtualIPStr) - 1);
    CHK_SSL_STR_EXIT(ret <= 0, "[-] SSL read virtual IP failed!\n", SSL_CONNECTION_ERROR);
    CHK_EXP_STR_EXIT((virtualIP = atoi(virtualIPStr)) == -1, "[-] SSL negotiate virtual IP failed!\n", SSL_CONNECTION_ERROR);
    printf("[+] SSL negotiate virtual IP done: " VPN_VIRTUAL_IP_POOL "%d!\n", virtualIP);

    /* Create TUN and add route */
    int tunfd = createTunDevice();
    char cmd[256] = {0};
    snprintf(cmd, 256, "sudo ifconfig tun0 " VPN_VIRTUAL_IP_POOL "%d/24 up", virtualIP);
    printf("[~] Creating and upping TUN ...\n");
    system(cmd);
    printf("[+] Creating and upping TUN done!\n");
    printf("[~] Adding route ...\n");
    system("sudo route add -net " VPN_INTERNAL_NET " tun0");
    printf("[+] Adding route done!\n");

    /* Send/Receive data */
    TUN_SSL tun_ssl = {tunfd, ssl};
    struct tcp_info info;
    int len = sizeof(info);

    while (1) {
        getsockopt(sockfd, IPPROTO_TCP, TCP_INFO, &info, (socklen_t*)&len);
        if (info.tcpi_state == TCP_ESTABLISHED) {
            fd_set fdset;
            FD_ZERO(&fdset);
            FD_SET(sockfd, &fdset);
            FD_SET(tunfd, &fdset);
            select((sockfd > tunfd ? sockfd : tunfd) + 1, &fdset, NULL, NULL, NULL);
            if (FD_ISSET(sockfd, &fdset)) { SSL2TUN(tun_ssl); }
            if (FD_ISSET(tunfd, &fdset)) { TUN2SSL(tun_ssl); }
        } else {
            printf("Connection closed by server.\n");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sockfd);
            return 0;
        }
    }
}
