#include <unistd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <errno.h>
#include <fcntl.h>
#include <libnet.h>
#include <netinet/udp.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>

/* IP Header */
struct ipheader {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    unsigned int   iph_hl:4, iph_v:4;           // IP Header length & Version.
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    unsigned int   iph_v:4, iph_hl:4;           // IP Header length & Version.
#endif
    uint8_t        iph_tos;                     // Type of service
    unsigned short iph_len;                     // IP Packet length (Both data and header)
    unsigned short iph_ident;                   // Identification
    unsigned short iph_flag:3, iph_offset:13;   // Flags and Fragmentation offset
    uint8_t        iph_ttl;                     // Time to Live
    uint8_t        iph_protocol;                // Type of the upper-level protocol
    unsigned short iph_chksum;                  // IP datagram checksum
    struct in_addr iph_sourceip;                // IP Source address (In network byte order)
    struct in_addr iph_destip;                  // IP Destination address (In network byte order)
};

/* Reference to struct ip in <netinet/ip.h> */
// struct ip {
// #if __BYTE_ORDER == __LITTLE_ENDIAN
//     unsigned int ip_hl:4;       /* header length */
//     unsigned int ip_v:4;        /* version */
// #endif
// #if __BYTE_ORDER == __BIG_ENDIAN
//     unsigned int ip_v:4;        /* version */
//     unsigned int ip_hl:4;       /* header length */
// #endif
//     uint8_t ip_tos;         /* type of service */
//     unsigned short ip_len;      /* total length */
//     unsigned short ip_id;       /* identification */
//     unsigned short ip_off;      /* fragment offset field */
// #define IP_RF 0x8000            /* reserved fragment flag */
// #define IP_DF 0x4000            /* dont fragment flag */
// #define IP_MF 0x2000            /* more fragments flag */
// #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
//     uint8_t ip_ttl;         /* time to live */
//     uint8_t ip_p;           /* protocol */
//     unsigned short ip_sum;      /* checksum */
//     struct in_addr ip_src, ip_dst;  /* source and dest address */
// };

/* UDP Header */
struct udpheader {
    uint16_t udph_srcport;      // source port
    uint16_t udph_destport;     // destination port
    uint16_t udph_len;          // udp length
    uint16_t udph_chksum;       // udp checksum
};

/* Reference to struct udphdr in <netinet/udp.h> */
// struct udphdr
// {
//   __extension__ union
//   {
//    struct
//    {
//      uint16_t uh_sport;    /* source port */
//      uint16_t uh_dport;    /* destination port */
//      uint16_t uh_ulen;     /* udp length */
//      uint16_t uh_sum;      /* udp checksum */
//    };
//     struct
//     {
//       uint16_t source;
//       uint16_t dest;
//       uint16_t len;
//       uint16_t check;
//     };
//   };
// };

/* DNS Header */
struct dnsheader {
    uint16_t query_id;
    uint16_t flags;
    uint16_t QDCOUNT;
    uint16_t ANCOUNT;
    uint16_t NSCOUNT;
    uint16_t ARCOUNT;
};

// Just calculate the sum of the buffer.
uint32_t checksum(uint16_t* buffer, int byte_size) {
    uint32_t cksum = 0;
    for (; byte_size > 1; byte_size -= 2) { cksum += *buffer++; }
    if (byte_size == 1) { cksum += *(uint16_t*)buffer; }
    return (cksum);
}

// Function for checksum calculation. From the RFC,
// the checksum algorithm is:
//  "The checksum field is the 16 bit one's complement of the one's
//  complement sum of all 16 bit words in the header.  For purposes of
//  computing the checksum, the value of the checksum field is zero."
uint16_t checksum_word(uint16_t* buffer, int word_size) {
    uint32_t sum;
    for (sum = 0; word_size > 0; word_size--) { sum += *buffer++; }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

// Calculate UDP checksum.
uint16_t udp_checksum(uint8_t* buffer, int udp_byte_size) {
    uint32_t sum = 0;
    struct ipheader* ipHeader = (struct ipheader*)(buffer);
    struct udpheader* udpHeader = (struct udpheader*)(buffer + sizeof(struct ipheader));

    /* Set checknum to 0. */
    udpHeader->udph_chksum = 0;

    /* Add sequential 16 bit words to sum. */
    sum = checksum((uint16_t*)&(ipHeader->iph_sourceip), 4);    // SrcIP
    sum += checksum((uint16_t*)&(ipHeader->iph_destip), 4);     // DestIP
    sum += htons(IPPROTO_UDP);                                  // Protocol
    sum += htons(udp_byte_size);                                // Udp_len
    sum += checksum((uint16_t*)udpHeader, udp_byte_size);       // Udp
    
    /* Add back carry outs from top 16 bits to low 16 bits. */
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

// Calculate IP checksum.
uint16_t ip_checksum(uint8_t* buffer) {
    struct ipheader* ipHeader = (struct ipheader*)(buffer);
    ipHeader->iph_chksum = 0;
    return checksum_word((uint16_t*)buffer, sizeof(struct ipheader) / 2);
}
