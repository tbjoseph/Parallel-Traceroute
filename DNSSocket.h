#pragma once

#ifndef DNS_SOCKET_H
#define DNS_SOCKET_H

#include "pch.h"


#define MAX_HOST_LEN		256
#define MAX_ATTEMPTS        3 
#define STATUS_OK           0x0 
#define DEPTH_LIMIT         (512 / 2)

/* DNS query types */
#define DNS_A 1 /* name -> IP */
#define DNS_NS 2 /* name server */
#define DNS_CNAME 5 /* canonical name */
#define DNS_PTR 12 /* IP -> name */
#define DNS_HINFO 13 /* host info/SOA */
#define DNS_MX 15 /* mail exchange */
#define DNS_AXFR 252 /* request for zone transfer */
#define DNS_ANY 255 /* all records */
#define MAX_DNS_LEN 512

/* query classes */
#define DNS_INET 1

/* flags */
#define DNS_QUERY (0 << 15) /* 0 = query; 1 = response */
#define DNS_RESPONSE (1 << 15)

#define DNS_STDQUERY (0 << 11) /* opcode - 4 bits */

#define DNS_AA (1 << 10) /* authoritative answer */
#define DNS_TC (1 << 9) /* truncated */
#define DNS_RD (1 << 8) /* recursion desired */
#define DNS_RA (1 << 7) /* recursion available */ 

#pragma pack(push,1)

struct QueryHeader {
    u_short type;
    u_short class_;
};

struct DNSanswerHdr {
    u_short type;
    u_short class_;
    u_int ttl;
    u_short len;
};

struct FixedDNSheader {
    u_short ID;
    u_short flags;
    u_short questions;
    u_short answers;
    u_short authority;
    u_short additional;
};

#pragma pack(pop) 

class DNSSocket {
    char buf_2[MAX_HOST_LEN + 1]; // current host2

    char* host; // current host
    int tx_id; // current ID
    u_short query_type; // DNS_A or DNS_PTR
    char packet[MAX_DNS_LEN]; // 512 bytes is max
    int recv_bytes;
    SOCKET sock;
    char buf[MAX_HOST_LEN + 1];
    char question_host[MAX_HOST_LEN + 1];
    char reversed[25];
    struct sockaddr_in remote;

    // bool Read(size_t max_download_size, bool printInfo = true);
    // bool Connect(const sockaddr_in& server, const char* host, const char* request, const char* method, const char* valid_codes, size_t max_download_size, bool asterisk, bool& isCodeValid, bool printInfo = true, LONG volatile* stats = nullptr);
    bool FlipIP(char* reversed_ip, int size);
    int CreateRequest();
    bool MakeDNSquestion(void* request_buf);
    __int64 ParseResponse();
    int ParseHost(char* buf, char* destination);
    bool ParseAnswer(char*& curr_pos, int count);

public:
    DNSSocket() : tx_id(1), recv_bytes(0) {
        
    };

    ~DNSSocket() {
        closesocket(sock);
    }


    bool Write(char* input_host, char* input_server);


    bool Open(char* input_server);

    bool Write_(char* input_host);
    bool Read();

    char* getQuestion() {
        FlipIP2(question_host, reversed, 25);
        return reversed;
    };

    char* getReversed() {
        return reversed;
    };

    char* getAnswer() { return buf; };
    SOCKET getSock() { return sock; };
    bool FlipIP2(char* original, char* reversed_ip, int size);


    // void Print();

};

#endif //DNS_SOCKET_H