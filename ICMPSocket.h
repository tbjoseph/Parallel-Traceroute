#pragma once

#ifndef ICMP_SOCKET_H
#define ICMP_SOCKET_H

#include "pch.h"
#include "DNSSocket.h"


struct probe {
    bool seen;
    bool echo;
    double start;
    double end;
    double rto;
    in_addr ip_addr;
    int hops;

    bool dns;
    int dns_hops;
    char host[MAX_HOST_LEN+1];
};


class ICMPSocket {
    SOCKET sock;
    u_char* send_buf;
    u_char* rec_buf;
    struct sockaddr_in remote;
    probe probe_list[31];

    HANDLE	socketReadyICMP;
    HANDLE	socketReadyDNS;

    LARGE_INTEGER frequency, time;

    DNSSocket dns_socket;


    // char* host; // current host
    // int tx_id; // current ID
    // u_short query_type; // DNS_A or DNS_PTR
    // int recv_bytes;

    // bool Read(size_t max_download_size, bool printInfo = true);
    // bool Connect(const sockaddr_in& server, const char* host, const char* request, const char* method, const char* valid_codes, size_t max_download_size, bool asterisk, bool& isCodeValid, bool printInfo = true, LONG volatile* stats = nullptr);
    // bool FlipIP(char* reversed_ip, int size);
    // int CreateRequest();
    // bool MakeDNSquestion(void* request_buf);
    // __int64 ParseResponse();
    // int ParseHost(char* buf, char* destination);
    // bool ParseAnswer(char* &curr_pos, int count);

public:
    ICMPSocket() : sock(-1), send_buf(nullptr), rec_buf(nullptr) {
        socketReadyDNS = CreateEvent(NULL, false, false, NULL);
        socketReadyICMP = CreateEvent(NULL, false, false, NULL);

    };


    ~ICMPSocket() { if (sock != -1) Close(); };

    bool Open(char* input_host);
    bool Write(int ttl);
    bool Read();
    bool Trace();
    bool Close();
    
    // void Print();

};

#endif //DNS_SOCKET_H