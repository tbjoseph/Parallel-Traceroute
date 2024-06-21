#include "pch.h"
#include "DNSSocket.h"

bool DNSSocket::ParseAnswer(char*& curr_pos, int count) {
    DNSanswerHdr* ah;
    const char* type;
    char answer_host[MAX_HOST_LEN + 1];
    char* answer_answer;
    for (u_short i = 0; i < count; i++) {
        // for (size_t i = 0; i < 30; i++) {
        //     u_char x = answers[i];
        //     printf("%02X ", x);
        // }
        // printf("\n\n");

        int bytes = ParseHost(curr_pos, answer_host);
        if (bytes == -1) return false;

        ah = (DNSanswerHdr*)(curr_pos + bytes);
        curr_pos = (char*)(ah + 1);

        if ((curr_pos - 1) >= (packet + recv_bytes)) {
            printf("  ++ invalid record: truncated RR answer header (i.e., don't have the full 10 bytes)\n");
            return false;
        }
        if ((curr_pos + ntohs(ah->len) - 1) >= (packet + recv_bytes)) {
            printf("   ++ invalid record: RR value length stretches the answer beyond packet\n");
            return false;
        }


        // if ( (curr_pos + ntohs(ah->len) - 1)  >= (packet + recv_bytes) ) {
        //     if (i != (count-1)) {
        //         printf("  ++ invalid section: not enough records (declared %d records but only %d found)\n", count, i);
        //     }
        //     else {
        //         printf("   ++ invalid record2: RR value length stretches the answer beyond packet\n");
        //     }
        //     return false;
        // }
        // if ( (curr_pos + ntohs(ah->len))  >= (packet + recv_bytes) ) {
        //     if (i != (count-1)) {
        //         printf("  ++ invalid section: not enough records (declared %d records but only %d found)\n", count, i);
        //     }
        //     else {
        //         printf("   ++ invalid record3: RR value length stretches the answer beyond packet\n");
        //     }
        //     return false;
        // }

        switch (ntohs(ah->type))
        {
        case DNS_A:
            in_addr ipAdress;
            ipAdress.s_addr = *(u_int*)curr_pos;
            answer_answer = inet_ntoa(ipAdress);
            break;
        case DNS_PTR:
        case DNS_NS:
        case DNS_CNAME:
            bytes = ParseHost(curr_pos, buf);
            if (bytes == -1) return false;
            answer_answer = buf;
            break;
        default:
            curr_pos += ntohs(ah->len);
            continue;
            break;
        }

        if ((curr_pos + ntohs(ah->len)) >= (packet + recv_bytes)) {
            if (i != (count - 1)) {
                printf("  ++ invalid section: not enough records (declared %d records but only %d found)\n", count, i);
                return false;
            }
        }

        switch (ntohs(ah->type)) {
        case DNS_A:
            type = "A";
            break;
        case DNS_NS:
            type = "NS";
            break;
        case DNS_CNAME:
            type = "CNAME";
            break;
        case DNS_PTR:
            type = "PTR";
            break;
        case DNS_HINFO:
            type = "HINFO";
            break;
        case DNS_MX:
            type = "MX";
            break;
        case DNS_AXFR:
            type = "AXFR";
            break;
        default:
            type = "UNKNOWN";
            break;
        }

        //printf("\t%s %s %s TTL = %d\n", answer_host, type, answer_answer, ntohs(ah->ttl));
        curr_pos += ntohs(ah->len);
    }

    return true;
}

int DNSSocket::ParseHost(char* host_, char* destination) {
    u_char size;
    int bytes_read = 0;
    int bytes_before_jump = 0;
    bool jump_occured = false; // bool for checking if a jump has occurred
    int depth = 0;

    while (true) {
        if (depth >= DEPTH_LIMIT) {
            printf("  ++ invalid record: jump loop \n");
            return -1;
        }

        size = *host_;
        if (size >= 0xC0) {
            if (!jump_occured) {
                bytes_before_jump = bytes_read; // save byte position before first jump
            }
            jump_occured = true;

            if ((host_ + 1) >= (packet + recv_bytes))
            {
                printf("  ++ invalid record: truncated jump offset (e.g., 0xC0 and the packet ends)\n");
                return -1;
            }
            int off = ((size & 0x3F) << 8) + host_[1];
            if (off >= recv_bytes) {
                printf("  ++ invalid record: jump beyond packet boundary\n");
                return -1;
            }
            if (off < sizeof(FixedDNSheader)) {
                printf("  ++ invalid record: jump into fixed DNS header \n");
                return -1;
            }


            host_ = packet + off;
            depth++;
            continue;
        }

        host_++; // 1 past the size byte to get to start of host section
        bytes_read += (size + 1); // size byte and following bytes to read. check before reading
        if (size == 0) break;
        if ((host_ + size - 1) >= (packet + recv_bytes)) {
            printf("  ++ invalid record: truncated name (e.g., '6 goog' and the packet ends)\n");
            return -1;
        }
        memcpy(destination, host_, size);
        destination[size] = '.'; // terminate host section with .
        destination += (size + 1); // get to next host section to copy into
        host_ += size; // get to byte of the size of string
    }
    destination[size - 1] = '\0';

    if (jump_occured) {
        return bytes_before_jump + 2;
    }

    return bytes_read;
}

__int64 DNSSocket::ParseResponse() {
    FixedDNSheader* fdh = (FixedDNSheader*)packet;
    u_short flags = ntohs(fdh->flags);
    //printf("  TXID 0x%.4X, flags 0x%.4X, questions %d, answers %d, authority %d, additional %d\n", 
    //ntohs(fdh->ID), flags, ntohs(fdh->questions), ntohs(fdh->answers), ntohs(fdh->authority), ntohs(fdh->additional));

    u_short result = flags & 0x000F; // Extracts the last 4 bits
    if (result == STATUS_OK) {
        //printf ("  succeeded with Rcode = %d\n", result);
    }
    else if (result == 3) {
        // printf ("  failed with Rcode = %d\n", ff->misc);
        //printf("  failed with Rcode = %d\n", result);
        strcpy_s(buf, MAX_HOST_LEN + 1, "<no DNS entry>");
    }
    else return -1;

    char* host_ = (char*)(fdh + 1);
    if (ntohs(fdh->questions) > 0) { // fdh->questions should always be 1
        //printf("  ------------ [questions] ----------\n");
        QueryHeader* qh;
        for (u_short i = 0; i < ntohs(fdh->questions); i++) {
            int bytes = ParseHost(host_, question_host);
            if (bytes == -1) return -1;

            // printf("%d\n", bytes);
            qh = (QueryHeader*)(host_ + bytes);
            //printf("\t%s type %d class %d\n", question_host, ntohs(qh->type), ntohs(qh->class_));
            host_ = (char*)(qh + 1);
        }
    }


    if (ntohs(fdh->answers) > 0) {
        //printf("  ------------ [answers] ------------\n");
        if (!ParseAnswer(host_, ntohs(fdh->answers))) {
            return -1;
        }
    }

    __int64 total_bytes = (host_ - ((char*)packet));
    return total_bytes;

    if (ntohs(fdh->authority) > 0) {
        printf("  ------------ [authority] ------------\n");
        if (!ParseAnswer(host_, ntohs(fdh->authority))) {
            return -1;
        }
    }

    if (ntohs(fdh->additional) > 0) {
        printf("  ------------ [additional] ------------\n");
        if (!ParseAnswer(host_, ntohs(fdh->additional))) {
            return -1;
        }


    }

    /*__int64 total_bytes = (host_ - ((char*)packet));
    return total_bytes;*/
}

bool DNSSocket::MakeDNSquestion(void* request_buf) {
    char* buf = (char*)request_buf;
    char* dot = strchr(host, '.');
    char* next_word = host;
    u_char size_of_next_word;
    int i = 0;

    while (dot != NULL) {
        size_of_next_word = (u_char)(dot - next_word);
        buf[i++] = size_of_next_word;
        memcpy(buf + i, next_word, size_of_next_word);
        i += size_of_next_word;
        next_word = host + i;
        dot = strchr(next_word, '.');
    }
    size_of_next_word = (u_char)strlen(next_word);
    buf[i++] = size_of_next_word;
    memcpy(buf + i, next_word, size_of_next_word);
    i += size_of_next_word;
    buf[i] = 0; // last word NULL-terminated 
    return true;
}

int DNSSocket::CreateRequest() {
    if (strlen(host) > MAX_HOST_LEN)
    {
        printf("host is too long\n");
        return -1;
    }
    int pkt_size = (int)strlen(host) + 2 + sizeof(FixedDNSheader) + sizeof(QueryHeader);

    // fixed field initialization
    FixedDNSheader* dh = (FixedDNSheader*)packet;
    QueryHeader* qh = (QueryHeader*)(packet + pkt_size - sizeof(QueryHeader));
    dh->ID = htons(tx_id++);
    dh->flags = htons(DNS_QUERY | DNS_RD | DNS_STDQUERY);
    dh->questions = htons(1);
    dh->answers = 0;
    dh->authority = 0;
    dh->additional = 0;
    qh->type = htons(query_type);
    qh->class_ = htons(DNS_INET);

    // fill in the question
    MakeDNSquestion(dh + 1); // dh + 1 = packet + sizeof(FixedDNSheader) = location right after the FixedDNSheader

    // transmit to Winsock
    // sendto (sock, packet, ...);

    return pkt_size;
}

bool DNSSocket::FlipIP(char* reversed_ip, int size) {

    char* ip_parts[4];
    const char delimeters[] = "."; // delimiter .
    char* next_token = NULL;

    ip_parts[0] = strtok_s(host, delimeters, &next_token);
    for (size_t i = 1; i < 4; i++) {
        ip_parts[i] = strtok_s(NULL, delimeters, &next_token); // get next token
    }
    sprintf_s(reversed_ip, size, "%s.%s.%s.%s.in-addr.arpa", ip_parts[3], ip_parts[2], ip_parts[1], ip_parts[0]);


    return true;
}


bool DNSSocket::FlipIP2(char* original, char* reversed_ip, int size) {

    char* ip_parts[4];
    const char delimeters[] = "."; // delimiter .
    char* next_token = NULL;

    ip_parts[0] = strtok_s(original, delimeters, &next_token);
    for (size_t i = 1; i < 4; i++) {
        ip_parts[i] = strtok_s(NULL, delimeters, &next_token); // get next token
    }
    sprintf_s(reversed_ip, size, "%s.%s.%s.%s", ip_parts[3], ip_parts[2], ip_parts[1], ip_parts[0]);


    return true;
}


bool DNSSocket::Write(char* input_host, char* input_server) {

    host = input_host;
    printf("Lookup  : %s\n", host);

    // ***** Decide query type
    if (inet_addr(host) == INADDR_NONE) {
        // Query type A : host to IP
        query_type = DNS_A;
    }
    else {
        // Query type PTR : IP to host
        query_type = DNS_PTR;
        char reversed_ip[29]; // strlen(xxx.xxx.xxx.xxx.in-addr.arpa) + 1
        FlipIP(reversed_ip, 29);
        host = reversed_ip;
    }




    // bind localsock to port 0
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(0);
    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        printf("bind() generated error %d\n", WSAGetLastError());
        return false;
    }
    // set remote sock to port 53
    struct sockaddr_in remote;
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.S_un.S_addr = inet_addr(input_server); // server’s IP //Double check .S_un.S_addr
    remote.sin_port = htons(53); // DNS port on server  


    // ***** Send request and recieve response
    printf("Query   : %s, type %d, TXID 0x%.4X\n", host, query_type, tx_id);
    printf("Server  : %s\n", input_server);
    printf("********************************\n");

    int len = CreateRequest();
    int count = 0;
    bool succeeded = false;
    __int64 bytes_read;

    while (count++ < MAX_ATTEMPTS) {
        printf("Attempt %d with %d bytes... ", count - 1, len);
        clock_t start = clock();

        if (sendto(sock, packet, len, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR) {
            printf("sendto error: %d\n", WSAGetLastError());
            continue; // ???
        }

        struct timeval timeout;
        timeout.tv_sec = 10;  // 10 seconds
        timeout.tv_usec = 0;  // 0 microseconds
        fd_set fd;   // file descriptor
        FD_ZERO(&fd);
        FD_SET(sock, &fd);

        int ret = select(0, &fd, NULL, NULL, &timeout);
        if (ret > 0) {
            struct sockaddr_in response;
            int size_of_sockaddr = sizeof(sockaddr);

            recv_bytes = recvfrom(sock, packet, MAX_DNS_LEN, 0, (struct sockaddr*)&response, &size_of_sockaddr);
            if (recv_bytes == SOCKET_ERROR) {
                printf("recvfrom failed with error: %d\n", WSAGetLastError());
                continue; // ???
            }

            // check if this packet came from the server to which we sent the query earlier
            if (response.sin_addr.S_un.S_addr != remote.sin_addr.S_un.S_addr || response.sin_port != remote.sin_port) {
                printf("bogus reply\n");
                continue; // ???
            }

            clock_t end = clock();
            int elapsed_time = (int)((double)(end - start) / CLOCKS_PER_SEC * 1000);
            printf("response in %d ms with %d bytes\n", elapsed_time, recv_bytes);
            if (recv_bytes < sizeof(FixedDNSheader))
            {
                printf("  ++ invalid reply: packet smaller than fixed DNS header\n");
                return false;
            }

            bytes_read = ParseResponse();
            if (bytes_read == -1) return false;

            closesocket(sock);

            if (bytes_read < recv_bytes) {
                printf("  ++ invalid section: not enough records (e.g., declared 5 answers but only 3 found) ");
                return false;
            }
            return true;
        }
        else if (ret == 0) {
            clock_t end = clock();
            int elapsed_time = (int)((double)(end - start) / CLOCKS_PER_SEC * 1000);
            printf("timeout in %d ms\n", elapsed_time);
        }
        else {
            printf("select failed with error: %d\n", WSAGetLastError());
        }
    }
    closesocket(sock);
    return false;
}



bool DNSSocket::Write_(char* input_host) {



    strcpy_s(buf_2, MAX_HOST_LEN + 1, input_host);

    host = buf_2;

    // ***** Decide query type
    if (inet_addr(host) == INADDR_NONE) {
        // Query type A : host to IP
        query_type = DNS_A;
    }
    else {
        // Query type PTR : IP to host
        query_type = DNS_PTR;
        char reversed_ip[29]; // strlen(xxx.xxx.xxx.xxx.in-addr.arpa) + 1
        FlipIP(reversed_ip, 29);
        host = reversed_ip;
    }




    


    // ***** Send request and recieve response


    int len = CreateRequest();
    int count = 0;
    bool succeeded = false;
    __int64 bytes_read;

    clock_t start = clock();

    if (sendto(sock, packet, len, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR) {
        printf("sendto error: %d\n", WSAGetLastError());
        return false; // ???
    }

    return true;
}


bool DNSSocket::Read() {
    //struct timeval timeout;
    //timeout.tv_sec = 10;  // 10 seconds
    //timeout.tv_usec = 0;  // 0 microseconds
    //fd_set fd;   // file descriptor
    //FD_ZERO(&fd);
    //FD_SET(sock, &fd);

    //int ret = select(0, &fd, NULL, NULL, &timeout);

    struct sockaddr_in response;
    int size_of_sockaddr = sizeof(sockaddr);

    recv_bytes = recvfrom(sock, packet, MAX_DNS_LEN, 0, (struct sockaddr*)&response, &size_of_sockaddr);
    if (recv_bytes == SOCKET_ERROR) {
        printf("recvfrom failed with error: %d\n", WSAGetLastError());
        return false; // ???
    }

    //// check if this packet came from the server to which we sent the query earlier
    //if (response.sin_addr.S_un.S_addr != remote.sin_addr.S_un.S_addr || response.sin_port != remote.sin_port) {
    //    printf("bogus reply\n");
    //    return false; // ???
    //}

    //clock_t end = clock();
    //int elapsed_time = (int)((double)(end - start) / CLOCKS_PER_SEC * 1000);


    if (recv_bytes < sizeof(FixedDNSheader))
    {
        printf("  ++ invalid reply: packet smaller than fixed DNS header\n");
        return false;
    }

    int bytes_read = ParseResponse();
    if (bytes_read == -1) return false;

    

    return true;
}


bool DNSSocket::Open(char* input_server) {
    // ***** Bind sock
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) {
        printf("socket() generated error %d\n", WSAGetLastError());
    }


    // bind localsock to port 0
    struct sockaddr_in local;
    memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(0);
    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) == SOCKET_ERROR) {
        printf("bind() generated error %d\n", WSAGetLastError());
        return false;
    }
    // set remote sock to port 53
    
    memset(&remote, 0, sizeof(remote));
    remote.sin_family = AF_INET;
    remote.sin_addr.S_un.S_addr = inet_addr(input_server); // server’s IP //Double check .S_un.S_addr
    remote.sin_port = htons(53); // DNS port on server  


}