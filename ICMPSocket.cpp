#include "pch.h"
#include "ICMPSocket.h"
#include "Checksum.h"
#include "DNSSocket.h"


bool ICMPSocket::Trace() {
    char x[] = "206.53.174.13";
    dns_socket.Open((char*)"8.8.8.8");


    //dns_socket.Write_(x);
    //dns_socket.Write_((char*)"142.250.113.113");
    //dns_socket.Read();
    //printf("Answer: %s\n", dns_socket.getAnswer());
    //printf("q: %s\n", dns_socket.getQuestion());

    //dns_socket.Read();

    //printf("Answer: %s\n", dns_socket.getAnswer());
    //printf("q: %s\n", dns_socket.getQuestion());



    if (sock == -1)
    {
        printf("Trace(): socket not opened\n");
        return false;
    }

    u_short seq;

    QueryPerformanceFrequency(&frequency);

    QueryPerformanceCounter(&time);
    double start = (double)(time.QuadPart) / frequency.QuadPart;

    double initial_rto = 500e-3; // 500 ms


    for (seq = 1; seq <= 30; seq++)
    {
        if (!Write(seq)) return false;

        QueryPerformanceCounter(&time);
        probe_list[seq].start = (double)(time.QuadPart) / frequency.QuadPart;
        probe_list[seq].rto = initial_rto;
        probe_list[seq].seen = false;
        probe_list[seq].echo = false;
        probe_list[seq].dns = false;
        probe_list[seq].hops = 1;
        probe_list[seq].dns_hops = 0;
    }



    seq = 1;
    WSAEventSelect(sock, socketReadyICMP, FD_READ);
    WSAEventSelect(dns_socket.getSock(), socketReadyDNS, FD_READ);
    HANDLE events[] = { socketReadyICMP, socketReadyDNS };
    DWORD timeout = initial_rto * 1e3;
    double curr_time;



    while (true) {
      
        // printf("nextToSend = %lu\n", nextToSend);
        std::priority_queue<double, std::vector<double>, std::greater<double>> minHeap;


        //printf("seq %d tme %lu\n", seq, timeout);

        // printf("waiting\n");
        int ret = WaitForMultipleObjects(2, events, false, timeout);
        // printf("done\n");

        QueryPerformanceCounter(&time);
        curr_time = (double)(time.QuadPart) / frequency.QuadPart;


        switch (ret) {
        case WAIT_TIMEOUT:
            //printf("timeout\n");


            for (int i = seq; i <= 30; i++) {

                if ( !probe_list[i].seen && (curr_time >= (probe_list[i].start + probe_list[i].rto)) ) { // not recieved and timeout expired
                    if (probe_list[i].hops == 3)
                    {
                        probe_list[i].seen = true;
                        probe_list[i].hops++;
                    }
                    else {
                        // calc new rto

                        // both edges
                        if ( ((i > 1) && (i < 30)) && (probe_list[i - 1].seen && probe_list[i + 1].seen) )
                        {
                            // double the avg of prev and next
                            probe_list[i].rto = (probe_list[i - 1].end - probe_list[i - 1].start) + (probe_list[i + 1].end - probe_list[i + 1].start);
                        }

                        // one edge
                        else if ( (i > 1) && probe_list[i - 1].seen) { // prev edge
                            probe_list[i].rto = (probe_list[i - 1].end - probe_list[i - 1].start) * 4;
                        }
                        else if ((i < 30) && probe_list[i + 1].seen) { // next edge
                            probe_list[i].rto = (probe_list[i + 1].end - probe_list[i + 1].start) * 2;
                        }

                        // no edges
                        else {
                            probe_list[i].rto *= 2;
                        }


                        
                        Write(i);

                        QueryPerformanceCounter(&time);
                        probe_list[i].start = (double)(time.QuadPart) / frequency.QuadPart;

                        probe_list[i].hops++;
                    }
                }


                if ( probe_list[i].seen && (curr_time >= (probe_list[i].end + 5)) ) { // dns sent but timeout expired
                    probe_list[i].dns = true;
                    strcpy_s(probe_list[i].host, MAX_HOST_LEN + 1, "<timeout>");

                }
            }




            //printf("rto: %d %d %f\n", seq, probe_list[seq].hops, probe_list[seq].rto);


           
            break;
        case WAIT_OBJECT_0: // ICMP received

            Read();



            break;
        case WAIT_OBJECT_0 + 1: // DNS received

            dns_socket.Read();
            dns_socket.getQuestion();

            for (int i = seq; i <= 30; i++)
            {
                if (probe_list[i].hops == 4)
                {
                    probe_list[i].dns = true;
                }
                
                else if (probe_list[i].seen) {
                    
                    int result = strcmp(inet_ntoa(probe_list[i].ip_addr), dns_socket.getReversed());

                    //printf("dns: %d %s %s\n", i, inet_ntoa(probe_list[i].ip_addr), dns_socket.getReversed());


                    if (result == 0)
                    {
                        strcpy_s(probe_list[i].host, MAX_HOST_LEN + 1, dns_socket.getAnswer());
                        probe_list[i].dns = true;
                        break;
                    }
                    
                }


                
            }
            
            //printf("dns seq %d\n", seq);



            break;
        default:
            // handle failed wait;
            printf("FAILED WAIT %lu\n", GetLastError());
            break;
        }


        while (seq <= 30 && probe_list[seq].seen && !probe_list[seq].echo && probe_list[seq].dns) {


            if (probe_list[seq].hops == 4)
            {
                printf(" %d *\n", seq);
            }
            else {
                printf(" %d %s (%s) %.3f ms (%d)\n",
                    seq,
                    probe_list[seq].host,
                    inet_ntoa(probe_list[seq].ip_addr),
                    (probe_list[seq].end - probe_list[seq].start) * 1e3,
                    probe_list[seq].hops
                );
            }
            if (seq == 30)
            {
                QueryPerformanceCounter(&time);
                double end = (double)(time.QuadPart) / frequency.QuadPart;
                printf("\nTotal execution time: %.0f ms\n", (end - start) * 1000); 
                
                return true;
            }

            seq++;
        }

        if (probe_list[seq].echo && probe_list[seq].dns) {
            printf(" %d %s (%s) %.3f ms (%d)\n",
                seq,
                probe_list[seq].host,
                inet_ntoa(probe_list[seq].ip_addr),
                (probe_list[seq].end - probe_list[seq].start) * 1e3,
                probe_list[seq].hops
            );
            break;
        }


        // update timeouts
        QueryPerformanceCounter(&time);
        curr_time = (double)(time.QuadPart) / frequency.QuadPart;


        //printf("dd %f ", probe_list[seq].start + probe_list[seq].rto);
        ////printf("dd %f ", probe_list[seq].end + 5);
        //printf("dd %f\n", curr_time);
        for (int i = seq; i <= 30; i++)
        {
            if (!probe_list[i].seen) { // outstanding packet
                minHeap.push( probe_list[i].start + probe_list[i].rto );
                //printf("here2 seq %d\n", seq);

            }
            else if (probe_list[i].seen) { // outstanding dns
                minHeap.push( probe_list[i].end + 5 );
                //printf("here1 seq %d\n", seq);
            }
        }

        timeout = max((minHeap.top() - curr_time) * 1e3, 0);
        

       /* timeoutICMP = max( ((probe_list[seq].start + probe_list[seq].rto) - curr_time) * 1e3, 0);

        if (probe_list[seq].seen)
        {
            timeoutDNS = ((probe_list[seq].end + 5) - curr_time) * 1e3;

        }*/
        //timeoutDNS = 500;



        //bool retransmission = (dupACK == 3) || (ret == WAIT_TIMEOUT);
        //// if (first packet of window || just did a retx (timeout / 3-dup ACK) || senderBase moved forward)
        //// printf("check recalc %d\n", retransmission);
        //if (first_packet || retransmission || (oldSndBase < sndBase)) {
        //    // printf("RECALC\n");
        //    timerExpire = (double)clock() / CLOCKS_PER_SEC + rto;
        //}


        // if (closeACK == sndBase)
        // {
        //     break;
        // }

        // printf("\n\n");


    }


  /*  for (seq = 1; seq <= 30; seq++)
    {
        if (!Read()) return false;

        if (probe_list[seq].seen) {
            printf("(%d) xx (%s)\n", seq, inet_ntoa(probe_list[seq].ip_addr));
        }
    }*/



    QueryPerformanceCounter(&time);
    double end = (double)(time.QuadPart) / frequency.QuadPart;
    printf("\nTotal execution time: %.0f ms\n", (end - start) * 1000);


    return true;

}

bool ICMPSocket::Write(int ttl) {

    if (sock == -1)
    {
        printf("Write(): socket not opened\n");
        return false;
    }

    ICMPHeader *icmp = (ICMPHeader *) send_buf; 
  
    // set up ID/SEQ fields as needed
    icmp->seq = ttl;

    // set up optional fields as needed

    // initialize checksum to zero
    icmp->checksum = 0;
    // compute checksum and transmit the packet 
    /* calculate the checksum */ 
    int packet_size = sizeof(ICMPHeader); // 8 bytes 
    icmp->checksum = ip_checksum ((u_short *) send_buf, packet_size); 

    // need Ws2tcpip.h for IP_TTL, which is equal to 4; there is another constant with the same
    // name in multicast headers – do not use it!
    if (setsockopt (sock, IPPROTO_IP, IP_TTL, (const char *) &ttl, sizeof (ttl)) == SOCKET_ERROR) {
        printf ("setsockopt failed with %d\n", WSAGetLastError()); 
         // some cleanup 
        return false; 
    }


    // use regular sendto on the above socket 
    if (sendto (sock, (char*) send_buf, packet_size, 0, (struct sockaddr*)&remote, sizeof(remote)) == SOCKET_ERROR) {
        printf ("sendto failed with %d\n", WSAGetLastError());
        return false;
    }

    return true;

}



bool ICMPSocket::Read() {

    if (sock == -1)
    {
        printf("Read(): socket not opened\n");
        return false;
    }
  

    // receive from the socket into rec_buf

   
    struct sockaddr_in response;
    int size_of_sockaddr = sizeof(sockaddr);
    int recv_bytes;

    recv_bytes = recvfrom(sock, (char*)rec_buf, MAX_REPLY_SIZE, 0, (struct sockaddr*)&response, &size_of_sockaddr);
    if (recv_bytes == SOCKET_ERROR) {
        printf("recvfrom failed with error: %d\n", WSAGetLastError());
        return false;
    }



    IPHeader* router_ip_hdr = (IPHeader*)rec_buf;

    int router_ip_hdr_len = router_ip_hdr->h_len * 4;

    ICMPHeader* router_icmp_hdr = (ICMPHeader*)(rec_buf + router_ip_hdr_len);
    IPHeader* orig_ip_hdr = (IPHeader*)(router_icmp_hdr + 1);
    ICMPHeader* orig_icmp_hdr = (ICMPHeader*)(orig_ip_hdr + 1);

    /*if (recv_bytes < 56)
    {
        printf("Not enough bytes %d\n", recv_bytes);
    }*/


    if (router_icmp_hdr->type == ICMP_ECHO_REPLY && router_icmp_hdr->code == ICMP_TTL_EXPIRED_CODE) {
        //printf("echo reply2\n");

        if (router_ip_hdr->proto == ICMP_PROTOCOL) {

            // check if process ID matches
            if (router_icmp_hdr->id == GetCurrentProcessId())
            {
                probe_list[router_icmp_hdr->seq].seen = true;
                
                struct in_addr ip_addr;
                ip_addr.s_addr = router_ip_hdr->source_ip;

                probe_list[router_icmp_hdr->seq].ip_addr = ip_addr;
                dns_socket.Write_(inet_ntoa(ip_addr));

                probe_list[router_icmp_hdr->seq].echo = true;

                QueryPerformanceCounter(&time);
                probe_list[router_icmp_hdr->seq].end = (double)(time.QuadPart) / frequency.QuadPart;


                    
                // take router_ip_hdr->source_ip and
                // initiate a DNS lookup
                //printf("HERE do DNS lookup 2\n");
                //printf("echo reply3 %d\n", orig_icmp_hdr->seq);

            }
        }
    }
        
    if (router_icmp_hdr->type == ICMP_TTL_EXPIRED && router_icmp_hdr->code == ICMP_TTL_EXPIRED_CODE) {

        if (orig_ip_hdr->proto == ICMP_PROTOCOL) {
        // check if process ID matches
            if (orig_icmp_hdr->id == GetCurrentProcessId())
            {
                probe_list[orig_icmp_hdr->seq].seen = true;
                
                // take router_ip_hdr->source_ip and
                // initiate a DNS lookup
                struct in_addr ip_addr;
                ip_addr.s_addr = router_ip_hdr->source_ip;

                probe_list[orig_icmp_hdr->seq].ip_addr = ip_addr; 
                dns_socket.Write_(inet_ntoa(ip_addr));

                QueryPerformanceCounter(&time);
                probe_list[orig_icmp_hdr->seq].end = (double)(time.QuadPart) / frequency.QuadPart;


                //printf("HERE do DNS lookup\n");
            }
        }
    }

    


    // u_char rec_buf [MAX_REPLY_SIZE]; /* this buffer starts with an IP header */
    // IPHeader *router_ip_hdr = (IPHeader *) rec_buf;
    // ICMPHeader *router_icmp_hdr = (ICMPHeader *) (router_ip_hdr + 1);
    // IPHeader *orig_ip_hdr = (IPHeader *) (router_icmp_hdr + 1);
    // ICMPHeader *orig_icmp_hdr = (ICMPHeader *) (orig_ip_hdr + 1);
    // // receive from the socket into rec_buf
    // // ...
    // // check if this is TTL_expired; make sure packet size >= 56 bytes
    // if (router_icmp_hdr->type == ... && router_icmp_hdr->code == ...) {
    //     if (orig_ip_hdr->proto == ICMP) {
    //     // check if process ID matches
    //         if (orig_icmp_hdr->id == GetCurrentProcessId())
    //         {
    //             // take router_ip_hdr->source_ip and
    //             // initiate a DNS lookup
    //         }
    //     }
    // }


    return true;

}



bool ICMPSocket::Open(char* input_host) {

    if (sock != -1)
    {
        printf("Open(): socket already opened\n");
        return true;
    }

    /* ready to create a socket */
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock == INVALID_SOCKET) {
        printf("Unable to create a raw socket: error %d\n", WSAGetLastError());
        // do some cleanup
        Close();
        // then exit
        return false;
    }



    struct hostent* remote_host;
    memset(&remote, 0, sizeof(remote));
    //printf("input: %s\n", input_host);

    DWORD IP = inet_addr(input_host);
    if (IP == INADDR_NONE) {
        // if not a valid IP, then do a DNS lookup
        if ((remote_host = gethostbyname(input_host)) == NULL)
        {
            printf("Invalid string: neither FQDN, nor IP address\n");
            Close();
            return false;
        }
        else {// take the first IP address and copy into sin_addr
            memcpy((char*)&(remote.sin_addr), remote_host->h_addr, remote_host->h_length);
            printf("Tracerouting to %s...\n", inet_ntoa(remote.sin_addr));
        }
    }
    else {
        // if a valid IP, directly drop its binary version into sin_addr
        remote.sin_addr.S_un.S_addr = IP;
        printf("Tracerouting to %s...\n", input_host);

    }
    remote.sin_family = AF_INET;



    // set up buffers

    // reciever buf
    rec_buf = new u_char[MAX_REPLY_SIZE]; /* this buffer starts with an IP header */

    // buffer for the ICMP header
    //u_char send_buf [MAX_ICMP_SIZE]; /* IP header is not present here */
    send_buf = new u_char[MAX_ICMP_SIZE]; /* IP header is not present here */

    ICMPHeader* icmp = (ICMPHeader*)send_buf;
    // set up the echo request
    // no need to flip the byte order since fields are 1 byte each
    icmp->type = ICMP_ECHO_REQUEST;
    icmp->code = 0;

    // set up ID/SEQ fields as needed
    icmp->id = (u_short)GetCurrentProcessId();




    return true;

}



bool ICMPSocket::Close() {

    if (sock == -1)
    {
        printf("Close(): socket not opened\n");
        return false;
    }

    closesocket(sock);

    if (send_buf != nullptr)
    {
        delete[] send_buf;
        send_buf = nullptr;
    }

    if (rec_buf != nullptr)
    {
        delete[] rec_buf;
        rec_buf = nullptr;
    }

    return true;
}
















//bool ICMPSocket::Read() {
//
//    if (sock == -1)
//    {
//        printf("Read(): socket not opened\n");
//        return false;
//    }
//
//
//    // receive from the socket into rec_buf
//
//    struct timeval timeout;
//    timeout.tv_sec = 2;  // 10 seconds
//    timeout.tv_usec = 0;  // 0 microseconds
//    fd_set fd;   // file descriptor
//    FD_ZERO(&fd);
//    FD_SET(sock, &fd);
//
//    int ret = select(0, &fd, NULL, NULL, &timeout);
//
//    if (ret > 0) {
//        struct sockaddr_in response;
//        int size_of_sockaddr = sizeof(sockaddr);
//        int recv_bytes;
//
//        recv_bytes = recvfrom(sock, (char*)rec_buf, MAX_REPLY_SIZE, 0, (struct sockaddr*)&response, &size_of_sockaddr);
//        if (recv_bytes == SOCKET_ERROR) {
//            printf("recvfrom failed with error: %d\n", WSAGetLastError());
//            return false;
//        }
//
//
//
//        IPHeader* router_ip_hdr = (IPHeader*)rec_buf;
//
//        int router_ip_hdr_len = router_ip_hdr->h_len * 4;
//
//        ICMPHeader* router_icmp_hdr = (ICMPHeader*)(rec_buf + router_ip_hdr_len);
//        IPHeader* orig_ip_hdr = (IPHeader*)(router_icmp_hdr + 1);
//        ICMPHeader* orig_icmp_hdr = (ICMPHeader*)(orig_ip_hdr + 1);
//
//        /*if (recv_bytes < 56)
//        {
//            printf("Not enough bytes %d\n", recv_bytes);
//        }*/
//
//        probe_list[orig_icmp_hdr->seq].seen = true;
//
//        if (router_icmp_hdr->type == ICMP_ECHO_REPLY && router_icmp_hdr->code == ICMP_TTL_EXPIRED_CODE) {
//            printf("echo reply2\n");
//
//            if (router_ip_hdr->proto == ICMP_PROTOCOL) {
//                // check if process ID matches
//                if (router_icmp_hdr->id == GetCurrentProcessId())
//                {
//                    struct in_addr ip_addr;
//                    ip_addr.s_addr = router_ip_hdr->source_ip;
//
//                    probe_list[orig_icmp_hdr->seq].ip_addr = ip_addr;
//
//                    // take router_ip_hdr->source_ip and
//                    // initiate a DNS lookup
//                    printf("HERE do DNS lookup 2\n");
//                }
//            }
//        }
//
//        if (router_icmp_hdr->type == ICMP_TTL_EXPIRED && router_icmp_hdr->code == ICMP_TTL_EXPIRED_CODE) {
//
//            if (orig_ip_hdr->proto == ICMP_PROTOCOL) {
//                // check if process ID matches
//                if (orig_icmp_hdr->id == GetCurrentProcessId())
//                {
//                    // take router_ip_hdr->source_ip and
//                    // initiate a DNS lookup
//                    struct in_addr ip_addr;
//                    ip_addr.s_addr = router_ip_hdr->source_ip;
//
//                    probe_list[orig_icmp_hdr->seq].ip_addr = ip_addr;
//
//
//                    //printf("HERE do DNS lookup\n");
//                }
//            }
//        }
//
//
//
//    }
//    else if (ret == 0) {
//        // clock_t end = clock();
//        // int elapsed_time = (int) ((double)(end - start) / CLOCKS_PER_SEC * 1000);
//        printf("timeout in %d ms\n", 0);
//        return true;
//    }
//    else {
//        printf("select failed with error: %d\n", WSAGetLastError());
//    }
//
//
//
//
//
//    // u_char rec_buf [MAX_REPLY_SIZE]; /* this buffer starts with an IP header */
//    // IPHeader *router_ip_hdr = (IPHeader *) rec_buf;
//    // ICMPHeader *router_icmp_hdr = (ICMPHeader *) (router_ip_hdr + 1);
//    // IPHeader *orig_ip_hdr = (IPHeader *) (router_icmp_hdr + 1);
//    // ICMPHeader *orig_icmp_hdr = (ICMPHeader *) (orig_ip_hdr + 1);
//    // // receive from the socket into rec_buf
//    // // ...
//    // // check if this is TTL_expired; make sure packet size >= 56 bytes
//    // if (router_icmp_hdr->type == ... && router_icmp_hdr->code == ...) {
//    //     if (orig_ip_hdr->proto == ICMP) {
//    //     // check if process ID matches
//    //         if (orig_icmp_hdr->id == GetCurrentProcessId())
//    //         {
//    //             // take router_ip_hdr->source_ip and
//    //             // initiate a DNS lookup
//    //         }
//    //     }
//    // }
//
//
//    return true;
//
//}