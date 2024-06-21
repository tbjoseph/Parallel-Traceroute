// pch.h: This is a precompiled header file.
// Files listed below are compiled only once, improving build performance for future builds.
// This also affects IntelliSense performance, including code completion and many code browsing features.
// However, files listed here are ALL re-compiled if any one of them is updated between builds.
// Do not add files here that you will be updating frequently as this negates the performance advantage.

#ifndef PCH_H
#define PCH_H

#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

#include <winsock2.h>
#include <Ws2tcpip.h>
//#include <windows.h>


//#pragma comment(lib, "wsock32.lib")
#pragma comment(lib, "Ws2_32.lib")




#include <iostream>
#include <string>
#include <set>
#include <queue>
#include <functional>

#include "ICMPSocket.h"


//#define IP_HDR_SIZE 20 /* RFC 791 */
#define IP_HDR_SIZE 60 // 0xF * 4
#define ICMP_HDR_SIZE 8 /* RFC 792 */
/* max payload size of an ICMP message originated in the program */
#define MAX_SIZE 65200
/* max size of an IP datagram */
#define MAX_ICMP_SIZE (MAX_SIZE + ICMP_HDR_SIZE)
/* the returned ICMP message will most likely include only 8 bytes
* of the original message plus the IP header (as per RFC 792); however,
* longer replies (e.g., 68 bytes) are possible */
#define MAX_REPLY_SIZE (IP_HDR_SIZE + ICMP_HDR_SIZE + MAX_ICMP_SIZE)
/* ICMP packet types */
#define ICMP_ECHO_REPLY 0
#define ICMP_DEST_UNREACH 3
#define ICMP_TTL_EXPIRED 11
#define ICMP_TTL_EXPIRED_CODE 0
#define ICMP_ECHO_REQUEST 8
#define ICMP_PROTOCOL 1


/* remember the current packing state */
#pragma pack (push)
#pragma pack (1)
/* define the IP header (20 bytes) */
class IPHeader {
public:
    u_char h_len:4; /* lower 4 bits: length of the header in dwords */
    u_char version:4; /* upper 4 bits: version of IP, i.e., 4 */
    u_char tos; /* type of service (TOS), ignore */
    u_short len; /* length of packet */
    u_short ident; /* unique identifier */
    u_short flags; /* flags together with fragment offset - 16 bits */
    u_char ttl; /* time to live */
    u_char proto; /* protocol number (6=TCP, 17=UDP, etc.) */
    u_short checksum; /* IP header checksum */
    u_long source_ip;
    u_long dest_ip;
};
/* define the ICMP header (8 bytes) */
class ICMPHeader{
public:
    u_char type; /* ICMP packet type */
    u_char code; /* type subcode */
    u_short checksum; /* checksum of the ICMP */
    u_short id; /* application-specific ID */
    u_short seq; /* application-specific sequence */
};
/* now restore the previous packing state */
#pragma pack (pop) 



#endif //PCH_H
