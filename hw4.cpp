// hw4.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include "ICMPSocket.h"


int main(int argc, char **argv)
{
    if (argc != 2) {
        printf("Usage: hw4.exe [destination]\n\n");
        printf("[destination]\tThe hostname or IP address you want to traceroute.\n");
        return -1;
    }
    WSADATA wsaData;
    WORD wVersionRequested = MAKEWORD(2, 2);
    if (WSAStartup(wVersionRequested, &wsaData) != 0)
    {
        printf("WSAStartup error %d\n", WSAGetLastError());
        WSACleanup();
        return -1;
    }

    


    ICMPSocket sock;

    sock.Open(argv[1]);

    sock.Trace();

    sock.Close();



    WSACleanup();

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
