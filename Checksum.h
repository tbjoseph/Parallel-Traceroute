#pragma once

#ifndef CHECKSUM_H
#define CHECKSUM_H

#include "pch.h"

/*
* ======================================================================
* ip_checksum: compute Internet checksums
*
* Returns the checksum. No errors possible.
*
* ======================================================================
*/
u_short ip_checksum (u_short *buffer, int size)
{
    u_long cksum = 0;

    /* sum all the words together, adding the final byte if size is odd */
    while (size > 1){
        cksum += *buffer++;
        size -= sizeof (u_short);
    }

    if (size) 
    cksum += *(u_char *) buffer;

    /* add carry bits to lower u_short word */
    cksum = (cksum >> 16) + (cksum & 0xffff);

    /* return a bitwise complement of the resulting mishmash */
    return (u_short) (~cksum);
} 

#endif //CHECKSUM_H
