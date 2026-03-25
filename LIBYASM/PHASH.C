/* Modified for use with yasm by Peter Johnson. */
#include "util.h"
#include "phash.h"

#define ub4 unsigned long

#define hashsize(n) ((ub4)1<<(n))
#define hashmask(n) (hashsize(n)-1)

#define mix(a,b,c) \
{ \
    a -= b; a -= c; a ^= (c>>13); \
    a &= 0xffffffff; \
    b -= c; b -= a; b ^= (a<<8); \
    b &= 0xffffffff; \
    c -= a; c -= b; c ^= (b>>13); \
    c &= 0xffffffff; \
    a -= b; a -= c; a ^= (c>>12);  \
    a &= 0xffffffff; \
    b -= c; b -= a; b ^= (a<<16); \
    b &= 0xffffffff; \
    c -= a; c -= b; c ^= (b>>5); \
    c &= 0xffffffff; \
    a -= b; a -= c; a ^= (c>>3);  \
    a &= 0xffffffff; \
    b -= c; b -= a; b ^= (a<<10); \
    b &= 0xffffffff; \
    c -= a; c -= b; c ^= (b>>15); \
    c &= 0xffffffff; \
}

unsigned long
phash_lookup(
    register const char *sk,
    register size_t length,
    register unsigned long level)
{
    register unsigned long a,b,c;
    register size_t len;
    register const unsigned char *k = (const unsigned char *)sk;

    len = length;
    a = b = 0x9e3779b9;
    c = level;

    while (len >= 12)
    {
        a += (k[0] +((ub4)k[1]<<8) +((ub4)k[2]<<16) +((ub4)k[3]<<24));
        a &= 0xffffffff;
        b += (k[4] +((ub4)k[5]<<8) +((ub4)k[6]<<16) +((ub4)k[7]<<24));
        b &= 0xffffffff;
        c += (k[8] +((ub4)k[9]<<8) +((ub4)k[10]<<16)+((ub4)k[11]<<24));
        c &= 0xffffffff;
        mix(a,b,c);
        k += 12; len -= 12;
    }

    c += (ub4)length;
    switch(len)
    {
        case 11: c+=((ub4)k[10]<<24);
        case 10: c+=((ub4)k[9]<<16);
        case 9 : c+=((ub4)k[8]<<8);
                 c &= 0xffffffff;
        case 8 : b+=((ub4)k[7]<<24);
        case 7 : b+=((ub4)k[6]<<16);
        case 6 : b+=((ub4)k[5]<<8);
        case 5 : b+=k[4];
                 b &= 0xffffffff;
        case 4 : a+=((ub4)k[3]<<24);
        case 3 : a+=((ub4)k[2]<<16);
        case 2 : a+=((ub4)k[1]<<8);
        case 1 : a+=k[0];
                 a &= 0xffffffff;
    }
    mix(a,b,c);
    return c;
}

#define mixc(a,b,c,d,e,f,g,h) \
{ \
    a^=b<<11; d+=a; b+=c; \
    b^=c>>2;  e+=b; c+=d; \
    c^=d<<8;  f+=c; d+=e; \
    d^=e>>16; g+=d; e+=f; \
    e^=f<<10; h+=e; f+=g; \
    f^=g>>4;  a+=f; g+=h; \
    g^=h<<8;  b+=g; h+=a; \
    h^=a>>9;  c+=h; a+=b; \
}

void
phash_checksum(
    register const char *sk,
    register size_t len,
    register unsigned long *state)
{
    register unsigned long a,b,c,d,e,f,g,h;
    register size_t length;
    register const unsigned char *k = (const unsigned char *)sk;

    length = len;
    a=state[0]; b=state[1]; c=state[2]; d=state[3];
    e=state[4]; f=state[5]; g=state[6]; h=state[7];

    while (len >= 32)
    {
        a += (k[0] +(k[1]<<8) +(k[2]<<16) +(k[3]<<24));
        b += (k[4] +(k[5]<<8) +(k[6]<<16) +(k[7]<<24));
        c += (k[8] +(k[9]<<8) +(k[10]<<16)+(k[11]<<24));
        d += (k[12]+(k[13]<<8)+(k[14]<<16)+(k[15]<<24));
        e += (k[16]+(k[17]<<8)+(k[18]<<16)+(k[19]<<24));
        f += (k[20]+(k[21]<<8)+(k[22]<<16)+(k[23]<<24));
        g += (k[24]+(k[25]<<8)+(k[26]<<16)+(k[27]<<24));
        h += (k[28]+(k[29]<<8)+(k[30]<<16)+(k[31]<<24));
        mixc(a,b,c,d,e,f,g,h);
        mixc(a,b,c,d,e,f,g,h);
        mixc(a,b,c,d,e,f,g,h);
        mixc(a,b,c,d,e,f,g,h);
        k += 32; len -= 32;
    }

    h += (ub4)length;
    switch(len)
    {
        case 31: h+=(k[30]<<24);
        case 30: h+=(k[29]<<16);
        case 29: h+=(k[28]<<8);
        case 28: g+=(k[27]<<24);
        case 27: g+=(k[26]<<16);
        case 26: g+=(k[25]<<8);
        case 25: g+=k[24];
        case 24: f+=(k[23]<<24);
        case 23: f+=(k[22]<<16);
        case 22: f+=(k[21]<<8);
        case 21: f+=k[20];
        case 20: e+=(k[19]<<24);
        case 19: e+=(k[18]<<16);
        case 18: e+=(k[17]<<8);
        case 17: e+=k[16];
        case 16: d+=(k[15]<<24);
        case 15: d+=(k[14]<<16);
        case 14: d+=(k[13]<<8);
        case 13: d+=k[12];
        case 12: c+=(k[11]<<24);
        case 11: c+=(k[10]<<16);
        case 10: c+=(k[9]<<8);
        case 9 : c+=k[8];
        case 8 : b+=(k[7]<<24);
        case 7 : b+=(k[6]<<16);
        case 6 : b+=(k[5]<<8);
        case 5 : b+=k[4];
        case 4 : a+=(k[3]<<24);
        case 3 : a+=(k[2]<<16);
        case 2 : a+=(k[1]<<8);
        case 1 : a+=k[0];
    }
    mixc(a,b,c,d,e,f,g,h);
    mixc(a,b,c,d,e,f,g,h);
    mixc(a,b,c,d,e,f,g,h);
    mixc(a,b,c,d,e,f,g,h);

    state[0]=a; state[1]=b; state[2]=c; state[3]=d;
    state[4]=e; state[5]=f; state[6]=g; state[7]=h;
}
