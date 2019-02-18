#define HASH_LENGTH 32
#define HASH_ALPHA_SIZE 16
#define SIZE_MATCHES 5e7
////////////////////////////////////////////////////////////////MD5 STRUCT/////////////////////////////////////////////////////////////
/* MD5
 converted to C++ class by Frank Thilo (thilo@unix-ag.org)
 for bzflag (http://www.bzflag.org)
 
   based on:
 
   md5.h and md5.c
   reference implementation of RFC 1321
 
   Copyright (C) 1991-2, RSA Data Security, Inc. Created 1991. All
rights reserved.
 
License to copy and use this software is granted provided that it
is identified as the "RSA Data Security, Inc. MD5 Message-Digest
Algorithm" in all material mentioning or referencing this software
or this function.
 
License is also granted to make and use derivative works provided
that such works are identified as "derived from the RSA Data
Security, Inc. MD5 Message-Digest Algorithm" in all material
mentioning or referencing the derived work.
 
RSA Data Security, Inc. makes no representations concerning either
the merchantability of this software or the suitability of this
software for any particular purpose. It is provided "as is"
without express or implied warranty of any kind.
 
These notices must be retained in any copies of any part of this
documentation and/or software.
 
*/
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21
#define blocksize 64

struct MD5{
    bool finalized;
    unsigned char buffer[blocksize]; // bytes that didn't fit in last 64 byte chunk
    unsigned int count[2];   // 64bit counter for number of bits (lo, hi)
    unsigned int state[4];   // digest so far
    unsigned char digest[16]; // the result
};

inline unsigned int F(unsigned int x, unsigned int y, unsigned int z) {
    return (x&y) | (~x&z);
}

inline unsigned int G(unsigned int x, unsigned int y, unsigned int z) {
    return (x&z) | (y&~z);
}

inline unsigned int H(unsigned int x, unsigned int y, unsigned int z) {
    return x^y^z;
}

inline unsigned int I(unsigned int x, unsigned int y, unsigned int z) {
    return y ^ (x | ~z);
}

// rotate_left rotates x left n bits.
inline unsigned int rotate_left(unsigned int x, int n) {
    return (x << n) | (x >> (32-n));
}

// FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
// Rotation is separate from addition to prevent recomputation.
inline unsigned int FF(unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int ac) {
    return rotate_left(a+ F(b,c,d) + x + ac, s) + b;
}

inline unsigned int GG(unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int ac) {
    return rotate_left(a + G(b,c,d) + x + ac, s) + b;
}

inline unsigned int HH(unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int ac) {
    return rotate_left(a + H(b,c,d) + x + ac, s) + b;
}

inline unsigned int II(unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int ac) {
    return rotate_left(a + I(b,c,d) + x + ac, s) + b;
}

void init(__global struct MD5 * md5){
    md5->finalized=false;

    md5->count[0] = 0;
    md5->count[1] = 0;

    // load magic initialization constants.
    md5->state[0] = 0x67452301;
    md5->state[1] = 0xefcdab89;
    md5->state[2] = 0x98badcfe;
    md5->state[3] = 0x10325476;
}

void decode(unsigned int output[], const unsigned char input[], unsigned int len){
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4)
        output[i] = ((unsigned int)input[j]) | (((unsigned int)input[j+1]) << 8) |
            (((unsigned int)input[j+2]) << 16) | (((unsigned int)input[j+3]) << 24);
}

void decode2(unsigned int output[], __global unsigned char input[], unsigned int len){
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4)
        output[i] = ((unsigned int)input[j]) | (((unsigned int)input[j+1]) << 8) |
            (((unsigned int)input[j+2]) << 16) | (((unsigned int)input[j+3]) << 24);
}

// encodes input (unsigned int) into output (unsigned char). Assumes len is
// a multiple of 4.
void encode(unsigned char output[], __global unsigned int input[], unsigned int len){
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = input[i] & 0xff;
        output[j+1] = (input[i] >> 8) & 0xff;
        output[j+2] = (input[i] >> 16) & 0xff;
        output[j+3] = (input[i] >> 24) & 0xff;
    }
}

void encode2(__global unsigned char output[], __global unsigned int input[], unsigned int len){
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = input[i] & 0xff;
        output[j+1] = (input[i] >> 8) & 0xff;
        output[j+2] = (input[i] >> 16) & 0xff;
        output[j+3] = (input[i] >> 24) & 0xff;
    }
}

// apply MD5 algo on a block
void transform(__global struct MD5 * md5, const unsigned char block[blocksize]){
    unsigned int a = md5->state[0], b = md5->state[1], c = md5->state[2], d = md5->state[3], x[16];
    decode (x, block, blocksize);

    /* Round 1 */
    a = FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
    d = FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
    c = FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
    b = FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
    a = FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
    d = FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
    c = FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
    b = FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
    a = FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
    d = FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
    c = FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
    b = FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
    a = FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
    d = FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
    c = FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
    b = FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

    /* Round 2 */
    a = GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
    d = GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
    c = GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
    b = GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
    a = GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
    d = GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
    c = GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
    b = GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
    a = GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
    d = GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
    c = GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
    b = GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
    a = GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
    d = GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
    c = GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
    b = GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    a = HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
    d = HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
    c = HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
    b = HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
    a = HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
    d = HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
    c = HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
    b = HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
    a = HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
    d = HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
    c = HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
    b = HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
    a = HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
    d = HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
    c = HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
    b = HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

    /* Round 4 */
    a = II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
    d = II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
    c = II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
    b = II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
    a = II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
    d = II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
    c = II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
    b = II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
    a = II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
    d = II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
    c = II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
    b = II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
    a = II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
    d = II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
    c = II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
    b = II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

    md5->state[0] += a;
    md5->state[1] += b;
    md5->state[2] += c;
    md5->state[3] += d;

    // Zeroize sensitive information.
    for(int i = 0; i < 16; ++i)
        x[i] = 0;
}

void transform2(__global struct MD5 * md5, __global unsigned char block[blocksize]){
    unsigned int a = md5->state[0], b = md5->state[1], c = md5->state[2], d = md5->state[3], x[16];
    decode2 (x, block, blocksize);

    /* Round 1 */
    a = FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
    d = FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
    c = FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
    b = FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
    a = FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
    d = FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
    c = FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
    b = FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
    a = FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
    d = FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
    c = FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
    b = FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
    a = FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
    d = FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
    c = FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
    b = FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

    /* Round 2 */
    a = GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
    d = GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
    c = GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
    b = GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
    a = GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
    d = GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
    c = GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
    b = GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
    a = GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
    d = GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
    c = GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
    b = GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
    a = GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
    d = GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
    c = GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
    b = GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    a = HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
    d = HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
    c = HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
    b = HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
    a = HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
    d = HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
    c = HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
    b = HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
    a = HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
    d = HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
    c = HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
    b = HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
    a = HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
    d = HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
    c = HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
    b = HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

    /* Round 4 */
    a = II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
    d = II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
    c = II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
    b = II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
    a = II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
    d = II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
    c = II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
    b = II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
    a = II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
    d = II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
    c = II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
    b = II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
    a = II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
    d = II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
    c = II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
    b = II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

    md5->state[0] += a;
    md5->state[1] += b;
    md5->state[2] += c;
    md5->state[3] += d;

    // Zeroize sensitive information.
    for(int i = 0; i < 16; ++i)
        x[i] = 0;
}

// MD5 block update operation. Continues an MD5 message-digest
// operation, processing another message block
void update(__global struct MD5 * md5, const unsigned char input[], unsigned int length){
    // compute number of bytes mod 64
    unsigned int index = md5->count[0] / 8 % blocksize;

    // Update number of bits
    if ((md5->count[0] += (length << 3)) < (length << 3))
        md5->count[1]++;
    md5->count[1] += (length >> 29);

    // number of bytes we need to fill in buffer
    unsigned int firstpart = 64 - index;

    unsigned int i;

    // transform as many times as possible.
    if (length >= firstpart){
        // fill buffer first, transform
        for(int k = index; k < index + firstpart; ++k)
            md5->buffer[k] = input[k-index];
        //memcpy(&buffer[index], input, firstpart);
        transform2(md5, md5->buffer);

        // transform chunks of blocksize (64 bytes)
        for (i = firstpart; i + blocksize <= length; i += blocksize)
            transform(md5, &input[i]);

        index = 0;
    }
    else i = 0;

    // buffer remaining input
    for(int k = index; k < index + length - i; ++k)
        md5->buffer[k] = input[i+k-index];
    //memcpy(&buffer[index], &input[i], length-i);
}

void update2(__global struct MD5 * md5, __global unsigned char input[], unsigned int length){
    // compute number of bytes mod 64
    unsigned int index = md5->count[0] / 8 % blocksize;

    // Update number of bits
    if ((md5->count[0] += (length << 3)) < (length << 3))
        md5->count[1]++;
    md5->count[1] += (length >> 29);

    // number of bytes we need to fill in buffer
    unsigned int firstpart = 64 - index;

    unsigned int i;

    // transform as many times as possible.
    if (length >= firstpart){
        // fill buffer first, transform
        for(int k = index; k < index + firstpart; ++k)
            md5->buffer[k] = input[k-index];
        //memcpy(&buffer[index], input, firstpart);
        transform2(md5, md5->buffer);

        // transform chunks of blocksize (64 bytes)
        for (i = firstpart; i + blocksize <= length; i += blocksize)
            transform2(md5, &input[i]);

        index = 0;
    }
    else i = 0;

    // buffer remaining input
    for(int k = index; k < index + length - i; ++k)
        md5->buffer[k] = input[i+k-index];
    //memcpy(&buffer[index], &input[i], length-i);
}

//////////////////////////////

// MD5 finalization. Ends an MD5 message-digest operation, writing the
// the message digest and zeroizing the context.
void finalize(__global struct MD5 * md5){
    unsigned char padding[64] = {
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    if (!md5->finalized){
        // Save number of bits
        unsigned char bits[8];
        encode(bits, md5->count, 8);

        // pad out to 56 mod 64.
        unsigned int index = md5->count[0] / 8 % 64;
        unsigned int padLen = (index < 56) ? (56 - index) : (120 - index);
        update(md5, padding, padLen);

        // Append length (before padding)
        update(md5, bits, 8);

        // Store state in digest
        encode2(md5->digest, md5->state, 16);

        // Zeroize sensitive information.
        for(int i = 0; i < 64; ++i)
            md5->buffer[i] = 0;
        for(int i = 0; i < 2; ++i)
            md5->count[i] = 0;
        //memset(buffer, 0, sizeof buffer);
        //memset(count, 0, sizeof count);

        md5->finalized=true;
    }
}

//////////////////////////////
char hex_to_str(int val){
    if(val < 10) return (char)(val + '0');
    return (char)(val - 10 + 'a');
}

// return hex representation of digest as string
void hexdigest(__global struct MD5 * md5, __global char* out_hash) {
    if (!(md5->finalized))
        return;
    for (int i=0; i<16; i++){
        //sprintf(buf+i*2, "%02x", digest[i]);
        out_hash[i*2] = hex_to_str( md5->digest[i] >> 4 );
        out_hash[i*2 + 1] = hex_to_str( md5->digest[i]&((1<<4)-1) );
    }
    out_hash[32]=0;
}

void change_text(__global struct MD5 * md5, __global unsigned char* text){
    init(md5);
    int len = 0;
    while(text[len] != '\0') ++len;
    update2(md5, text, len);
    finalize(md5);
}

//////////////////////////////////////////////////////////////END MD5 STRUCT//////////////////////////////////////////////////////////

int char_to_child_id( char ch ){
    if(ch >= '0' && ch <= '9') return ch - '0';
    return ch - 'a' + 10;
}

bool is_in_hash_trie( __global char * hash, __global int* trie, long string_val ){
    int cur = 0;
    for(int i = 0; i < HASH_LENGTH; ++i){
        int ch = char_to_child_id( hash[i] );
        if(trie[cur*HASH_ALPHA_SIZE+ch] == 0){
            return false;
        }
        cur = trie[cur*HASH_ALPHA_SIZE+ch];
    }
    return true;
}

void value_to_password( long val, __global char* format, const int format_size, __global unsigned char* pass ){
    for(int i = format_size-1; i >= 0; --i){
        int base = (format[i] == '0') ? 10 : 26;
        pass[i] = format[i] + val % base;
        val /= base;
    }
    pass[format_size] = 0;
}

bool check_password(const long string_val, __global struct MD5 * d_encrypter, __global unsigned char* d_passwords, __global char* d_hashes, __global char* format, const int format_size, __global int* d_cnt, __global int* d_trie, const int id_wi){
    bool match_found = false;
    value_to_password(string_val, format, format_size, d_passwords+((format_size+1)*id_wi));
    change_text((d_encrypter+id_wi), d_passwords+((format_size+1)*id_wi));
    hexdigest((d_encrypter+id_wi), d_hashes+((HASH_LENGTH+1)*id_wi));
    if( is_in_hash_trie( d_hashes+((HASH_LENGTH+1)*id_wi), d_trie, string_val ) ){
        d_cnt[id_wi] = d_cnt[id_wi] + 1;
        match_found = true;
        //printf( "Hash %s matched with string %s\n", d_hashes+((HASH_LENGTH+1)*id_wi), d_passwords+((format_size+1)*id_wi));
    }
    return match_found;
}

__kernel void BruteForce( __global int * d_cnt, __global int * d_trie, __global struct MD5* d_encrypter, __global char * d_format, __global unsigned char* d_passwords, __global char* d_hashes, __global long* d_matches, const int format_size, const long total_strings ){
    int id_wi = get_global_id(0);
    int total_wi = get_global_size(0);
    long passwords_per_thread = (total_strings + total_wi - 1) / total_wi;
    long st = passwords_per_thread * id_wi;
    long en = (st + passwords_per_thread < total_strings) ? st + passwords_per_thread : total_strings;
    int sz_per_wi = (SIZE_MATCHES + total_wi - 1) / total_wi;
    int cur_match_pos = id_wi * sz_per_wi;
    int max_match_pos = cur_match_pos + sz_per_wi < SIZE_MATCHES ? cur_match_pos + sz_per_wi : SIZE_MATCHES;
    for(long i = st; i < en; ++i){
        if( check_password(i, d_encrypter, d_passwords, d_hashes, d_format, format_size, d_cnt, d_trie, id_wi) ){
            if(cur_match_pos < max_match_pos){
                d_matches[cur_match_pos] = i;
            }
            ++cur_match_pos;
        }
    }
}