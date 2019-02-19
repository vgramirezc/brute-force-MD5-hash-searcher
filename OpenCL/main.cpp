#include <iostream>
#include <fstream>
#include <math.h>
#include <string.h>
#include <vector>
#include <CL/cl.hpp>

using namespace std;

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
    return x&y | ~x&z;
}

inline unsigned int G(unsigned int x, unsigned int y, unsigned int z) {
    return x&z | y&~z;
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
inline void FF(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int ac) {
    a = rotate_left(a+ F(b,c,d) + x + ac, s) + b;
}

inline void GG(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int ac) {
    a = rotate_left(a + G(b,c,d) + x + ac, s) + b;
}

inline void HH(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int ac) {
    a = rotate_left(a + H(b,c,d) + x + ac, s) + b;
}

inline void II(unsigned int &a, unsigned int b, unsigned int c, unsigned int d, unsigned int x, unsigned int s, unsigned int ac) {
    a = rotate_left(a + I(b,c,d) + x + ac, s) + b;
}

void init(MD5 * md5){
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

// encodes input (unsigned int) into output (unsigned char). Assumes len is
// a multiple of 4.
void encode(unsigned char output[], const unsigned int input[], unsigned int len){
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = input[i] & 0xff;
        output[j+1] = (input[i] >> 8) & 0xff;
        output[j+2] = (input[i] >> 16) & 0xff;
        output[j+3] = (input[i] >> 24) & 0xff;
    }
}

// apply MD5 algo on a block
void transform(MD5 * md5, const unsigned char block[blocksize]){
    unsigned int a = md5->state[0], b = md5->state[1], c = md5->state[2], d = md5->state[3], x[16];
    decode (x, block, blocksize);

    /* Round 1 */
    FF (a, b, c, d, x[ 0], S11, 0xd76aa478); /* 1 */
    FF (d, a, b, c, x[ 1], S12, 0xe8c7b756); /* 2 */
    FF (c, d, a, b, x[ 2], S13, 0x242070db); /* 3 */
    FF (b, c, d, a, x[ 3], S14, 0xc1bdceee); /* 4 */
    FF (a, b, c, d, x[ 4], S11, 0xf57c0faf); /* 5 */
    FF (d, a, b, c, x[ 5], S12, 0x4787c62a); /* 6 */
    FF (c, d, a, b, x[ 6], S13, 0xa8304613); /* 7 */
    FF (b, c, d, a, x[ 7], S14, 0xfd469501); /* 8 */
    FF (a, b, c, d, x[ 8], S11, 0x698098d8); /* 9 */
    FF (d, a, b, c, x[ 9], S12, 0x8b44f7af); /* 10 */
    FF (c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
    FF (b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
    FF (a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
    FF (d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
    FF (c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
    FF (b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

    /* Round 2 */
    GG (a, b, c, d, x[ 1], S21, 0xf61e2562); /* 17 */
    GG (d, a, b, c, x[ 6], S22, 0xc040b340); /* 18 */
    GG (c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
    GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa); /* 20 */
    GG (a, b, c, d, x[ 5], S21, 0xd62f105d); /* 21 */
    GG (d, a, b, c, x[10], S22,  0x2441453); /* 22 */
    GG (c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
    GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8); /* 24 */
    GG (a, b, c, d, x[ 9], S21, 0x21e1cde6); /* 25 */
    GG (d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
    GG (c, d, a, b, x[ 3], S23, 0xf4d50d87); /* 27 */
    GG (b, c, d, a, x[ 8], S24, 0x455a14ed); /* 28 */
    GG (a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
    GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8); /* 30 */
    GG (c, d, a, b, x[ 7], S23, 0x676f02d9); /* 31 */
    GG (b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    HH (a, b, c, d, x[ 5], S31, 0xfffa3942); /* 33 */
    HH (d, a, b, c, x[ 8], S32, 0x8771f681); /* 34 */
    HH (c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
    HH (b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
    HH (a, b, c, d, x[ 1], S31, 0xa4beea44); /* 37 */
    HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9); /* 38 */
    HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60); /* 39 */
    HH (b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
    HH (a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
    HH (d, a, b, c, x[ 0], S32, 0xeaa127fa); /* 42 */
    HH (c, d, a, b, x[ 3], S33, 0xd4ef3085); /* 43 */
    HH (b, c, d, a, x[ 6], S34,  0x4881d05); /* 44 */
    HH (a, b, c, d, x[ 9], S31, 0xd9d4d039); /* 45 */
    HH (d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
    HH (c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
    HH (b, c, d, a, x[ 2], S34, 0xc4ac5665); /* 48 */

    /* Round 4 */
    II (a, b, c, d, x[ 0], S41, 0xf4292244); /* 49 */
    II (d, a, b, c, x[ 7], S42, 0x432aff97); /* 50 */
    II (c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
    II (b, c, d, a, x[ 5], S44, 0xfc93a039); /* 52 */
    II (a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
    II (d, a, b, c, x[ 3], S42, 0x8f0ccc92); /* 54 */
    II (c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
    II (b, c, d, a, x[ 1], S44, 0x85845dd1); /* 56 */
    II (a, b, c, d, x[ 8], S41, 0x6fa87e4f); /* 57 */
    II (d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
    II (c, d, a, b, x[ 6], S43, 0xa3014314); /* 59 */
    II (b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
    II (a, b, c, d, x[ 4], S41, 0xf7537e82); /* 61 */
    II (d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
    II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb); /* 63 */
    II (b, c, d, a, x[ 9], S44, 0xeb86d391); /* 64 */

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
void update(MD5 * md5, const unsigned char input[], unsigned int length){
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
        transform(md5, md5->buffer);

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

//////////////////////////////

// MD5 finalization. Ends an MD5 message-digest operation, writing the
// the message digest and zeroizing the context.
void finalize(MD5 * md5){
    static unsigned char padding[64] = {
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
        encode(md5->digest, md5->state, 16);

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
    if(val < 10) return char(val) + '0';
    return char(val) - 10 + 'a';
}

// return hex representation of digest as string
void hexdigest(MD5 * md5, char* out_hash) {
    if (!(md5->finalized))
        return;
    for (int i=0; i<16; i++){
        //sprintf(buf+i*2, "%02x", digest[i]);
        out_hash[i*2] = hex_to_str( md5->digest[i] >> 4 );
        out_hash[i*2 + 1] = hex_to_str( md5->digest[i]&((1<<4)-1) );
    }
    out_hash[32]=0;
}

void change_text(MD5 * md5, char* text){
    init(md5);
    int len = 0;
    while(text[len] != '\0') ++len;
    update(md5, (const unsigned char*)text, len);
    finalize(md5);
}

//////////////////////////////////////////////////////////////END MD5 STRUCT//////////////////////////////////////////////////////////

const int HASH_LENGTH = 32;
const int HASH_ALPHA_SIZE = 16;
const int MAX_HASHES_SIZE = 100005;
const int NUMBER_OF_BLOCKS = 26;
const int SIZE_MATCHES = 5e7;
int trie_size = 0;
int hashes_trie[HASH_ALPHA_SIZE*HASH_LENGTH*MAX_HASHES_SIZE];
long long matches_ids[SIZE_MATCHES];

//OPENCL LIST OF ERRORS
const char *getErrorString(cl_int error)
{
    switch(error){
        // run-time and JIT compiler errors
        case 0: return "CL_SUCCESS";
        case -1: return "CL_DEVICE_NOT_FOUND";
        case -2: return "CL_DEVICE_NOT_AVAILABLE";
        case -3: return "CL_COMPILER_NOT_AVAILABLE";
        case -4: return "CL_MEM_OBJECT_ALLOCATION_FAILURE";
        case -5: return "CL_OUT_OF_RESOURCES";
        case -6: return "CL_OUT_OF_HOST_MEMORY";
        case -7: return "CL_PROFILING_INFO_NOT_AVAILABLE";
        case -8: return "CL_MEM_COPY_OVERLAP";
        case -9: return "CL_IMAGE_FORMAT_MISMATCH";
        case -10: return "CL_IMAGE_FORMAT_NOT_SUPPORTED";
        case -11: return "CL_BUILD_PROGRAM_FAILURE";
        case -12: return "CL_MAP_FAILURE";
        case -13: return "CL_MISALIGNED_SUB_BUFFER_OFFSET";
        case -14: return "CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST";
        case -15: return "CL_COMPILE_PROGRAM_FAILURE";
        case -16: return "CL_LINKER_NOT_AVAILABLE";
        case -17: return "CL_LINK_PROGRAM_FAILURE";
        case -18: return "CL_DEVICE_PARTITION_FAILED";
        case -19: return "CL_KERNEL_ARG_INFO_NOT_AVAILABLE";

        // compile-time errors
        case -30: return "CL_INVALID_VALUE";
        case -31: return "CL_INVALID_DEVICE_TYPE";
        case -32: return "CL_INVALID_PLATFORM";
        case -33: return "CL_INVALID_DEVICE";
        case -34: return "CL_INVALID_CONTEXT";
        case -35: return "CL_INVALID_QUEUE_PROPERTIES";
        case -36: return "CL_INVALID_COMMAND_QUEUE";
        case -37: return "CL_INVALID_HOST_PTR";
        case -38: return "CL_INVALID_MEM_OBJECT";
        case -39: return "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR";
        case -40: return "CL_INVALID_IMAGE_SIZE";
        case -41: return "CL_INVALID_SAMPLER";
        case -42: return "CL_INVALID_BINARY";
        case -43: return "CL_INVALID_BUILD_OPTIONS";
        case -44: return "CL_INVALID_PROGRAM";
        case -45: return "CL_INVALID_PROGRAM_EXECUTABLE";
        case -46: return "CL_INVALID_KERNEL_NAME";
        case -47: return "CL_INVALID_KERNEL_DEFINITION";
        case -48: return "CL_INVALID_KERNEL";
        case -49: return "CL_INVALID_ARG_INDEX";
        case -50: return "CL_INVALID_ARG_VALUE";
        case -51: return "CL_INVALID_ARG_SIZE";
        case -52: return "CL_INVALID_KERNEL_ARGS";
        case -53: return "CL_INVALID_WORK_DIMENSION";
        case -54: return "CL_INVALID_WORK_GROUP_SIZE";
        case -55: return "CL_INVALID_WORK_ITEM_SIZE";
        case -56: return "CL_INVALID_GLOBAL_OFFSET";
        case -57: return "CL_INVALID_EVENT_WAIT_LIST";
        case -58: return "CL_INVALID_EVENT";
        case -59: return "CL_INVALID_OPERATION";
        case -60: return "CL_INVALID_GL_OBJECT";
        case -61: return "CL_INVALID_BUFFER_SIZE";
        case -62: return "CL_INVALID_MIP_LEVEL";
        case -63: return "CL_INVALID_GLOBAL_WORK_SIZE";
        case -64: return "CL_INVALID_PROPERTY";
        case -65: return "CL_INVALID_IMAGE_DESCRIPTOR";
        case -66: return "CL_INVALID_COMPILER_OPTIONS";
        case -67: return "CL_INVALID_LINKER_OPTIONS";
        case -68: return "CL_INVALID_DEVICE_PARTITION_COUNT";

        // extension errors
        case -1000: return "CL_INVALID_GL_SHAREGROUP_REFERENCE_KHR";
        case -1001: return "CL_PLATFORM_NOT_FOUND_KHR";
        case -1002: return "CL_INVALID_D3D10_DEVICE_KHR";
        case -1003: return "CL_INVALID_D3D10_RESOURCE_KHR";
        case -1004: return "CL_D3D10_RESOURCE_ALREADY_ACQUIRED_KHR";
        case -1005: return "CL_D3D10_RESOURCE_NOT_ACQUIRED_KHR";
        default: return "Unknown OpenCL error";
    }
}

void check_error(float id, cl_int error){
    if(error != CL_SUCCESS){
        cout << "Error at " << id << ": " << getErrorString(error) << endl;
    }
}

int ch_to_int( string str ){
    int len = str.size();
    int ans = 0;
    for( int i = 0; i < len; ++i ){
        if( str[ i ] < '0' || str[ i ] > '9' ) return -1;
        ans *= 10;
        ans += str[ i ] - '0';
    }
    return ans;
}

bool check_format( char* format, int format_size ){
    for( int i = 0; i < format_size; ++i ){
        if( format[ i ] != 'a' && format[ i ] != 'A' && format[ i ] != '0' )
            return false;
    }
    return true;
}

int char_to_child_id( char ch ){
    if(ch >= '0' && ch <= '9') return ch - '0';
    return ch - 'a' + 10;
}

void trie_insert( const string& hash ){
    int cur = 0;
    for(int i = 0; i < hash.size(); ++i){
        int ch = char_to_child_id( hash[i] );
        if(hashes_trie[cur*HASH_ALPHA_SIZE+ch] == 0)
            hashes_trie[cur*HASH_ALPHA_SIZE+ch] = ++trie_size;
        cur = hashes_trie[cur*HASH_ALPHA_SIZE+ch];
    }
}

void build_hashes_trie( ifstream& in_hash ){
    string h;
    while( in_hash >> h ){
        trie_insert( h );
    }
}

bool is_in_hash_trie( char * hash, int* trie, long long string_val ){
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

int get_total_strings( char* format, int format_size ){
    long long total = 1LL;
    for(int i = 0; i < format_size; ++i){
        if(format[i] == '0') total *= 10LL;
        else total *= 26LL;
    }
    return total;
}

void value_to_password( long long val, char* format, int format_size, char* pass ){
    for(int i = format_size-1; i >= 0; --i){
        int base = (format[i] == '0') ? 10 : 26;
        pass[i] = format[i] + val % base;
        val /= base;
    }
    pass[format_size] = 0;
}

int main( int argc, char *argv[] ){
    if( argc != 4 ){
        printf( "You must pass exactly three arguments:\n" );
        printf( "  1. The password pattern\n" );
        printf( "  2. The name of the file containing the hashes.\n" );
        printf( "  3. The total of work items.\n" );
        exit( 0 );
    }
    char * format = argv[1];
    int format_size = strlen( format );
    if( !check_format( format, format_size ) ){
        printf( "The password pattern must have the following format:\n" );
        printf( "  * a: lowercase letter [a-z].\n" );
        printf( "  * A: uppercase letter. [A-Z]\n" );
        printf( "  * 0: digit. [0-9]\n" );
        printf( "E.g.: Aaaaa00 means passwords of length 7 starting with an uppercase letter, followed by 4 lowercase letters and ending with two digits.\n" );
        exit( 0 );
    }
    ifstream in_hash( argv[2] );
    if( !in_hash ){
        printf( "Error reading file %s\n", argv[2] );
        exit( 0 );
    }
    int total_wi = ch_to_int( argv[ 3 ] );
    if( total_wi <= 0 ){
        printf( "Invalid argument [%s]. The number of work items must be a positive integer.\n", argv[3] );
        exit( 0 );
    }

    build_hashes_trie( in_hash );
    long long total_strings = get_total_strings( format, format_size );

    //OpenCL code
    vector<cl::Platform> platforms;
    cl::Platform::get(&platforms);
    auto platform = platforms.front();

    vector<cl::Device> devices;
    platform.getDevices(CL_DEVICE_TYPE_ALL, &devices);
    auto device = devices.front();

    ifstream BruteForceFile("BruteForce.cl");
    string src(istreambuf_iterator<char>(BruteForceFile), (istreambuf_iterator<char>()));

    cl::Program::Sources sources(1, make_pair(src.c_str(), src.length()+1));

    cl::Context context(device);
    cl::Program program(context, sources);

    auto err = program.build("-cl-std=CL1.2");
    check_error(1, err);
    if(err != CL_SUCCESS){
        string buildlog = program.getBuildInfo<CL_PROGRAM_BUILD_LOG>(device);
        cout << buildlog << endl;
    }
    
    int * h_cnt = (int*) malloc(sizeof(int) * total_wi);
    cl::Buffer d_cnt(context, CL_MEM_WRITE_ONLY | CL_MEM_HOST_READ_ONLY, sizeof(int) * total_wi, nullptr, &err);
    check_error(2, err);
    cl::Buffer d_format(context, CL_MEM_READ_ONLY | CL_MEM_HOST_NO_ACCESS | CL_MEM_COPY_HOST_PTR, sizeof(format), format, &err);
    check_error(3, err);
    cl::Buffer d_trie(context, CL_MEM_READ_ONLY | CL_MEM_HOST_NO_ACCESS | CL_MEM_COPY_HOST_PTR, sizeof(hashes_trie), hashes_trie, &err);
    check_error(4, err);
    //encrypter
    cl::Buffer d_encrypter(context, CL_MEM_WRITE_ONLY, sizeof(MD5)*total_wi, nullptr, &err);
    check_error(4.2, err);
    //char * h_pass = (char*)malloc((format_size+1)*total_wi);
    //cl::Buffer d_passwords(context, CL_MEM_WRITE_ONLY | CL_MEM_HOST_READ_ONLY, sizeof(char)*(format_size+1)*total_wi, nullptr, &err);
    cl::Buffer d_passwords(context, CL_MEM_WRITE_ONLY, sizeof(char)*(format_size+1)*total_wi, nullptr, &err);
    check_error(5, err);
    cl::Buffer d_hashes(context, CL_MEM_WRITE_ONLY, sizeof(char)*(HASH_LENGTH+1)*total_wi, nullptr, &err);
    check_error(6, err);
    cl::Buffer d_matches(context, CL_MEM_WRITE_ONLY | CL_MEM_HOST_READ_ONLY, sizeof(matches_ids), nullptr, &err);
    check_error(6.2, err);

    cl::Kernel kernel(program, "BruteForce");
    err = kernel.setArg(0, d_cnt);
    check_error(7, err);
    err = kernel.setArg(1, d_trie);
    check_error(8, err);
    err = kernel.setArg(2, d_encrypter);
    check_error(8.2, err);
    err = kernel.setArg(3, d_format);
    check_error(9, err);
    err = kernel.setArg(4, d_passwords);
    check_error(10, err);
    err = kernel.setArg(5, d_hashes);
    check_error(11, err);
    err = kernel.setArg(6, d_matches);
    check_error(11.2, err);
    err = kernel.setArg(7, format_size);
    check_error(12, err);
    err = kernel.setArg(8, total_strings);
    check_error(13, err);

    cl::CommandQueue queue(context, device);
    err = queue.enqueueFillBuffer(d_cnt, 0, 0, sizeof(int) * total_wi);
    check_error(13.2, err);
    err = queue.enqueueFillBuffer(d_matches, 0, 0, sizeof(int)*SIZE_MATCHES);
    check_error(13.3, err);
    err = queue.enqueueNDRangeKernel(kernel, cl::NullRange, cl::NDRange(total_wi));
    check_error(14, err);
    err = queue.enqueueReadBuffer(d_cnt, CL_TRUE, 0, sizeof(int) * total_wi, h_cnt);
    check_error(15, err);
    err = queue.enqueueReadBuffer(d_matches, CL_TRUE, 0, sizeof(matches_ids), matches_ids);
    check_error(15, err);
    cl::finish();

    int total_matches = 0;
    MD5 md5;
    char match_pass[format_size+1], match_hash[HASH_LENGTH];
    int sz_per_wi = (SIZE_MATCHES + total_wi - 1) / total_wi;
    for(int i = 0, idx = 0; i < total_wi; ++i, idx += sz_per_wi){
        for(int j = 0; j < h_cnt[i]; ++j){
            if(j == sz_per_wi || idx + j == SIZE_MATCHES) break;
            value_to_password( matches_ids[idx + j], format, format_size, match_pass );
            change_text(&md5, match_pass);
            hexdigest(&md5, match_hash);
            printf("Hash %s matched with string %s\n", match_hash, match_pass);
        }
        total_matches += h_cnt[i];
    }
    printf( "Total matches: %d\n", total_matches );
    return 0;
}