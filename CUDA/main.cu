#include <cstdlib>
#include <iostream>
#include <fstream>
#include <math.h>
#include <string.h>
#include <vector>
#include "md5.h"
#include "omp.h"

using namespace std;

const int HASH_LENGTH = 32;
const int HASH_ALPHA_SIZE = 16;
const int MAX_HASHES_SIZE = 100005;
const int SIZE_MATCHES = 5e5;
int trie_size = 0;
int hashes_trie[HASH_ALPHA_SIZE*HASH_LENGTH*MAX_HASHES_SIZE];
int hash_id[HASH_LENGTH*MAX_HASHES_SIZE];
long long matches_ids[SIZE_MATCHES];

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

__host__ __device__ int char_to_child_id( char ch ){
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

__host__ __device__ bool is_in_hash_trie( char * hash, int* trie, long long string_val ){
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

__host__ __device__ void value_to_password( long long val, char* format, int format_size, char* pass ){
    for(int i = format_size-1; i >= 0; --i){
        int base = (format[i] == '0') ? 10 : 26;
        pass[i] = format[i] + val % base;
        val /= base;
    }
    pass[format_size] = '\0';
}

__device__ bool check_password(long long string_val, MD5 * d_encrypter, char* d_passwords, char* d_hashes, char* format, int format_size, int* d_cnt, int* d_trie, int index){
    value_to_password(string_val, format, format_size, d_passwords+((format_size+1)*index));
    (d_encrypter+index)->change_text(d_passwords+((format_size+1)*index));
    (d_encrypter+index)->hexdigest(d_hashes+((HASH_LENGTH+1)*index));
    if( is_in_hash_trie( d_hashes+((HASH_LENGTH+1)*index), d_trie, string_val ) ){
        d_cnt[index] = d_cnt[index] + 1;
        return true;
        //printf( "Hash %s matched with string %s\n", d_hashes+((HASH_LENGTH+1)*index), d_passwords+((format_size+1)*index));
    }
    return false;
}

__global__ void brute_force( int * d_cnt, int * d_trie, char * d_format, MD5* d_encrypter, char* d_passwords, char* d_hashes, long long * d_matches, int format_size, int total_threads, long long total_strings ){
    long long passwords_per_thread = (total_strings + total_threads - 1) / total_threads;
    int index = (blockDim.x * blockIdx.x) + threadIdx.x;
    long long st = passwords_per_thread * index;
    long long en = min(st + passwords_per_thread, total_strings);
    int sz_per_wi = (SIZE_MATCHES + total_threads - 1) / total_threads;
    int cur_match_pos = index * sz_per_wi;
    int max_match_pos = cur_match_pos + sz_per_wi < SIZE_MATCHES ? cur_match_pos + sz_per_wi : SIZE_MATCHES;
    for(long long i = st; i < en; ++i){
        if( check_password(i, d_encrypter, d_passwords, d_hashes, d_format, format_size, d_cnt, d_trie, index) ){
            if(cur_match_pos < max_match_pos){
                d_matches[cur_match_pos] = i;
            }
            ++cur_match_pos;
        }
    }
}

int main( int argc, char *argv[] ){
    if( argc != 5 ){
        printf( "You must pass exactly four arguments:\n" );
        printf( "  1. The password pattern\n" );
        printf( "  2. The name of the file containing the hashes.\n" );
        printf( "  3. The total number of threads.\n" );
        printf( "  4. The number of blocks.\n" );
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
    int num_threads = ch_to_int( argv[ 3 ] );
    if( num_threads <= 0 ){
        printf( "Invalid argument [%s]. The number of threads must be a positive integer.\n", argv[3] );
        exit( 0 );
    }
    int number_of_blocks = ch_to_int( argv[ 4 ] );
    if( number_of_blocks <= 0 ){
        printf( "Invalid argument [%s]. The number of blocks must be a positive integer.\n", argv[4] );
        exit( 0 );
    }
    build_hashes_trie( in_hash );
    long long total_strings = get_total_strings( format, format_size );

    int size_cnt = sizeof(int) * num_threads;
    //Declaring pointers
    int* h_cnt;
    int* d_cnt;
    char* d_format;
    int* d_trie;
    MD5* d_encrypter;
    char* d_passwords;
    char* d_hashes;
    long long * d_matches;

    //Alloc memory
    h_cnt = (int*)malloc(size_cnt);
    cudaError_t err = cudaSuccess;

    err = cudaMalloc( (void **) &d_cnt, size_cnt );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 1 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    err = cudaMalloc( (void **) &d_format, sizeof(format) );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 2 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    err = cudaMalloc( (void **) &d_trie, sizeof(int)*HASH_ALPHA_SIZE*HASH_LENGTH*MAX_HASHES_SIZE );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 3 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    err = cudaMalloc( (void **) &d_encrypter, sizeof(MD5)*num_threads );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 3.2 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    err = cudaMalloc( (void **) &d_passwords, sizeof(char)*(format_size+1)*num_threads );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 3.3 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    err = cudaMalloc( (void **) &d_hashes, sizeof(char)*(HASH_LENGTH+1)*num_threads );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 3.4 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    err = cudaMalloc( (void **) &d_matches, sizeof(matches_ids) );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 3.5 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    //Initialize
    for(int i = 0; i < num_threads; ++i)
        h_cnt[i] = 0;

    //Copy host to device
    err = cudaMemcpy( d_cnt, h_cnt, size_cnt, cudaMemcpyHostToDevice );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 4 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    err = cudaMemcpy( d_format, format, sizeof(format), cudaMemcpyHostToDevice );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 5 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    err = cudaMemcpy( d_trie, &hashes_trie, sizeof(hashes_trie), cudaMemcpyHostToDevice );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 6 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    //Launch kernel
    int total_threads;
    if(num_threads <= number_of_blocks){
        total_threads = num_threads;
        printf("CUDA kernel launch with %d block(s) of %d thread(s) Total: %i\n", num_threads, 1, num_threads);
        brute_force<<<num_threads, 1>>>(d_cnt, d_trie, d_format, d_encrypter, d_passwords, d_hashes, d_matches, format_size, num_threads, total_strings);
    }
    else{
        int threads_per_block = num_threads/number_of_blocks;
        total_threads = number_of_blocks * threads_per_block;
        printf("CUDA kernel launch with %d block(s) of %d thread(s) Total: %i\n", number_of_blocks, threads_per_block, total_threads);
        brute_force<<<number_of_blocks, threads_per_block>>>(d_cnt, d_trie, d_format, d_encrypter, d_passwords, d_hashes, d_matches, format_size, total_threads, total_strings);
    }

    err = cudaGetLastError();
    if (err != cudaSuccess){
        fprintf(stderr, "Failed to launch kernel (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    //Copy device to host
    err = cudaMemcpy( h_cnt, d_cnt, size_cnt, cudaMemcpyDeviceToHost );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 7 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    err = cudaMemcpy( matches_ids, d_matches, sizeof(matches_ids), cudaMemcpyDeviceToHost );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 7.2 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }

    //Free memory
    err = cudaFree( d_cnt );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 8 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    err = cudaFree( d_trie );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 9 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    err = cudaFree( d_format );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 10 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    err = cudaFree( d_encrypter );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 11 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    err = cudaFree( d_passwords );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 12 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    err = cudaFree( d_hashes );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 13 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    err = cudaFree( d_matches );
    if (err != cudaSuccess){
        fprintf(stderr, "Error 14 (error code %s)!\n", cudaGetErrorString(err));
        exit(EXIT_FAILURE);
    }
    int total_matches = 0;
    MD5 md5;
    char match_pass[format_size+1], match_hash[HASH_LENGTH];
    int sz_per_wi = (SIZE_MATCHES + total_threads - 1) / total_threads;
    for(int i = 0, idx = 0; i < total_threads; ++i, idx += sz_per_wi){
        for(int j = 0; j < h_cnt[i]; ++j){
            if(j == sz_per_wi || idx + j == SIZE_MATCHES) break;
            value_to_password( matches_ids[idx + j], format, format_size, match_pass );
            md5.change_text(match_pass);
            md5.hexdigest(match_hash);
            printf("Hash %s matched with string %s\n", match_hash, match_pass);
        }
        total_matches += h_cnt[i];
    }
    printf("Total matches %d\n", total_matches);
    return 0;
}