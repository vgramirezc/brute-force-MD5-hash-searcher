#include <cstdlib>
#include <iostream>
#include <fstream>
#include <math.h>
#include <string.h>
#include <vector>
#include "md5.h"

using namespace std;

const int HASH_LENGTH = 32;
const int HASH_ALPHA_SIZE = 16;
const int MAX_HASHES_SIZE = 100005;
int trie_size = 0;
int hashes_trie[HASH_ALPHA_SIZE][HASH_LENGTH*MAX_HASHES_SIZE];
int hash_id[HASH_LENGTH*MAX_HASHES_SIZE];
vector<string> hashes_list;

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

void trie_insert( const string& hash, int id ){
    int cur = 0;
    for(int i = 0; i < hash.size(); ++i){
        int ch = char_to_child_id( hash[i] );
        if(hashes_trie[ch][cur] == 0)
            hashes_trie[ch][cur] = ++trie_size;
        cur = hashes_trie[ch][cur];
    }
    hash_id[cur] = id;
}

void build_hashes_trie( ifstream& in_hash ){
    string h;
    while( in_hash >> h ){
        trie_insert( h, hashes_list.size() );
        hashes_list.push_back( h );
    }
}

bool is_in_hash_trie( const string& hash ){
    int cur = 0;
    for(int i = 0; i < hash.size(); ++i){
        int ch = char_to_child_id( hash[i] );
        if(hashes_trie[ch][cur] == 0) return false;
        cur = hashes_trie[ch][cur];
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

char* value_to_password( long long val, char* format, int format_size ){
    char* ans = new char[format_size+1];
    for(int i = format_size-1; i >= 0; --i){
        int base = (format[i] == '0') ? 10 : 26;
        ans[i] = format[i] + val % base;
        val /= base;
    }
    ans[format_size] = 0;
    return ans;
}

void check_password(long long string_val, char* format, int format_size, int& total_matches){
    char * pass = value_to_password(string_val, format, format_size);
    string h = md5( pass );
    if( is_in_hash_trie( h ) ){
        ++total_matches;
        cout << "Hash " << h << " matched with string " << pass << '\n';
    }
}

int main( int argc, char *argv[] ){
    if( argc != 3 || !check_format( argv[1], strlen(argv[1]) ) ){
        cout << "You must pass exactly two arguments:\n";
        cout << "  1. The password pattern to try, using the following format:\n";
        cout << "    * a: lowercase letter [a-z].\n";
        cout << "    * A: uppercase letter. [A-Z]\n";
        cout << "    * 0: digit. [0-9]\n";
        cout << "  E.g.: Aaaaa00 means passwords of length 7 starting with an uppercase letter, followed by 4 lowercase letters and ending with two digits.\n";
        cout << "  2. The name of the file containing the hashes.\n";
        exit( 0 );
    }
    char* format = argv[1];
    int format_size = strlen( format );
    ifstream in_hash( argv[ 2 ] );
    if( !in_hash ){
        cout << "Error reading file " << argv[ 2 ] << '\n';
        exit( 0 );
    }
    build_hashes_trie( in_hash );
    long long total_strings = get_total_strings( format, format_size );
    int total_matches = 0;
    for(long long i = 0; i < total_strings; ++i){
        check_password(i, format, format_size, total_matches);
    }
    cout << "Total matches: " << total_matches << endl;
    return 0;
}