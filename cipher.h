#ifndef CIPHER_H
#define CIPHER_H

/*
##### CONSTANTS #####
*/

// The number of columns comprising a state in AES. It's a constant in AES, Nb = 4
unsigned int nb;
// The number of rounds in AES Cipher
unsigned int nr;
// The number of 32 bit words in the key
unsigned int nk;
// The lenght of the key
unsigned int key_len;
// The array that holds the intermediate results during encryption.
unsigned char state[4][4];
// The array that stores the round keys.
unsigned char round_key[240];
// The Key input to the AES Program
unsigned char key[32];

unsigned char sbox[256];
unsigned char rsbox[256];
unsigned char rcon[255];

/*
##### FUNCTIONS #####
*/

const unsigned char get_gamma(int);
const unsigned char get_inv_gamma(int);

void set_cipher_variables(int);
void set_key(const unsigned char[]);

void key_expansion();
void add_round_key(unsigned int);
void add_key(const char[]);
void get_round_key(unsigned int, unsigned char[]);
void sub_bytes();
void inv_sub_bytes();
void shift_rows();
void inv_shift_rows();
void mix_columns();
void inv_mix_columns();

void copy_to_state(const unsigned char[]);
void load_from_state(unsigned char[]);

void encode(const unsigned char[], unsigned char[]);
void decode(const unsigned char[], unsigned char[]);

#endif