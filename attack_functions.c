#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "attack_functions.h"
#include "cipher.h"
#include "utility.h"

unsigned char S1[256] = {
	0x51,0x7e,0x1a,0x3a,0x3b,0x1f,0xac,0x4b,0x20,0xad,0x88,0xf5,0x4f,0xc5,0x26,0xb5,
	0xde,0x25,0x45,0x5d,0xc3,0x81,0x8d,0x6b,0x03,0x15,0xbf,0x95,0xd4,0x58,0x49,0x8e,
	0x75,0xf4,0x99,0x27,0xbe,0xf0,0xc9,0x7d,0x63,0xe5,0x97,0x62,0xb1,0xbb,0xfe,0xf9,
	0x70,0x8f,0x94,0x52,0xab,0x72,0xe3,0x66,0xb2,0x2f,0x86,0xd3,0x30,0x23,0x02,0xed,
	0x8a,0xa7,0xf3,0x4e,0x65,0x06,0xd1,0xc4,0x34,0xa2,0x05,0xa4,0x0b,0x40,0x5e,0xbd,
	0x3e,0x96,0xdd,0x4d,0x91,0x71,0x04,0x60,0x19,0xd6,0x89,0x67,0xb0,0x07,0xe7,0x79,
	0xa1,0x7c,0xf8,0x00,0x09,0x32,0x1e,0x6c,0xfd,0x0f,0x3d,0x36,0x0a,0x68,0x9b,0x24,
	0x0c,0x93,0xb4,0x1b,0x80,0x61,0x5a,0x1c,0xe2,0xc0,0x3c,0x12,0x0e,0xf2,0x2d,0x14,
	0x57,0xaf,0xee,0xa3,0xf7,0x5c,0x44,0x5b,0x8b,0xcb,0xb6,0xb8,0xd7,0x42,0x13,0x84,
	0x85,0xd2,0xae,0xc7,0x1d,0xdc,0x0d,0x77,0x2b,0xa9,0x11,0x47,0xa8,0xa0,0x56,0x22,
	0x87,0xd9,0x8c,0x98,0xa6,0xa5,0xda,0x3f,0x2c,0x50,0x6a,0x54,0xf6,0x90,0x2e,0x82,
	0x9f,0x69,0x6f,0xcf,0xc8,0x10,0xe8,0xdb,0xcd,0x6e,0xec,0x83,0xe6,0xaa,0x21,0xef,
	0xba,0x4a,0xea,0x29,0x31,0x2a,0xc6,0x35,0x74,0xfc,0xe0,0x33,0xf1,0x41,0x7f,0x17,
	0x76,0x43,0xcc,0xe4,0x9e,0x4c,0xc1,0x46,0x9d,0x01,0xfa,0xfb,0xb3,0x92,0xe9,0x6d,
	0x9a,0x37,0x59,0xeb,0xce,0xb7,0xe1,0x7a,0x9c,0x55,0x18,0x73,0x53,0x5f,0xdf,0x78,
	0xca,0xb9,0x38,0xc2,0x16,0xbc,0x28,0xff,0x39,0x08,0xd8,0x64,0x7b,0xd5,0x48,0xd0
 };


unsigned char S2[256] = {
	0x50,0x53,0xc3,0x96,0xcb,0xf1,0xab,0x93,0x55,0xf6,0x91,0x25,0xfc,0xd7,0x80,0x8f,
	0x49,0x67,0x98,0xe1,0x02,0x12,0xa3,0xc6,0xe7,0x95,0xeb,0xda,0x2d,0xd3,0x29,0x44,
	0x6a,0x78,0x6b,0xdd,0xb6,0x17,0x66,0xb4,0x18,0x82,0x60,0x45,0xe0,0x84,0x1c,0x94,
	0x58,0x19,0x87,0xb7,0x23,0xe2,0x57,0x2a,0x07,0x03,0x9a,0xa5,0xf2,0xb2,0xba,0x5c,
	0x2b,0x92,0xf0,0xa1,0xcd,0xd5,0x1f,0x8a,0x9d,0xa0,0x32,0x75,0x39,0xaa,0x06,0x51,
	0xf9,0x3d,0xae,0x46,0xb5,0x05,0x6f,0xff,0x24,0x97,0xcc,0x77,0xbd,0x88,0x38,0xdb,
	0x47,0xe9,0xc9,0x00,0x83,0x48,0xac,0x4e,0xfb,0x56,0x1e,0x27,0x64,0x21,0xd1,0x3a,
	0xb1,0x0f,0xd2,0x9e,0x4f,0xa2,0x69,0x16,0x0a,0xe5,0x43,0x1d,0x0b,0xad,0xb9,0xc8,
	0x85,0x4c,0xbb,0xfd,0x9f,0xbc,0xc5,0x34,0x76,0xdc,0x68,0x63,0xca,0x10,0x40,0x20,
	0x7d,0xf8,0x11,0x6d,0x4b,0xf3,0xec,0xd0,0x6c,0x99,0xfa,0x22,0xc4,0x1a,0xd8,0xef,
	0xc7,0xc1,0xfe,0x36,0xcf,0x28,0x26,0xa4,0xe4,0x0d,0x9b,0x62,0xc2,0xe8,0x5e,0xf5,
	0xbe,0x7c,0xa9,0xb3,0x3b,0xa7,0x6e,0x7b,0x09,0xf4,0x01,0xa8,0x65,0x7e,0x08,0xe6,
	0xd9,0xce,0xd4,0xd6,0xaf,0x31,0x30,0xc0,0x37,0xa6,0xb0,0x15,0x4a,0xf7,0x0e,0x2f,
	0x8d,0x4d,0x54,0xdf,0xe3,0x1b,0xb8,0x7f,0x04,0x5d,0x73,0x2e,0x5a,0x52,0x33,0x13,
	0x8c,0x7a,0x8e,0x89,0xee,0x35,0xed,0x3c,0x59,0x3f,0x79,0xbf,0xea,0x5b,0x14,0x86,
	0x81,0x3e,0x2c,0x5f,0x72,0x0c,0x8b,0x41,0x71,0xde,0x9c,0x90,0x61,0x70,0x74,0x42
};

unsigned char S3[256] = {
	0xa7,0x65,0xa4,0x5e,0x6b,0x45,0x58,0x03,0xfa,0x6d,0x76,0x4c,0xd7,0xcb,0x44,0xa3,
	0x5a,0x1b,0x0e,0xc0,0x75,0xf0,0x97,0xf9,0x5f,0x9c,0x7a,0x59,0x83,0x21,0x69,0xc8,
	0x89,0x79,0x3e,0x71,0x4f,0xad,0xac,0x3a,0x4a,0x31,0x33,0x7f,0x77,0xae,0xa0,0x2b,
	0x68,0xfd,0x6c,0xf8,0xd3,0x02,0x8f,0xab,0x28,0xc2,0x7b,0x08,0x87,0xa5,0x6a,0x82,
	0x1c,0xb4,0xf2,0xe2,0xf4,0xbe,0x62,0xfe,0x53,0x55,0xe1,0xeb,0xec,0xef,0x9f,0x10,
	0x8a,0x06,0x05,0xbd,0x8d,0x5d,0xd4,0x15,0xfb,0xe9,0x43,0x9e,0x42,0x8b,0x5b,0xee,
	0x0a,0x0f,0x1e,0x00,0x86,0xed,0x70,0x72,0xff,0x38,0xd5,0x39,0xd9,0xa6,0x54,0x2e,
	0x67,0xe7,0x96,0x91,0xc5,0x20,0x4b,0x1a,0xba,0x2a,0xe0,0x17,0x0d,0xc7,0xa8,0xa9,
	0x19,0x07,0xdd,0x60,0x26,0xf5,0x3b,0x7e,0x29,0xc6,0xfc,0xf1,0xdc,0x85,0x22,0x11,
	0x24,0x3d,0x32,0xa1,0x2f,0x30,0x52,0xe3,0x16,0xb9,0x48,0x64,0x8c,0x3f,0x2c,0x90,
	0x4e,0xd1,0xa2,0x0b,0x81,0xde,0x8e,0xbf,0x9d,0x92,0xcc,0x46,0x13,0xb8,0xf7,0xaf,
	0x80,0x93,0x2d,0x12,0x99,0x7d,0x63,0xbb,0x78,0x18,0xb7,0x9a,0x6e,0xe6,0xcf,0xe8,
	0x9b,0x36,0x09,0x7c,0xb2,0x23,0x94,0x66,0xbc,0xca,0xd0,0xd8,0x98,0xda,0x50,0xf6,
	0xd6,0xb0,0x4d,0x04,0xb5,0x88,0x1f,0x51,0xea,0x35,0x74,0x41,0x1d,0xd2,0x56,0x47,
	0x61,0x0c,0x14,0x3c,0x27,0xc9,0xe5,0xb1,0xdf,0x73,0xce,0x37,0xcd,0xaa,0x6f,0xdb,
	0xf3,0xc4,0x34,0x40,0xc3,0x25,0x49,0x95,0x01,0xb3,0xe4,0xc1,0x84,0xb6,0x5c,0x57
};

unsigned char S4[256] = {
	0xf4,0x41,0x17,0x27,0xab,0x9d,0xfa,0xe3,0x30,0x76,0xcc,0x02,0xe5,0x2a,0x35,0x62,
	0xb1,0xba,0xea,0xfe,0x2f,0x4c,0x46,0xd3,0x8f,0x92,0x6d,0x52,0xbe,0x74,0xe0,0xc9,
	0xc2,0x8e,0x58,0xb9,0xe1,0x88,0x20,0xce,0xdf,0x1a,0x51,0x53,0x64,0x6b,0x81,0x08,
	0x48,0x45,0xde,0x7b,0x73,0x4b,0x1f,0x55,0xeb,0xb5,0xc5,0x37,0x28,0xbf,0x03,0x16,
	0xcf,0x79,0x07,0x69,0xda,0x05,0x34,0xa6,0x2e,0xf3,0x8a,0xf6,0x83,0x60,0x71,0x6e,
	0x21,0xdd,0x3e,0xe6,0x54,0xc4,0x06,0x50,0x98,0xbd,0x40,0xd9,0xe8,0x89,0x19,0xc8,
	0x7c,0x42,0x84,0x00,0x80,0x2b,0x11,0x5a,0x0e,0x85,0xae,0x2d,0x0f,0x5c,0x5b,0x36,
	0x0a,0x57,0xee,0x9b,0xc0,0xdc,0x77,0x12,0x93,0xa0,0x22,0x1b,0x09,0x8b,0xb6,0x1e,
	0xf1,0x75,0x99,0x7f,0x01,0x72,0x66,0xfb,0x43,0x23,0xed,0xe4,0x31,0x63,0x97,0xc6,
	0x4a,0xbb,0xf9,0x29,0x9e,0xb2,0x86,0xc1,0xb3,0x70,0x94,0xe9,0xfc,0xf0,0x7d,0x33,
	0x49,0x38,0xca,0xd4,0xf5,0x7a,0xb7,0xad,0x3a,0x78,0x5f,0x7e,0x8d,0xd8,0x39,0xc3,
	0x5d,0xd0,0xd5,0x25,0xac,0x18,0x9c,0x3b,0x26,0x59,0x9a,0x4f,0x95,0xff,0xbc,0x15,
	0xe7,0x6f,0x9f,0xb0,0xa4,0x3f,0xa5,0xa2,0x4e,0x82,0x90,0xa7,0x04,0xec,0xcd,0x91,
	0x4d,0xef,0xaa,0x96,0xd1,0x6a,0x2c,0x65,0x5e,0x8c,0x87,0x0b,0x67,0xdb,0x10,0xd6,
	0xd7,0xa1,0xf8,0x13,0xa9,0x61,0x1c,0x47,0xd2,0xf2,0x14,0xc7,0xf7,0xfd,0x3d,0x44,
	0xaf,0x68,0x24,0xa3,0x1d,0xe2,0x3c,0x0d,0xa8,0x0c,0xb4,0x56,0xcb,0x32,0x6c,0xb8
};

/* 
//
//  AES N STANDARD ROUNDS ENCODING FUNCTION
//
*/

// NOTA: questo codice è molto simile a del codice che si trova in cipher.c

void encode_N_std_rounds(const unsigned char in[], unsigned char out[], unsigned char N )
{
	// Copy the input PlainText to state array.
	copy_to_state( in );

	// Add the First round key to the state before starting the rounds.
	add_round_key(0);

	// There will be N identical rounds.
	// They are executed in the loop below.
	
	unsigned char round;
	
	for (round = 1 ; round <= N ; ++round) 
	{
		sub_bytes();   // Gamma
		shift_rows();  // lambda
		mix_columns(); // lambda
		add_round_key(round);
	}

	// The encryption process is over.
	// Copy the state array to output array.
	load_from_state( out );
}

/* 
//
//  AES N ROUNDS ENCODING FUNCTION
//
*/

//NOTA: molto simile al codice sopra... si può comprimere?

void encode_N_rounds(const unsigned char in[], unsigned char out[], unsigned char N)
{
	// Copy the input PlainText to state array.
	copy_to_state( in );

	// Add the First round key to the state before starting the rounds.
	add_round_key(0);

	// There will be N identical rounds.
	// They are executed in the loop below.

	unsigned char round;
	
	for (round = 1 ; round < N ; ++round ) 
	{
		sub_bytes();   // Gamma
		shift_rows();  // lambda
		mix_columns(); // lambda
		add_round_key(round);
	}

	sub_bytes();
	shift_rows();
	add_round_key(N);

	// The encryption process is over.
	// Copy the state array to output array.
	load_from_state( out );
}


/*
//
// IT CONVERTS A 4 BYTES VECTOR TO UINT32_T
//
*/
unsigned int get_position_4bytes(unsigned char byte_array[])
{
	unsigned long long int pos = 0;
	pos = (byte_array[0]<<24) | (byte_array[1]<<16) | (byte_array[2]<<8) | byte_array[3];
	return pos;
}

/*
//
// IT EXTRACTS THE BYTES CORRESPONDING TO THE PRESCRIBED CONFIGURATION ID
//
*/
void extract(unsigned char ciphertext[], unsigned char config_id, unsigned char tmp[])
{
	if (config_id == 1)
	{
		tmp[0] = ciphertext[0];
		tmp[1] = ciphertext[13];
		tmp[2] = ciphertext[10];
		tmp[3] = ciphertext[7];
	}
	else if (config_id == 2)
	{
		tmp[0] = ciphertext[4];
		tmp[1] = ciphertext[1];
		tmp[2] = ciphertext[14];
		tmp[3] = ciphertext[11];
	}
	else if (config_id == 3)
	{
		tmp[0] = ciphertext[8];
		tmp[1] = ciphertext[5];
		tmp[2] = ciphertext[2];
		tmp[3] = ciphertext[15];
	}
	else if (config_id == 4)
	{
		tmp[0] = ciphertext[12];
		tmp[1] = ciphertext[9];
		tmp[2] = ciphertext[6];
		tmp[3] = ciphertext[3];
	}
}

// k1,k2,k3,k4 sono unsigned char o unsigned int?

void fill( unsigned char k1, unsigned char k2, unsigned char k3, unsigned char k4, unsigned char config_id, unsigned char key_guess[16] )
{
	if (config_id == 1)
	{
		key_guess[0] = k1;
		key_guess[13] = k2;
		key_guess[10] = k3;
		key_guess[7] = k4;
	} else if (config_id == 2) {
		key_guess[4] = k1;
		key_guess[1] = k2;
		key_guess[14] = k3;
		key_guess[11] = k4;
	} else if (config_id == 3) {
		key_guess[8] = k1;
		key_guess[5] = k2;
		key_guess[2] = k3;
		key_guess[15] = k4;
	} else if (config_id == 4) {
		key_guess[12] = k1;
		key_guess[9] = k2;
		key_guess[6] = k3;
		key_guess[3] = k4;
	}
}

/*
//
// IT ENCRYPTS TWO SETS OF 2^32 PLAINTEXTS AND CONSTRUCT TWO VECTORS OF 2^32 BITS FOR THE PRESCRIBED CONFIGURATION ID
//
*/
void encryption(unsigned char plaintext[], unsigned char ciphertext[], unsigned char N_rounds, unsigned char vect[], unsigned char config_id)
{
	unsigned char tmp[4] = {0,0,0,0};
	unsigned long pos;
	
	unsigned int i;
	unsigned int j;
	unsigned int k;
	unsigned int h;
	
	pos = 0;

	for (i = 0; i < 256; ++i)
	{
		for (j = 0; j < 256; ++j)
		{
			for (k = 0; k < 256; ++k)
			{
				for (h = 0; h < 256; ++h)
				{
					// Create the Delta set
					plaintext[0] = i;
					plaintext[5] = j;
					plaintext[10] = k;
					plaintext[15] = h;

					encode_N_rounds(plaintext,ciphertext,N_rounds);
				
					extract(ciphertext,config_id,tmp);
					pos = get_position_4bytes(tmp);
					toggle_bit(vect, pos);
				}
                
			}
		}
	}
}

/* 
//
//  PARTIAL SUM x_2 FIRST ROW
//
*/
unsigned char x_2_firstrow(unsigned char c1, unsigned char c2, unsigned char k1, unsigned char k2)
{
	unsigned char x2 = 0;
	x2 = S1[c1 ^ k1] ^ S2[c2 ^ k2];
	return x2;
}

/* 
//
//  PARTIAL SUM x_3 FIRST ROW
//
*/
unsigned char x_3_firstrow(unsigned char x2, unsigned char c3, unsigned char k3 )
{
	unsigned char x3 = 0;
	x3 = x2 ^ S3[c3 ^ k3];
	return x3;
}

/* 
//
//  PARTIAL SUM x_4 FIRST ROW
//
*/
unsigned char x_4_firstrow(unsigned char x3, unsigned char c4, unsigned char k4 )
{
	unsigned char x4 = 0;
	x4 = x3 ^ S4[c4 ^ k4];
	return x4;
}

/* 
//
//  PARTIAL SUM x_2 SECOND ROW
//
*/

unsigned char x_2_secondrow(unsigned char c1, unsigned char c2, unsigned char k1, unsigned char k2)
{
	unsigned char x2 = 0;
	x2 = S4[c1 ^ k1] ^ S1[c2 ^ k2];
	return x2;
}

/* 
//
//  PARTIAL SUM x_3 SECOND ROW
//
*/
unsigned char x_3_secondrow(unsigned char x2, unsigned char c3, unsigned char k3)
{
	unsigned char x3 = 0;
	x3 = x2 ^ S2[c3 ^ k3];
	return x3;
}

/* 
//
//  PARTIAL SUM x_4 SECOND ROW
//
*/
unsigned char x_4_secondrow(unsigned char x3, unsigned char c4, unsigned char k4 )
{
	unsigned char x4 = 0;
	x4 = x3 ^ S3[c4 ^ k4];
	return x4;
}

/* 
//
//  PARTIAL SUM x_2 THIRD ROW
//
*/
unsigned char x_2_thirdrow(unsigned char c1, unsigned char c2, unsigned char k1, unsigned char k2)
{
	unsigned char x2 = 0;
	x2 = S3[c1 ^ k1] ^ S4[c2 ^ k2];
	return x2;
}

/* 
//
//  PARTIAL SUM x_3 THIRD ROW
//
*/
unsigned char x_3_thirdrow(unsigned char x2, unsigned char c3, unsigned char k3)
{
	unsigned char x3 = 0;
	x3 = x2 ^ S1[c3 ^ k3];
	return x3;
}

/* 
//
//  PARTIAL SUM x_4 THIRD ROW
//
*/
unsigned char x_4_thirdrow(unsigned char x3, unsigned char c4, unsigned char k4 )
{
	unsigned char x4 = 0;
	x4 = x3 ^ S2[c4 ^ k4];
	return x4;
}

/* 
//
//  PARTIAL SUM x_2 FOURTH ROW
//
*/
unsigned char x_2_fourthrow(unsigned char c1, unsigned char c2, unsigned char k1, unsigned char k2)
{
	unsigned char x2 = 0;
	x2 = S2[c1 ^ k1] ^ S3[c2 ^ k2];
	return x2;
}

/* 
//
//  PARTIAL SUM x_3 FOURTH ROW
//
*/
unsigned char x_3_fourthrow(unsigned char x2, unsigned char c3, unsigned char k3)
{
	unsigned char x3 = 0;
	x3 = x2 ^ S4[c3 ^ k3];
	return x3;
}

/* 
//
//  PARTIAL SUM x_4 FOURTH ROW
//
*/
unsigned char x_4_fourthrow(unsigned char x3, unsigned char c4, unsigned char k4 )
{
	unsigned char x4 = 0;
	x4 = x3 ^ S1[c4 ^ k4];
	return x4;
}

/* 
//
//  TOTAL SUM
//
*/
unsigned char total_sum(unsigned char vect[], unsigned char k5)
{
	unsigned char sum;
	unsigned int i;
	
	sum = 0;
	
	for (i = 0; i < 256; ++i)
	{
		if (vect[i/8] & (1 << (7-i%8)))
		{
			sum ^= get_inv_gamma(i ^ k5);
		}
	}
	return sum;
}

/*
//
// UPDATE THE VECTOR OF 2^24 BITS FIRST ROW
//
*/
unsigned char * get_encrypted_array(char * file_path){

	unsigned long long int two_to_32_vector_size;
	unsigned int char_array_size, j;

	two_to_32_vector_size = 4294967296u;
	char_array_size = two_to_32_vector_size/8;

	FILE * vect_file;

	printf ("WORKER %*.d: %*.4f - Opening 2^32 bit encrypted vectors' file...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));

	vect_file = fopen(file_path,"r");

	if (vect_file == NULL){
		printf ("WORKER %*.d: %*.4f - ERROR: cannot open the encrypted vector files!\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
		return NULL;
	}

	unsigned char *vector;

	printf ("WORKER %*.d: %*.4f - Allocating memory for encrypted vector file...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));

	vector = malloc (sizeof(char)*char_array_size);

	printf ("WORKER %*.d: %*.4f - Starting reading encrypted vector file...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));

	for ( j = 0; j < char_array_size; j++){
		vector[j] = getc(vect_file);
	}

	printf ("WORKER %*.d: %*.4f - Done! Closing files' sockets...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));

	fclose(vect_file);
	
	return vector;
}

/*
//
// UPDATE THE VECTOR OF 2^24 BITS FIRST ROW
//
*/
void update_vect_2_24_firstrow(unsigned char *encrypted_vector, unsigned char vect12[], unsigned char k1, unsigned char k2)
{
	unsigned long long pos32;
	unsigned long long pos24;
	unsigned long long i;
	unsigned long long j;
	unsigned long long maxiter;
	
    unsigned char a;
    unsigned char b;
    unsigned char x2;
    
    unsigned long long int * encrypted_vector_big_pointer;
    unsigned long long int * vect12_big_pointer;
    
    encrypted_vector_big_pointer = (unsigned long long int *)encrypted_vector;
    vect12_big_pointer = (unsigned long long int *) vect12;
    
	printf ("WORKER %*.d: %*.4f - Starting the update 2_24_firstrow main loop...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
    
    for (i = 0; i < 262144; i++){
        vect12_big_pointer[i] = 0x00;
    }
    
    for(i=0; i<65536; ++i )
    {
        // Compute c1,c2
        a = (i >> 8) & 0xff;
        b = i & 0xff;

        pos32 = i << 10;
        x2 = x_2_firstrow(a,b,k1,k2);
        pos24 = x2 << 10;
        maxiter = pos24 + 1024;

        // Update vect12
        for(j=pos24; j<maxiter; ++j)
        {
            vect12_big_pointer[j] = encrypted_vector_big_pointer[pos32] ^ vect12_big_pointer[j];
            pos32++;
        }
    }
	
	printf ("WORKER %*.d: %*.4f - Released memory from 2_24_firstrow.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
}

/*
//
// UPDATE THE VECTOR OF 2^16 BITS FIRST ROW
//
*/
void update_vect_2_16_firstrow(unsigned char vect12[], unsigned char vect13[], unsigned char k3)
{
	unsigned long pos24;
	unsigned long pos16;
	unsigned long maxiter;
	unsigned long i;
	unsigned long j;
	
	unsigned char a;
	unsigned char b;
	unsigned char x3;
    
    unsigned long long int * vect12_big_pointer;
    unsigned long long int * vect13_big_pointer;
    
    vect12_big_pointer = (unsigned long long int *) vect12;
    vect13_big_pointer = (unsigned long long int *) vect13;
	
	//printf ("WORKER %*.d: %*.4f - Starting the update 2_16_firstrow main loop...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
    
    for (i = 0; i < 1024; i++){
        vect13_big_pointer[i] = 0x00;
    }

    for( i=0; i<65536; ++i )
    {
        // Compute x2,c3
        a = (i >> 8) & 0xff;
        b = i & 0xff;

        pos24 = i << 2;
        x3 = x_3_firstrow(a,b,k3);
        pos16 = x3 << 2;
        maxiter = pos16 + 4;

        // Update vect13
        for( j=pos16; j<maxiter; ++j )
        {
            vect13_big_pointer[j] = vect12_big_pointer[pos24] ^ vect13_big_pointer[j];
            pos24++;
        }
    }
    
	//printf ("WORKER %*.d: %*.4f - Main loop of 2_16_firstrow completed.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
}

/*
//
// UPDATE THE VECTOR OF 2^8 BITS FIRST ROW
//
*/
void update_vect_2_8_firstrow(unsigned char vect13[], unsigned char vect14[], unsigned char k4)
{
	unsigned long pos8;
	unsigned long i;
	
	unsigned char a;
	unsigned char b;
	unsigned char x4;

	//printf ("WORKER %*.d: %*.4f - Starting the update 2_8_firstrow main loop...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
    
    for (i = 0; i < 32; i++){
        vect14[i] = 0x00;
    }
	
    for (i=0; i<65536; ++i)
    {
        // Compute x3,c4
        a = (i >> 8) & 0xff;
        b = i & 0xff;

        x4 = x_4_firstrow(a,b,k4);
        pos8 = x4;

        if (vect13[i/8] & (1 << (7-i%8)))
        {
            // Update vect14
            toggle_bit(vect14,pos8);
        }

    }
    
	//printf ("WORKER %*.d: %*.4f - Main loop of 2_8_firstrow completed.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
}

/*
//
// UPDATE THE VECTOR OF 2^24 BITS SECOND ROW
//
*/
void update_vect_2_24_secondrow(unsigned char *encrypted_vector, unsigned char vect12[], unsigned char k1, unsigned char k2)
{
	unsigned long long pos32;
	unsigned long long pos24;
	unsigned long long i;
	unsigned long long j;
	unsigned long long maxiter;
	
    unsigned char a;
    unsigned char b;
    unsigned char x2;
    
    unsigned long long int * encrypted_vector_big_pointer;
    unsigned long long int * vect12_big_pointer;
    
    encrypted_vector_big_pointer = (unsigned long long int *)encrypted_vector;
    vect12_big_pointer = (unsigned long long int *) vect12;

	printf ("WORKER %*.d: %*.4f - Starting the update 2_24_secondrow main loop...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	
    for (i = 0; i < 262144; i++){
        vect12_big_pointer[i] = 0x00;
    }
    
    for(i=0; i<65536; ++i )
    {
        // Compute c1,c2
        a = (i >> 8) & 0xff;
        b = i & 0xff;

        pos32 = i << 10;
        x2 = x_2_secondrow(a,b,k1,k2);
        pos24 = x2 << 10;
        maxiter = pos24 + 1024;

        // Update vect12
        for(j=pos24; j<maxiter; ++j)
        {
            vect12_big_pointer[j] = encrypted_vector_big_pointer[pos32] ^ vect12_big_pointer[j];
            pos32++;
        }
    }
	
	printf ("WORKER %*.d: %*.4f - Main loop of 2_24_secondrow completed.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));

}

/*
//
// UPDATE THE VECTOR OF 2^16 BITS SECOND ROW
//
*/
void update_vect_2_16_secondrow(unsigned char vect12[], unsigned char vect13[], unsigned char k3 )
{
	unsigned long pos24;
	unsigned long pos16;
	unsigned long maxiter;
	unsigned long i;
	unsigned long j;
	
	unsigned char a;
	unsigned char b;
	unsigned char x3;
    
    unsigned long long int * vect12_big_pointer;
    unsigned long long int * vect13_big_pointer;
    
    vect12_big_pointer = (unsigned long long int *) vect12;
    vect13_big_pointer = (unsigned long long int *) vect13;

	//printf ("WORKER %*.d: %*.4f - Starting the update 2_16_secondrow main loop...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	
    for (i = 0; i < 1024; i++){
        vect13_big_pointer[i] = 0x00;
    }
    
    for( i=0; i<65536; ++i )
    {
        // Compute x2,c3
        a = (i >> 8) & 0xff;
        b = i & 0xff;

        pos24 = i << 2;
        x3 = x_3_secondrow(a,b,k3);
        pos16 = x3 << 2;
        maxiter = pos16 + 4;

        // Update vect13
        for( j=pos16; j<maxiter; ++j )
        {
            vect13_big_pointer[j] = vect12_big_pointer[pos24] ^ vect13_big_pointer[j];
            pos24++;
        }
    }
	//printf ("WORKER %*.d: %*.4f - Main loop of 2_16_secondrow completed.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
}

/*
//
// UPDATE THE VECTOR OF 2^8 BITS SECOND ROW
//
*/
void update_vect_2_8_secondrow(unsigned char vect13[], unsigned char vect14[], unsigned char k4 )
{
	unsigned long pos16;
	unsigned long pos8;
	unsigned long i;
	
	unsigned char a;
	unsigned char b;
	unsigned char x4;

	//printf ("WORKER %*.d: %*.4f - Starting the update 2_8_secondrow main loop...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
    
    for (i = 0; i < 32; i++){
        vect14[i] = 0x00;
    }
	
    for (i=0; i<65536; ++i)
    {
        // Compute x3,c4
        a = (i >> 8) & 0xff;
        b = i & 0xff;

        x4 = x_4_secondrow(a,b,k4);
        pos8 = x4;

        if (vect13[i/8] & (1 << (7-i%8)))
        {
            // Update vect14
            toggle_bit(vect14,pos8);
        }

    }
	
	//printf ("WORKER %*.d: %*.4f - Main loop of 2_8_secondrow completed.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
}

/*
//
// UPDATE THE VECTOR OF 2^24 BITS THIRD ROW
//
*/
void update_vect_2_24_thirdrow(unsigned char *encrypted_vector, unsigned char vect12[], unsigned char k1, unsigned char k2)
{
	unsigned long long pos32;
	unsigned long long pos24;
	unsigned long long i;
	unsigned long long j;
	unsigned long long maxiter;
	
    unsigned char a;
    unsigned char b;
    unsigned char x2;
    
    unsigned long long int * encrypted_vector_big_pointer;
    unsigned long long int * vect12_big_pointer;
    
    encrypted_vector_big_pointer = (unsigned long long int *)encrypted_vector;
    vect12_big_pointer = (unsigned long long int *) vect12;
    
	printf ("WORKER %*.d: %*.4f - Starting the update 2_24_thirdrow main loop...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
    
    for (i = 0; i < 262144; i++){
        vect12_big_pointer[i] = 0x00;
    }
    
    for(i=0; i<65536; ++i )
    {
        // Compute c1,c2
        a = (i >> 8) & 0xff;
        b = i & 0xff;

        pos32 = i << 10;
        x2 = x_2_thirdrow(a,b,k1,k2);
        pos24 = x2 << 10;
        maxiter = pos24 + 1024;

        // Update vect12
        for(j=pos24; j<maxiter; ++j)
        {
            vect12_big_pointer[j] = encrypted_vector_big_pointer[pos32] ^ vect12_big_pointer[j];
            pos32++;
        }
    }
	
	printf ("WORKER %*.d: %*.4f - Released memory from 2_24_thirdrow.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
}

/*
//
// UPDATE THE VECTOR OF 2^16 BITS THIRD ROW
//
*/
void update_vect_2_16_thirdrow(unsigned char vect12[], unsigned char vect13[], unsigned char k3)
{
	unsigned long pos24;
	unsigned long pos16;
	unsigned long maxiter;
	unsigned long i;
	unsigned long j;
	
	unsigned char a;
	unsigned char b;
	unsigned char x3;
    
    unsigned long long int * vect12_big_pointer;
    unsigned long long int * vect13_big_pointer;
    
    vect12_big_pointer = (unsigned long long int *) vect12;
    vect13_big_pointer = (unsigned long long int *) vect13;
	
	//printf ("WORKER %*.d: %*.4f - Starting the update 2_16_thirdrow main loop...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
    
    for (i = 0; i < 1024; i++){
        vect13_big_pointer[i] = 0x00;
    }

    for( i=0; i<65536; ++i )
    {
        // Compute x2,c3
        a = (i >> 8) & 0xff;
        b = i & 0xff;

        pos24 = i << 2;
        x3 = x_3_thirdrow(a,b,k3);
        pos16 = x3 << 2;
        maxiter = pos16 + 4;

        // Update vect13
        for( j=pos16; j<maxiter; ++j )
        {
            vect13_big_pointer[j] = vect12_big_pointer[pos24] ^ vect13_big_pointer[j];
            pos24++;
        }
    }
    
	//printf ("WORKER %*.d: %*.4f - Main loop of 2_16_thirdrow completed.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
}

/*
//
// UPDATE THE VECTOR OF 2^8 BITS THIRD ROW
//
*/
void update_vect_2_8_thirdrow(unsigned char vect13[], unsigned char vect14[], unsigned char k4)
{
	unsigned long pos8;
	unsigned long i;
	
	unsigned char a;
	unsigned char b;
	unsigned char x4;

	//printf ("WORKER %*.d: %*.4f - Starting the update 2_8_thirdrow main loop...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
    
    for (i = 0; i < 32; i++){
        vect14[i] = 0x00;
    }
	
    for (i=0; i<65536; ++i)
    {
        // Compute x3,c4
        a = (i >> 8) & 0xff;
        b = i & 0xff;

        x4 = x_4_thirdrow(a,b,k4);
        pos8 = x4;

        if (vect13[i/8] & (1 << (7-i%8)))
        {
            // Update vect14
            toggle_bit(vect14,pos8);
        }

    }
    
	//printf ("WORKER %*.d: %*.4f - Main loop of 2_8_thirdrow completed.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
}


/*
//
// UPDATE THE VECTOR OF 2^24 BITS FOURTH ROW
//
*/
void update_vect_2_24_fourthrow(unsigned char *encrypted_vector, unsigned char vect12[], unsigned char k1, unsigned char k2)
{
	unsigned long long pos32;
	unsigned long long pos24;
	unsigned long long i;
	unsigned long long j;
	unsigned long long maxiter;
	
    unsigned char a;
    unsigned char b;
    unsigned char x2;
    
    unsigned long long int * encrypted_vector_big_pointer;
    unsigned long long int * vect12_big_pointer;
    
    encrypted_vector_big_pointer = (unsigned long long int *)encrypted_vector;
    vect12_big_pointer = (unsigned long long int *) vect12;
    
	printf ("WORKER %*.d: %*.4f - Starting the update 2_24_fourthrow main loop...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
    
    for (i = 0; i < 262144; i++){
        vect12_big_pointer[i] = 0x00;
    }
    
    for(i=0; i<65536; ++i )
    {
        // Compute c1,c2
        a = (i >> 8) & 0xff;
        b = i & 0xff;

        pos32 = i << 10;
        x2 = x_2_fourthrow(a,b,k1,k2);
        pos24 = x2 << 10;
        maxiter = pos24 + 1024;

        // Update vect12
        for(j=pos24; j<maxiter; ++j)
        {
            vect12_big_pointer[j] = encrypted_vector_big_pointer[pos32] ^ vect12_big_pointer[j];
            pos32++;
        }
    }
	
	printf ("WORKER %*.d: %*.4f - Released memory from 2_24_fourthrow.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
}

/*
//
// UPDATE THE VECTOR OF 2^16 BITS FOURTH ROW
//
*/
void update_vect_2_16_fourthrow(unsigned char vect12[], unsigned char vect13[], unsigned char k3)
{
	unsigned long pos24;
	unsigned long pos16;
	unsigned long maxiter;
	unsigned long i;
	unsigned long j;
	
	unsigned char a;
	unsigned char b;
	unsigned char x3;
    
    unsigned long long int * vect12_big_pointer;
    unsigned long long int * vect13_big_pointer;
    
    vect12_big_pointer = (unsigned long long int *) vect12;
    vect13_big_pointer = (unsigned long long int *) vect13;
	
	//printf ("WORKER %*.d: %*.4f - Starting the update 2_16_fourthrow main loop...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
    
    for (i = 0; i < 1024; i++){
        vect13_big_pointer[i] = 0x00;
    }

    for( i=0; i<65536; ++i )
    {
        // Compute x2,c3
        a = (i >> 8) & 0xff;
        b = i & 0xff;

        pos24 = i << 2;
        x3 = x_3_fourthrow(a,b,k3);
        pos16 = x3 << 2;
        maxiter = pos16 + 4;

        // Update vect13
        for( j=pos16; j<maxiter; ++j )
        {
            vect13_big_pointer[j] = vect12_big_pointer[pos24] ^ vect13_big_pointer[j];
            pos24++;
        }
    }
    
	//printf ("WORKER %*.d: %*.4f - Main loop of 2_16_fourthrow completed.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
}

/*
//
// UPDATE THE VECTOR OF 2^8 BITS FOURTH ROW
//
*/
void update_vect_2_8_fourthrow(unsigned char vect13[], unsigned char vect14[], unsigned char k4)
{
	unsigned long pos8;
	unsigned long i;
	
	unsigned char a;
	unsigned char b;
	unsigned char x4;

	//printf ("WORKER %*.d: %*.4f - Starting the update 2_8_fourthrow main loop...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
    
    for (i = 0; i < 32; i++){
        vect14[i] = 0x00;
    }
	
    for (i=0; i<65536; ++i)
    {
        // Compute x3,c4
        a = (i >> 8) & 0xff;
        b = i & 0xff;

        x4 = x_4_fourthrow(a,b,k4);
        pos8 = x4;

        if (vect13[i/8] & (1 << (7-i%8)))
        {
            // Update vect14
            toggle_bit(vect14,pos8);
        }

    }
    
	//printf ("WORKER %*.d: %*.4f - Main loop of 2_8_fourthrow completed.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
}

/* 
//
//  FOURTH ROW INSTANCE
//
*/
int fourth_row_instance(unsigned char *fourthvect12, unsigned char *fourthvect22, unsigned char *fourthvect32, unsigned char k3, unsigned char k4 )
{
	int flag;
	unsigned long i;
	
	flag = 0;

	// Create vectors of 2^16 bits
	unsigned char *fourthvect13;
	unsigned char *fourthvect23;
	unsigned char *fourthvect33;
        
    unsigned long long int *fourthvect13_big_pointer;
	unsigned long long int *fourthvect23_big_pointer;
	unsigned long long int *fourthvect33_big_pointer;
	
	//printf ("WORKER %*.d: %*.4f - Allocating 2^16 bits fourth vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	
	fourthvect13_big_pointer = malloc(sizeof(unsigned long long int)*1024);
	fourthvect23_big_pointer = malloc(sizeof(unsigned long long int)*1024);
	fourthvect33_big_pointer = malloc(sizeof(unsigned long long int)*1024);
	
	for(i = 0; i < 1024; i++)
	{
		fourthvect13_big_pointer[i] = 0x00;
		fourthvect23_big_pointer[i] = 0x00;
		fourthvect33_big_pointer[i] = 0x00;
	}
    
    fourthvect13 = (unsigned char *)fourthvect13_big_pointer;
	fourthvect23 = (unsigned char *)fourthvect23_big_pointer;
	fourthvect33 = (unsigned char *)fourthvect33_big_pointer;

	//printf ("WORKER %*.d: %*.4f - Allocated and initilized 2^16 bits fourth vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));

	// Create vectors of 2^8 bits
	unsigned char *fourthvect14;
	unsigned char *fourthvect24;
	unsigned char *fourthvect34;
    
    unsigned long long int *fourthvect14_big_pointer;
	unsigned long long int *fourthvect24_big_pointer;
	unsigned long long int *fourthvect34_big_pointer;
	
	//printf ("WORKER %*.d: %*.4f - Allocating 2^8 bits fourth vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	
	fourthvect14_big_pointer = malloc(sizeof(unsigned long long int)*4);
	fourthvect24_big_pointer = malloc(sizeof(unsigned long long int)*4);
	fourthvect34_big_pointer = malloc(sizeof(unsigned long long int)*4);
	
	for(i = 0; i < 4; i++)
	{
		fourthvect14_big_pointer[i] = 0x00;
		fourthvect24_big_pointer[i] = 0x00;
		fourthvect34_big_pointer[i] = 0x00;
	}
    
    fourthvect14 = (unsigned char *)fourthvect14_big_pointer;
	fourthvect24 = (unsigned char *)fourthvect24_big_pointer;
	fourthvect34 = (unsigned char *)fourthvect34_big_pointer;
	
	//printf ("WORKER %*.d: %*.4f - Allocated and initilized 2^8 bits fourth vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	
	unsigned char fourthsum1 = 0;
	unsigned char fourthsum2 = 0;
	unsigned char fourthsum3 = 0;
	
	// printf ("WORKER %*.d: %*.4f - Updating fourthvect13...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_16_fourthrow(fourthvect12,fourthvect13,k3);
	
	// printf ("WORKER %*.d: %*.4f - Updating fourthvect23...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_16_fourthrow(fourthvect22,fourthvect23,k3);
	
	// printf ("WORKER %*.d: %*.4f - Updating fourthvect33...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_16_fourthrow(fourthvect32,fourthvect33,k3);
	
	// printf ("WORKER %*.d: %*.4f - Updated 2^16 bits fourth vectors.\n", 4, rank, 10, get_elapsed_time(worker_start_t));


	// printf ("WORKER %*.d: %*.4f - Updating fourthvect14...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_8_fourthrow(fourthvect13,fourthvect14,k4);
	
	// printf ("WORKER %*.d: %*.4f - Updating fourthvect24...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_8_fourthrow(fourthvect23,fourthvect24,k4);
	
	// printf ("WORKER %*.d: %*.4f - Updating fourthvect34...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_8_fourthrow(fourthvect33,fourthvect34,k4);

	// printf ("WORKER %*.d: %*.4f - Updated 2^8 bits fourth vectors.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	unsigned int k5;
	
	for (k5 = 0; k5 < 256; ++k5)
	{
		
		fourthsum1 = total_sum(fourthvect14,k5);
		fourthsum2 = total_sum(fourthvect24,k5);
		fourthsum3 = total_sum(fourthvect34,k5);

		if ((fourthsum1 == 0) && (fourthsum2 == 0) && (fourthsum3 == 0))
		{
			flag = 1;
			break;
		}
	}
	
	free (fourthvect13);
	free (fourthvect23);
	free (fourthvect33);
	
	free (fourthvect14);
	free (fourthvect24);
	free (fourthvect34);
	
	return flag;
}

/* 
//
//  THIRD ROW INSTANCE
//
*/
int third_row_instance(unsigned char *thirdvect12, unsigned char *thirdvect22, unsigned char *thirdvect32, unsigned char k3, unsigned char k4 )
{
	int flag;
	unsigned long i;
	
	flag = 0;

	// Create vectors of 2^16 bits
	unsigned char *thirdvect13;
	unsigned char *thirdvect23;
	unsigned char *thirdvect33;
        
    unsigned long long int *thirdvect13_big_pointer;
	unsigned long long int *thirdvect23_big_pointer;
	unsigned long long int *thirdvect33_big_pointer;
	
	//printf ("WORKER %*.d: %*.4f - Allocating 2^16 bits third vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	
	thirdvect13_big_pointer = malloc(sizeof(unsigned long long int)*1024);
	thirdvect23_big_pointer = malloc(sizeof(unsigned long long int)*1024);
	thirdvect33_big_pointer = malloc(sizeof(unsigned long long int)*1024);
	
	for(i = 0; i < 1024; i++)
	{
		thirdvect13_big_pointer[i] = 0x00;
		thirdvect23_big_pointer[i] = 0x00;
		thirdvect33_big_pointer[i] = 0x00;
	}
    
    thirdvect13 = (unsigned char *)thirdvect13_big_pointer;
	thirdvect23 = (unsigned char *)thirdvect23_big_pointer;
	thirdvect33 = (unsigned char *)thirdvect33_big_pointer;

	//printf ("WORKER %*.d: %*.4f - Allocated and initilized 2^16 bits third vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));

	// Create vectors of 2^8 bits
	unsigned char *thirdvect14;
	unsigned char *thirdvect24;
	unsigned char *thirdvect34;
    
    unsigned long long int *thirdvect14_big_pointer;
	unsigned long long int *thirdvect24_big_pointer;
	unsigned long long int *thirdvect34_big_pointer;
	
	//printf ("WORKER %*.d: %*.4f - Allocating 2^8 bits third vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	
	thirdvect14_big_pointer = malloc(sizeof(unsigned long long int)*4);
	thirdvect24_big_pointer = malloc(sizeof(unsigned long long int)*4);
	thirdvect34_big_pointer = malloc(sizeof(unsigned long long int)*4);
	
	for(i = 0; i < 4; i++)
	{
		thirdvect14_big_pointer[i] = 0x00;
		thirdvect24_big_pointer[i] = 0x00;
		thirdvect34_big_pointer[i] = 0x00;
	}
    
    thirdvect14 = (unsigned char *)thirdvect14_big_pointer;
	thirdvect24 = (unsigned char *)thirdvect24_big_pointer;
	thirdvect34 = (unsigned char *)thirdvect34_big_pointer;
	
	//printf ("WORKER %*.d: %*.4f - Allocated and initilized 2^8 bits third vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	
	unsigned char thirdsum1 = 0;
	unsigned char thirdsum2 = 0;
	unsigned char thirdsum3 = 0;
	
	// printf ("WORKER %*.d: %*.4f - Updating thirdvect13...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_16_thirdrow(thirdvect12,thirdvect13,k3);
	
	// printf ("WORKER %*.d: %*.4f - Updating thirdvect23...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_16_thirdrow(thirdvect22,thirdvect23,k3);
	
	// printf ("WORKER %*.d: %*.4f - Updating thirdvect33...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_16_thirdrow(thirdvect32,thirdvect33,k3);
	
	// printf ("WORKER %*.d: %*.4f - Updated 2^16 bits third vectors.\n", 4, rank, 10, get_elapsed_time(worker_start_t));


	// printf ("WORKER %*.d: %*.4f - Updating thirdvect14...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_8_thirdrow(thirdvect13,thirdvect14,k4);
	
	// printf ("WORKER %*.d: %*.4f - Updating thirdvect24...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_8_thirdrow(thirdvect23,thirdvect24,k4);
	
	// printf ("WORKER %*.d: %*.4f - Updating thirdvect34...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_8_thirdrow(thirdvect33,thirdvect34,k4);

	// printf ("WORKER %*.d: %*.4f - Updated 2^8 bits third vectors.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	unsigned int k5;
	
	for (k5 = 0; k5 < 256; ++k5)
	{
		
		thirdsum1 = total_sum(thirdvect14,k5);
		thirdsum2 = total_sum(thirdvect24,k5);
		thirdsum3 = total_sum(thirdvect34,k5);

		if ((thirdsum1 == 0) && (thirdsum2 == 0) && (thirdsum3 == 0))
		{
			flag = 1;
			break;
		}
	}
	
	free (thirdvect13);
	free (thirdvect23);
	free (thirdvect33);
	
	free (thirdvect14);
	free (thirdvect24);
	free (thirdvect34);
	
	return flag;
}

/* 
//
//  SECOND ROW INSTANCE
//
*/
int second_row_instance(unsigned char *secondvect12, unsigned char *secondvect22, unsigned char *secondvect32, unsigned char k3, unsigned char k4 )
{
	int flag;
	unsigned long i;
	
	flag = 0;

	// Create vectors of 2^16 bits
	unsigned char *secondvect13;
	unsigned char *secondvect23;
	unsigned char *secondvect33;
        
    unsigned long long int *secondvect13_big_pointer;
	unsigned long long int *secondvect23_big_pointer;
	unsigned long long int *secondvect33_big_pointer;
	
	//printf ("WORKER %*.d: %*.4f - Allocating 2^16 bits second vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	
	secondvect13_big_pointer = malloc(sizeof(unsigned long long int)*1024);
	secondvect23_big_pointer = malloc(sizeof(unsigned long long int)*1024);
	secondvect33_big_pointer = malloc(sizeof(unsigned long long int)*1024);
	
	for(i = 0; i < 1024; i++)
	{
		secondvect13_big_pointer[i] = 0x00;
		secondvect23_big_pointer[i] = 0x00;
		secondvect33_big_pointer[i] = 0x00;
	}
    
    secondvect13 = (unsigned char *)secondvect13_big_pointer;
	secondvect23 = (unsigned char *)secondvect23_big_pointer;
	secondvect33 = (unsigned char *)secondvect33_big_pointer;

	//printf ("WORKER %*.d: %*.4f - Allocated and initilized 2^16 bits second vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));

	// Create vectors of 2^8 bits
	unsigned char *secondvect14;
	unsigned char *secondvect24;
	unsigned char *secondvect34;
    
    unsigned long long int *secondvect14_big_pointer;
	unsigned long long int *secondvect24_big_pointer;
	unsigned long long int *secondvect34_big_pointer;
	
	//printf ("WORKER %*.d: %*.4f - Allocating 2^8 bits second vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	
	secondvect14_big_pointer = malloc(sizeof(unsigned long long int)*4);
	secondvect24_big_pointer = malloc(sizeof(unsigned long long int)*4);
	secondvect34_big_pointer = malloc(sizeof(unsigned long long int)*4);
	
	for(i = 0; i < 4; i++)
	{
		secondvect14_big_pointer[i] = 0x00;
		secondvect24_big_pointer[i] = 0x00;
		secondvect34_big_pointer[i] = 0x00;
	}
    
    secondvect14 = (unsigned char *)secondvect14_big_pointer;
	secondvect24 = (unsigned char *)secondvect24_big_pointer;
	secondvect34 = (unsigned char *)secondvect34_big_pointer;
	
	//printf ("WORKER %*.d: %*.4f - Allocated and initilized 2^8 bits second vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	
	unsigned char secondsum1 = 0;
	unsigned char secondsum2 = 0;
	unsigned char secondsum3 = 0;
	
	// printf ("WORKER %*.d: %*.4f - Updating secondvect13...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_16_secondrow(secondvect12,secondvect13,k3);
	
	// printf ("WORKER %*.d: %*.4f - Updating secondvect23...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_16_secondrow(secondvect22,secondvect23,k3);
	
	// printf ("WORKER %*.d: %*.4f - Updating secondvect33...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_16_secondrow(secondvect32,secondvect33,k3);
	
	// printf ("WORKER %*.d: %*.4f - Updated 2^16 bits second vectors.\n", 4, rank, 10, get_elapsed_time(worker_start_t));


	// printf ("WORKER %*.d: %*.4f - Updating secondvect14...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_8_secondrow(secondvect13,secondvect14,k4);
	
	// printf ("WORKER %*.d: %*.4f - Updating secondvect24...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_8_secondrow(secondvect23,secondvect24,k4);
	
	// printf ("WORKER %*.d: %*.4f - Updating secondvect34...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_8_secondrow(secondvect33,secondvect34,k4);

	// printf ("WORKER %*.d: %*.4f - Updated 2^8 bits second vectors.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	unsigned int k5;
	
	for (k5 = 0; k5 < 256; ++k5)
	{
		
		secondsum1 = total_sum(secondvect14,k5);
		secondsum2 = total_sum(secondvect24,k5);
		secondsum3 = total_sum(secondvect34,k5);

		if ((secondsum1 == 0) && (secondsum2 == 0) && (secondsum3 == 0))
		{
			flag = 1;
			break;
		}
	}
	
	free (secondvect13);
	free (secondvect23);
	free (secondvect33);
	
	free (secondvect14);
	free (secondvect24);
	free (secondvect34);
	
	return flag;
}

/* 
  //
  //  PARTIAL SUM ATTACK
  //
  */
int partial_sum_attack(unsigned char *vect11, unsigned char *vect21, unsigned char *vect31, unsigned char key_guess[16], unsigned char k1, unsigned char k2, unsigned char config_id)
{

	unsigned long i;
	
	// Create vectors of 2^24 bits
	unsigned char *vect12;
	unsigned char *vect22;
	unsigned char *vect32;
    
    unsigned long long int *vect12_big_pointer;
    unsigned long long int *vect22_big_pointer;
    unsigned long long int *vect32_big_pointer;
	
	printf ("WORKER %*.d: %*.4f - Allocating 2^24 bits vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	
	vect12_big_pointer = malloc(sizeof(unsigned long long int)*262144);
	vect22_big_pointer = malloc(sizeof(unsigned long long int)*262144);
	vect32_big_pointer = malloc(sizeof(unsigned long long int)*262144);
	
	for(i = 0; i < 262144; i++)
	{
		vect12_big_pointer[i] = 0x00;
		vect22_big_pointer[i] = 0x00;
		vect32_big_pointer[i] = 0x00;
	}
    
    vect12 = (unsigned char *)vect12_big_pointer;
    vect22 = (unsigned char *)vect22_big_pointer;
    vect32 = (unsigned char *)vect32_big_pointer;
	
	printf ("WORKER %*.d: %*.4f - Allocated and initilized 2^24 bits vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	
	// Create vectors of 2^16 bits
	unsigned char *vect13;
	unsigned char *vect23;
	unsigned char *vect33;
    
    unsigned long long int *vect13_big_pointer;
    unsigned long long int *vect23_big_pointer;
    unsigned long long int *vect33_big_pointer;
	
	printf ("WORKER %*.d: %*.4f - Allocating 2^16 bits vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	
	vect13_big_pointer = malloc(sizeof(unsigned long long int)*1024);
	vect23_big_pointer = malloc(sizeof(unsigned long long int)*1024);
	vect33_big_pointer = malloc(sizeof(unsigned long long int)*1024);
	
	for(i = 0; i < 1024; i++)
	{
		vect13_big_pointer[i] = 0x00;
		vect23_big_pointer[i] = 0x00;
		vect33_big_pointer[i] = 0x00;
	}
    
    vect13 = (unsigned char *)vect13_big_pointer;
    vect23 = (unsigned char *)vect23_big_pointer;
    vect33 = (unsigned char *)vect33_big_pointer;
	
	printf ("WORKER %*.d: %*.4f - Allocated and initialized 2^16 bits vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	
	// Create vectors of 2^8 bits
	unsigned char *vect14;
	unsigned char *vect24;
	unsigned char *vect34;
    
    unsigned long long int *vect14_big_pointer;
    unsigned long long int *vect24_big_pointer;
    unsigned long long int *vect34_big_pointer;
	
	printf ("WORKER %*.d: %*.4f - Allocating 2^8 bits vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	
	vect14_big_pointer = malloc(sizeof(unsigned long long int)*4);
	vect24_big_pointer = malloc(sizeof(unsigned long long int)*4);
	vect34_big_pointer = malloc(sizeof(unsigned long long int)*4);
	
	for(i = 0; i < 4; i++)
	{
		vect14_big_pointer[i] = 0x00;
		vect24_big_pointer[i] = 0x00;
		vect34_big_pointer[i] = 0x00;
	}
	
    vect14 = (unsigned char *)vect14_big_pointer;
    vect24 = (unsigned char *)vect24_big_pointer;
    vect34 = (unsigned char *)vect34_big_pointer;
    
	printf ("WORKER %*.d: %*.4f - Allocated and initialized 2^8 bits vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));

	unsigned int sum1 = 0;
	unsigned int sum2 = 0;
	unsigned int sum3 = 0;

	unsigned int k3;
	unsigned int k4;
	unsigned int k5;	
    
	printf ("WORKER %*.d: %*.4f - Updating vect12...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_24_firstrow(vect11,vect12,k1,k2);
    
	printf ("WORKER %*.d: %*.4f - Updating vect22...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_24_firstrow(vect21,vect22,k1,k2);
	
	printf ("WORKER %*.d: %*.4f - Updating vect32...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
	update_vect_2_24_firstrow(vect31,vect32,k1,k2);

	for (k3 = 0; k3 < 256; ++k3)
	{
		// printf ("WORKER %*.d: %*.4f - Updating vect13...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
		update_vect_2_16_firstrow(vect12,vect13,k3);
		
		// printf ("WORKER %*.d: %*.4f - Updating vect23...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
		update_vect_2_16_firstrow(vect22,vect23,k3);
		
		// printf ("WORKER %*.d: %*.4f - Updating vect33...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
		update_vect_2_16_firstrow(vect32,vect33,k3);
		
		// printf ("WORKER %*.d: %*.4f - Updated 2^16 bits vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));

		for (k4 = 0; k4 < 256; ++k4)
		{
			// printf ("WORKER %*.d: %*.4f - Updating vect14...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
			update_vect_2_8_firstrow(vect13,vect14,k4);
			
			// printf ("WORKER %*.d: %*.4f - Updating vect24...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
			update_vect_2_8_firstrow(vect23,vect24,k4);
			
			// printf ("WORKER %*.d: %*.4f - Updating vect34...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
			update_vect_2_8_firstrow(vect33,vect34,k4);
            
			// printf ("WORKER %*.d: %*.4f - Updated 2^8 bits vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));

			for (k5 = 0; k5 < 256; ++k5 )
			{
            
				sum1 = total_sum(vect14,k5);
				sum2 = total_sum(vect24,k5);
				sum3 = total_sum(vect34,k5);
                
				if ((sum1 == 0) && (sum2 == 0) && (sum3 == 0))
				{
                
					// printf ("WORKER %*.d: %*.4f - Discovered sum1, sum2 and sum3 equal to 0! Counterchecking...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
				
                    // Create vectors of 2^24 bits
                    unsigned char *secondvect12;
                    unsigned char *secondvect22;
                    unsigned char *secondvect32;
                    
                    unsigned long long int *secondvect12_big_pointer;
                    unsigned long long int *secondvect22_big_pointer;
                    unsigned long long int *secondvect32_big_pointer;
                    
                    printf ("WORKER %*.d: %*.4f - Allocating 2^24 bits second vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
                    
                    secondvect12_big_pointer = malloc(sizeof(unsigned long long int)*262144);
                    secondvect22_big_pointer = malloc(sizeof(unsigned long long int)*262144);
                    secondvect32_big_pointer = malloc(sizeof(unsigned long long int)*262144);
                    
                    for(i = 0; i < 262144; i++)
                    {
                        secondvect12_big_pointer[i] = 0x00;
                        secondvect22_big_pointer[i] = 0x00;
                        secondvect32_big_pointer[i] = 0x00;
                    }
				
                    secondvect12 = (unsigned char *)secondvect12_big_pointer;
                    secondvect22 = (unsigned char *)secondvect22_big_pointer;
                    secondvect32 = (unsigned char *)secondvect32_big_pointer;
                    
                    printf ("WORKER %*.d: %*.4f - Allocated and initilized 2^24 bits second vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
				
				    printf ("WORKER %*.d: %*.4f - Updated 2^24 bits vectors.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
    
                	printf ("WORKER %*.d: %*.4f - Updating secondvect12...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
                	update_vect_2_24_secondrow(vect11,secondvect12,k1,k2);
                	
                	printf ("WORKER %*.d: %*.4f - Updating secondvect22...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
                	update_vect_2_24_secondrow(vect21,secondvect22,k1,k2);
                	
                	printf ("WORKER %*.d: %*.4f - Updating secondvect32...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
                	update_vect_2_24_secondrow(vect31,secondvect32,k1,k2);
                	
                	printf ("WORKER %*.d: %*.4f - Updated 2^24 bits second vectors.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
					if (second_row_instance(secondvect12,secondvect22,secondvect32,k3,k4))
					{
					    
    			        // printf ("WORKER %*.d: %*.4f - Discovered sum1, sum2 and sum3 equal to 0! Counterchecking...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
    				
                        // Create vectors of 2^24 bits
                        unsigned char *thirdvect12;
                        unsigned char *thirdvect22;
                        unsigned char *thirdvect32;
                        
                        unsigned long long int *thirdvect12_big_pointer;
                        unsigned long long int *thirdvect22_big_pointer;
                        unsigned long long int *thirdvect32_big_pointer;
                        
                        printf ("WORKER %*.d: %*.4f - Allocating 2^24 bits third vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
                        
                        thirdvect12_big_pointer = malloc(sizeof(unsigned long long int)*262144);
                        thirdvect22_big_pointer = malloc(sizeof(unsigned long long int)*262144);
                        thirdvect32_big_pointer = malloc(sizeof(unsigned long long int)*262144);
                        
                        for(i = 0; i < 262144; i++)
                        {
                            thirdvect12_big_pointer[i] = 0x00;
                            thirdvect22_big_pointer[i] = 0x00;
                            thirdvect32_big_pointer[i] = 0x00;
                        }
    				
                        thirdvect12 = (unsigned char *)thirdvect12_big_pointer;
                        thirdvect22 = (unsigned char *)thirdvect22_big_pointer;
                        thirdvect32 = (unsigned char *)thirdvect32_big_pointer;
                        
                        printf ("WORKER %*.d: %*.4f - Allocated and initilized 2^24 bits third vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
    				
    				    printf ("WORKER %*.d: %*.4f - Updated 2^24 bits vectors.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
        
                    	printf ("WORKER %*.d: %*.4f - Updating thirdvect12...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
                    	update_vect_2_24_thirdrow(vect11,thirdvect12,k1,k2);
                    	
                    	printf ("WORKER %*.d: %*.4f - Updating thirdvect22...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
                    	update_vect_2_24_thirdrow(vect21,thirdvect22,k1,k2);
                    	
                    	printf ("WORKER %*.d: %*.4f - Updating thirdvect32...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
                    	update_vect_2_24_thirdrow(vect31,thirdvect32,k1,k2);
                    	
                    	printf ("WORKER %*.d: %*.4f - Updated 2^24 bits third vectors.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
    					
    		            if (third_row_instance(thirdvect12,thirdvect22,thirdvect32,k3,k4))
					    {
    				        // printf ("WORKER %*.d: %*.4f - Discovered sum1, sum2 and sum3 equal to 0! Counterchecking...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
        				
                            // Create vectors of 2^24 bits
                            unsigned char *fourthvect12;
                            unsigned char *fourthvect22;
                            unsigned char *fourthvect32;
                            
                            unsigned long long int *fourthvect12_big_pointer;
                            unsigned long long int *fourthvect22_big_pointer;
                            unsigned long long int *fourthvect32_big_pointer;
                            
                            printf ("WORKER %*.d: %*.4f - Allocating 2^24 bits third vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
                            
                            fourthvect12_big_pointer = malloc(sizeof(unsigned long long int)*262144);
                            fourthvect22_big_pointer = malloc(sizeof(unsigned long long int)*262144);
                            fourthvect32_big_pointer = malloc(sizeof(unsigned long long int)*262144);
                            
                            for(i = 0; i < 262144; i++)
                            {
                                fourthvect12_big_pointer[i] = 0x00;
                                fourthvect22_big_pointer[i] = 0x00;
                                fourthvect32_big_pointer[i] = 0x00;
                            }
        				
                            fourthvect12 = (unsigned char *)fourthvect12_big_pointer;
                            fourthvect22 = (unsigned char *)fourthvect22_big_pointer;
                            fourthvect32 = (unsigned char *)fourthvect32_big_pointer;
                            
                            printf ("WORKER %*.d: %*.4f - Allocated and initilized 2^24 bits fourth vectors...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
        				
        				    printf ("WORKER %*.d: %*.4f - Updated 2^24 bits vectors.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
            
                        	printf ("WORKER %*.d: %*.4f - Updating fourthvect12...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
                        	update_vect_2_24_fourthrow(vect11,fourthvect12,k1,k2);
                        	
                        	printf ("WORKER %*.d: %*.4f - Updating fourthvect22...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
                        	update_vect_2_24_fourthrow(vect21,fourthvect22,k1,k2);
                        	
                        	printf ("WORKER %*.d: %*.4f - Updating fourthvect32...\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
                        	update_vect_2_24_fourthrow(vect31,fourthvect32,k1,k2);
                        	
                        	printf ("WORKER %*.d: %*.4f - Updated 2^24 bits fourth vectors.\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
                        	
                            if (fourth_row_instance(fourthvect12,fourthvect22,fourthvect32,k3,k4))
				            {
				                // printf ("WORKER %*.d: %*.4f - KEY GUESSED!\n", 4, worker_rank, 10, get_elapsed_time(worker_start_t));
                                fill(k1, k2, k3, k4, config_id, key_guess);
                                
                                free (secondvect12);
                                free (secondvect22);
                                free (secondvect32);
                                
                                free (thirdvect12);
                                free (thirdvect22);
                                free (thirdvect32);
                                
                                free (fourthvect12);
                                free (fourthvect22);
                                free (fourthvect32);
                                
                                free (vect12);
                                free (vect22);
                                free (vect32);
                                
                                free (vect13);
                                free (vect23);
                                free (vect33);
                                
                                free (vect14);
                                free (vect24);
                                free (vect34);
                                
                                return 1;
				            }
				            
                            free (fourthvect12);
                            free (fourthvect22);
                            free (fourthvect32);
                        	
					    }
    					
						free (thirdvect12);
                        free (thirdvect22);
                        free (thirdvect32);
						
					}
					
                    free (secondvect12);
                    free (secondvect22);
                    free (secondvect32);
				}
			}
		}
	}

	free (vect12);
	free (vect22);
	free (vect32);
	
	free (vect13);
	free (vect23);
	free (vect33);
	
	free (vect14);
	free (vect24);
	free (vect34);
	
	return 0;
}
