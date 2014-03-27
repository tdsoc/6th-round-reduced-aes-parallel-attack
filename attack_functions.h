#ifndef ATTACK_FUNCTIONS_H
#define ATTACK_FUNCTIONS_H
/*
##### CONSTANTS #####
*/
unsigned int worker_rank;
clock_t worker_start_t;
/*
##### FUNCTIONS #####
*/

void encode_N_std_rounds(const unsigned char[], unsigned char[], unsigned char);
void encode_N_rounds(const unsigned char[], unsigned char[], unsigned char);

unsigned int get_position_4bytes(unsigned char[]);

void extract(unsigned char[], unsigned char, unsigned char[]);
void encryption(unsigned char[], unsigned char[], unsigned char, unsigned char[], unsigned char);

unsigned char x_2_firstrow(unsigned char, unsigned char, unsigned char, unsigned char);
unsigned char x_3_firstrow(unsigned char, unsigned char, unsigned char);
unsigned char x_4_firstrow(unsigned char, unsigned char, unsigned char);

unsigned char x_2_secondrow(unsigned char, unsigned char, unsigned char, unsigned char);
unsigned char x_3_secondrow(unsigned char, unsigned char, unsigned char);
unsigned char x_4_secondrow(unsigned char, unsigned char, unsigned char);

unsigned char x_2_thirdrow(unsigned char, unsigned char, unsigned char, unsigned char);
unsigned char x_3_thirdrow(unsigned char, unsigned char, unsigned char);
unsigned char x_4_thirdrow(unsigned char, unsigned char, unsigned char);

unsigned char x_2_fourthrow(unsigned char, unsigned char, unsigned char, unsigned char);
unsigned char x_3_fourthrow(unsigned char, unsigned char, unsigned char);
unsigned char x_4_fourthrow(unsigned char, unsigned char, unsigned char);

unsigned char total_sum(unsigned char[], unsigned char);

unsigned char * get_encrypted_array(char *);

void update_vect_2_24_firstrow(unsigned char *, unsigned char[], unsigned char, unsigned char);
void update_vect_2_16_firstrow(unsigned char[], unsigned char[], unsigned char);
void update_vect_2_8_firstrow(unsigned char[], unsigned char[], unsigned char);

void update_vect_2_24_secondrow(unsigned char *, unsigned char[], unsigned char, unsigned char);
void update_vect_2_16_secondrow(unsigned char[], unsigned char[], unsigned char);
void update_vect_2_8_secondrow(unsigned char[], unsigned char[], unsigned char);

void update_vect_2_24_thirdrow(unsigned char *, unsigned char[], unsigned char, unsigned char);
void update_vect_2_16_thirdrow(unsigned char[], unsigned char[], unsigned char);
void update_vect_2_8_thirdrow(unsigned char[], unsigned char[], unsigned char);

void update_vect_2_24_fourthrow(unsigned char *, unsigned char[], unsigned char, unsigned char);
void update_vect_2_16_fourthrow(unsigned char[], unsigned char[], unsigned char);
void update_vect_2_8_fourthrow(unsigned char[], unsigned char[], unsigned char);

int fourth_row_instance(unsigned char *, unsigned char *, unsigned char *, unsigned char, unsigned char );
int third_row_instance(unsigned char *, unsigned char *, unsigned char *, unsigned char, unsigned char );
int second_row_instance(unsigned char *, unsigned char *, unsigned char *, unsigned char, unsigned char);
int partial_sum_attack(unsigned char *, unsigned char *, unsigned char *, unsigned char [], unsigned char, unsigned char, unsigned char);

#endif
