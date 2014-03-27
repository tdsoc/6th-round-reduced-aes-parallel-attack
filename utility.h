#ifndef UTILITY_H
#define UTILITY_H

/*
##### FUNCTIONS #####
*/
void set_bit (unsigned char *, unsigned long);
void clear_bit (unsigned char *, unsigned long);
void toggle_bit (unsigned char *, unsigned long);

double get_elapsed_time(clock_t);
#endif