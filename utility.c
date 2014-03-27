#include <stdio.h>
#include <time.h>
#include "utility.h"

void set_bit (unsigned char *bit_field, unsigned long index)
{
	bit_field[index/8] |= (1 << (index%8));
}

void clear_bit (unsigned char *bit_field, unsigned long index)
{
	bit_field[index/8] &= ~(1 << (index%8));
}

void toggle_bit (unsigned char *bit_field, unsigned long index)
{
	bit_field[index/8] ^= (1 << (7-index%8));
}

double get_elapsed_time(clock_t start_t)
{
	clock_t end_t, total_t;

	end_t = clock();
	total_t = (double)(end_t - start_t) / CLOCKS_PER_SEC;
	return total_t;
}
