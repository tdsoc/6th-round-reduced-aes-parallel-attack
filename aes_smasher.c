#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <mpi.h>

#include "utility.h"
#include "cipher.h"
#include "attack_functions.h"

void print_array(unsigned char print_me [], int array_size)
{
	int i;

	for (i = 0; i < array_size; i++)
	{
		printf ("0x%02x ", print_me[i]);
	}
}

unsigned char * prepare_vector(unsigned long vector_size){
	unsigned char * vector;
	unsigned int i;
	
	vector = malloc (sizeof(char)*vector_size);

	for (i = 0; i < vector_size; i++)
	{
		vector[i] = 0x00;
	}
	
	return vector;
}

int write_vector_to_file(unsigned char * vector, unsigned long vector_size, char* vector_file_path)
{
	unsigned int i;

	FILE *vector_file;

	vector_file = fopen(vector_file_path,"w");

	if (vector_file == NULL){
		printf("MASTER - ERROR: cannot open the encrypted vector files!\n");
		return 1;
	}

	for (i = 0; i < vector_size; i++){
		putc (vector[i], vector_file);
	}

	fclose(vector_file);
	
	return 0;
}

void initialize_plaintexts(unsigned char plaintext[3][16])
{
	int j;

	for ( j = 0; j < 16; ++j )
	{
		plaintext[0][j] = 0;
		plaintext[1][j] = 1;
		plaintext[2][j] = 5;
	}
}

int main(int argc, char *argv[])
{
	int flag, number_of_processes, rank;
	unsigned int i, w;
	
	unsigned long long two_to_32_vector_size;
	unsigned long char_array_size;
	
	char * share_path = "/aes-smasher/vectors";
	char * vect11_file_name = "vect11";
	char * vect21_file_name = "vect21";
	char * vect31_file_name = "vect31";
	char * destination_folder = "/aes-smasher/vectors";
	
	char * key_guessed_file_name_prefix = "/aes-smasher/guessed-keys/guessed-config-id-";
	char * key_guessed_file_name = "/aes-smasher/guessed-keys/guessed-whole-key";

	unsigned char * key_part_path;
	
	unsigned char * vect11_file_path;
	unsigned char * vect21_file_path;
	unsigned char * vect31_file_path;

	unsigned char * key_guess;
	unsigned char * whole_key_guessed;
	unsigned char config_id;
	
	clock_t start_t;
	
	MPI_Status stat;
	
	MPI_Init(&argc, &argv);
	
	MPI_Comm_size(MPI_COMM_WORLD, &number_of_processes);
	MPI_Comm_rank(MPI_COMM_WORLD, &rank);
	
	two_to_32_vector_size = 4294967296u;
	char_array_size = two_to_32_vector_size/8; // 2^32 bits = 2^32 / 2^3 bytes = 2^29 bytes = 536870912
	flag = 0;
	
	vect11_file_path = prepare_vector(256);
	vect21_file_path = prepare_vector(256);
	vect31_file_path = prepare_vector(256);
	
	key_part_path = prepare_vector(256);
	
	key_guess = prepare_vector(16);
	
	time_t rawtime;
	struct tm * timeinfo;
	
	if (rank == 0)
	{	
		unsigned char n_rounds;
		unsigned char plaintext[3][16];

		unsigned char * ciphertext;
		ciphertext = prepare_vector(16);
		
		unsigned char * vect11;
		unsigned char * vect21;
		unsigned char * vect31;
		
		// Setting AES to 128 bit
		set_cipher_variables(128);
        		
		printf("\n\n\t\tPARTIAL SUM ATTACK on AES reduced to 6 rounds\n\n\n");
		
		start_t = clock();
		
		time ( &rawtime );
		timeinfo = localtime ( &rawtime );
		printf("MASTER     : %*.4f - Current local time and date: %s", 10, get_elapsed_time(start_t), asctime (timeinfo));
        
		// Set the seed for the PRNG
		srand(time(NULL));
		printf("MASTER     : %*.4f - Initialized the PRNG\n", 10, get_elapsed_time(start_t));
		
		// Fix the number of rounds
		n_rounds = 6;
		
		// Choose the master key
		unsigned char master_key[16] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
		set_key(master_key);
		printf ("MASTER     : %*.4f - Master key set\n", 10, get_elapsed_time(start_t));
		printf ("MASTER     : %*.4f - Master key:\t", 10, get_elapsed_time(start_t));
		print_array(master_key,16);
		printf("\n");

		// Initialize the plaintexts
		initialize_plaintexts(plaintext);
		
		printf ("MASTER     : %*.4f - Plaintexts initialized\n", 10, get_elapsed_time(start_t));
		
		
		printf ("MASTER     : %*.4f - Ciphertext initialized\n", 10, get_elapsed_time(start_t));
		
		// Encrypt the 2^32 vectors
        
		printf ("MASTER     : %*.4f - Starting encryption process...\n", 10, get_elapsed_time(start_t));
		
		for (config_id = 1; config_id <= 4; config_id++)
		{
		
			sprintf(vect11_file_path, "%s/%s-id-%d", share_path, vect11_file_name, config_id);
			sprintf(vect21_file_path, "%s/%s-id-%d", share_path, vect21_file_name, config_id);
			sprintf(vect31_file_path, "%s/%s-id-%d", share_path, vect31_file_name, config_id);
			
			if (access(vect11_file_path, F_OK) == -1)
			{
				vect11 = prepare_vector (char_array_size);
				printf ("MASTER     : %*.4f - Starting 1st delta set creation for config_id=%d...\n", 10, get_elapsed_time(start_t), config_id);
				encryption(plaintext[0],ciphertext,n_rounds,vect11,config_id);
				printf ("MASTER     : %*.4f - ...1st delta set done!\n", 10, get_elapsed_time(start_t));
				printf ("MASTER     : %*.4f - Writing encrypted vector %s to disk...\n", 10, get_elapsed_time(start_t), vect11_file_path);
				if (write_vector_to_file(vect11, char_array_size, vect11_file_path))
				{
					MPI_Finalize();
					return 1;
				}
				
				free(vect11);
			}
			
			if (access(vect21_file_path, F_OK) == -1)
			{
				vect21 = prepare_vector (char_array_size);
				printf ("MASTER     : %*.4f - Starting 2nd delta set creation for config_id=%d...\n", 10, get_elapsed_time(start_t), config_id);
				encryption(plaintext[1],ciphertext,n_rounds,vect21,config_id);
				printf ("MASTER     : %*.4f - ...2nd delta set done!\n", 10, get_elapsed_time(start_t));
				printf ("MASTER     : %*.4f - Writing encrypted vector %s to disk...\n", 10, get_elapsed_time(start_t), vect21_file_path);
				if (write_vector_to_file(vect21, char_array_size, vect21_file_path))
				{
					MPI_Finalize();
					return 1;
				}
				
				free(vect21);
			}
			
			if (access(vect31_file_path, F_OK) == -1)
			{
				vect31 = prepare_vector (char_array_size);
				printf ("MASTER     : %*.4f - Starting 3rd delta set creation for config_id=%d...\n", 10, get_elapsed_time(start_t), config_id);
				encryption(plaintext[2],ciphertext,n_rounds,vect31,config_id);
				printf ("MASTER     : %*.4f - ...3rd delta set done!\n", 10, get_elapsed_time(start_t));
				printf ("MASTER     : %*.4f - Writing encrypted vector %s to disk...\n", 10, get_elapsed_time(start_t), vect31_file_path);
				if (write_vector_to_file(vect31, char_array_size, vect31_file_path))
				{
					MPI_Finalize();
					return 1;
				}
				
				free(vect31);
			}
		}

		printf ("MASTER     : %*.4f - Encryption phase completed\n", 10, get_elapsed_time(start_t));
		
		printf ("MASTER     : %*.4f - Cleaning up previous guessed keys...\n", 10, get_elapsed_time(start_t));
		
		sprintf (key_part_path, "%s%d", key_guessed_file_name_prefix, 1);
		remove (key_part_path);
		sprintf (key_part_path, "%s%d", key_guessed_file_name_prefix, 2);
		remove (key_part_path);
		sprintf (key_part_path, "%s%d", key_guessed_file_name_prefix, 3);
		remove (key_part_path);
		sprintf (key_part_path, "%s%d", key_guessed_file_name_prefix, 4);
		remove (key_part_path);
		
		remove (key_guessed_file_name);
		
		time ( &rawtime );
		timeinfo = localtime ( &rawtime );
		printf ("MASTER     : %*.4f - Current local time and date after finishing the encryption: %s", 10, get_elapsed_time(start_t), asctime (timeinfo));
		
		start_t = clock();
		printf ("MASTER     : %*.4f - Clock reset\n", 10, get_elapsed_time(start_t));
		
		// Subdivide jobs dynamically
		
		printf ("MASTER     : %*.4f - Subdividing jobs...\n", 10, get_elapsed_time(start_t));
		int number_of_jobs;
		int number_of_workers;
		int number_of_jobs_per_worker;
		
		number_of_jobs = 256;
		number_of_workers = number_of_processes -1;

		number_of_jobs_per_worker = number_of_jobs / number_of_workers;

		if (number_of_jobs % number_of_workers){
			number_of_jobs_per_worker++;
		}

		unsigned char jobs_per_workers [number_of_workers][number_of_jobs_per_worker];
		
		int number_of_assigned_jobs;
		
		number_of_assigned_jobs = 1;
		
		for (w = 0; w < number_of_jobs_per_worker; w++){
			for ( i = 0; i < number_of_workers ; i++){
				if (number_of_assigned_jobs <= number_of_jobs){
					jobs_per_workers [i][w] = number_of_assigned_jobs;
					number_of_assigned_jobs++;
				}else{
					jobs_per_workers [i][w] = -1;
				}
			}
		}
	
		printf ("MASTER     : %*.4f - Number of workers: %d\n", 10, get_elapsed_time(start_t), number_of_workers);
		printf ("MASTER     : %*.4f - Number of jobs: %d\n", 10, get_elapsed_time(start_t), number_of_jobs);
		printf ("MASTER     : %*.4f - Number of jobs per worker: %d\n", 10, get_elapsed_time(start_t), number_of_jobs_per_worker);
		
		printf ("MASTER     : %*.4f - Sending jobs to workers...\n", 10, get_elapsed_time(start_t));

		for (i = 0; i < number_of_workers; i++){
			MPI_Send(&number_of_jobs_per_worker, 1, MPI_INT, i+1, 0, MPI_COMM_WORLD);
			printf ("MASTER     : %*.4f - Number of jobs sent to worker %d\n", 10, get_elapsed_time(start_t), i);
			
			MPI_Send(jobs_per_workers[i], number_of_jobs_per_worker, MPI_CHAR, i+1, 0, MPI_COMM_WORLD);
			printf ("MASTER     : %*.4f - List of jobs sent to worker %d\n", 10, get_elapsed_time(start_t), i);
		}

		int worker_rank;
		int flag[4];
		
		flag[0] = 0x0;
		flag[1] = 0x0;
		flag[2] = 0x0;
		flag[3] = 0x0;
		
		whole_key_guessed = prepare_vector(16);
		
		time ( &rawtime );
		timeinfo = localtime ( &rawtime );
		printf ("MASTER     : %*.4f - Starting attack time and date: %s", 10, get_elapsed_time(start_t), asctime (timeinfo));
		
		printf ("MASTER     : %*.4f - Waiting for reply from workers...", 10, get_elapsed_time(start_t));
		
		for (config_id = 1; config_id <= 4; config_id++)
		{
			
			MPI_Recv(&worker_rank, 1, MPI_INT, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &stat);
			printf ("MASTER     : %*.4f - Received reply from  worker %d\n", 10, get_elapsed_time(start_t), worker_rank);
			
			MPI_Recv(&flag[config_id-1], 1, MPI_INT, worker_rank, MPI_ANY_TAG, MPI_COMM_WORLD, &stat);
			
			if (flag[config_id-1]) {
				printf ("MASTER     : %*.4f - Worker %d found the right key for config_id=%d\n", 10, get_elapsed_time(start_t), worker_rank, config_id);
				
				MPI_Recv(key_guess, 16, MPI_INT, MPI_ANY_SOURCE, MPI_ANY_TAG, MPI_COMM_WORLD, &stat);

				for (w = 0; w < 16; w++)
				{
					whole_key_guessed[w] |= key_guess[w];
				}
								
				printf ("MASTER     : %*.4f - Received right key from worker %d\n", 10, get_elapsed_time(start_t), worker_rank);
			} else {
				printf ("MASTER     : %*.4f - Worker %d DID NOT found the right key\n", 10, get_elapsed_time(start_t), worker_rank);
			}
			
		}
		
		if (flag[0] && flag[1] && flag[2] && flag[3])
		{
			
			// Print the attack result
			printf("MASTER     : %*.4f - 6th Round key guessed: ", 10, get_elapsed_time(start_t));
			print_array(whole_key_guessed,16);
			write_vector_to_file(whole_key_guessed, 16, key_guessed_file_name);
			printf("\n");
			
			printf("MASTER     : %*.4f - The attack has been successful!\n", 10, get_elapsed_time(start_t));
			
		} else{
			printf("MASTER     : %*.4f - The attack was not successful!\n", 10, get_elapsed_time(start_t));
		}
		
		time ( &rawtime );
		timeinfo = localtime ( &rawtime );
		printf("MASTER     : %*.4f - Finished attack time and date: %s", 10, get_elapsed_time(start_t), asctime (timeinfo));
		
		/*
		 * These have been removed because they broke everything
		 * (I don't know why)
		 * 
		 * free(whole_key_guessed);
		 * free(ciphertext);
		 * free(key_part_path);
		 * free(key_guess);
		 * free(vect11_file_path);
		 * free(vect21_file_path);
		 * free(vect31_file_path);
		 */

		printf ("MASTER     : %*.4f - Cleaning up...\n", 10, get_elapsed_time(start_t));
		
		printf ("MASTER     : %*.4f - Done!\n", 10, get_elapsed_time(start_t));
			
		MPI_Finalize();

		return 0;
	} else {
				
		unsigned int k2;
		unsigned int number_of_jobs;
		MPI_Recv(&number_of_jobs, 1, MPI_INT, 0, 0, MPI_COMM_WORLD, &stat);
		start_t = clock();
		worker_start_t = start_t;

		printf ("WORKER %*.d: %*.4f - Number of jobs: %d\n", 4, rank, 10, get_elapsed_time(start_t), number_of_jobs);
		
		unsigned char jobs[number_of_jobs];
		MPI_Recv(jobs, number_of_jobs, MPI_CHAR, 0, 0, MPI_COMM_WORLD, &stat);
		printf ("WORKER %*.d: %*.4f - Received the list of jobs\n", 4, rank, 10, get_elapsed_time(start_t));

		worker_rank = rank;
		
		printf ("WORKER %*.d: %*.4f - Starting the attack procedure...\n", 4, rank, 10, get_elapsed_time(start_t));
		
		for (config_id = 1; config_id <= 4; config_id++)
		{
			
			sprintf(vect11_file_path, "%s/%s-id-%d", share_path, vect11_file_name, config_id);
			sprintf(vect21_file_path, "%s/%s-id-%d", share_path, vect21_file_name, config_id);
			sprintf(vect31_file_path, "%s/%s-id-%d", share_path, vect31_file_name, config_id);

			unsigned char * vect11;
			unsigned char * vect21;
			unsigned char * vect31;
			
			vect11 = get_encrypted_array(vect11_file_path);
			vect21 = get_encrypted_array(vect21_file_path);
			vect31 = get_encrypted_array(vect31_file_path);
			
			flag = 0;
			
			for (i = 0; i < number_of_jobs; i++){
				if (jobs[i] != -1){
					//printf ("WORKER %*.d: %*.4f - Initializing guessed key storage...\n", 4, rank, 10, get_elapsed_time(start_t));
					
					char guessed_key_file_name[256];
					sprintf(guessed_key_file_name, "%s%d", key_guessed_file_name_prefix, config_id);
					
					for ( w = 0; w < 16; w++)
					{
						key_guess[w] = 0;
					}
			
					//printf ("WORKER %*.d: %*.4f - Starting the attack with k1=%d and i=%d ...\n", 4, rank, 10, get_elapsed_time(start_t), jobs[i], i);
			
					for (k2 = 0; k2 < 256; k2++){
						// Run the attack!
						printf ("WORKER %*.d: %*.4f - Starting the attack with k1=%d and K2=%d ...\n", 4, rank, 10, get_elapsed_time(start_t), jobs[i], k2);
						flag = partial_sum_attack(vect11, vect21, vect31, key_guess, jobs[i], k2, config_id);
					
						printf ("WORKER %*.d: %*.4f - Completed attack with k1=%d and K2=%d\n", 4, rank, 10, get_elapsed_time(start_t), jobs[i], k2);
						
						if (flag){
							
							write_vector_to_file(key_guess, 16, guessed_key_file_name);
							
							printf ("WORKER %*.d: %*.4f - Sending my rank to master...\n", 4, rank, 10, get_elapsed_time(start_t));
							MPI_Send(&rank, 1, MPI_INT, 0, 0, MPI_COMM_WORLD);

							printf ("WORKER %*.d: %*.4f - Sending the attack result to master...\n", 4, rank, 10, get_elapsed_time(start_t));
							MPI_Send(&flag, 1, MPI_INT, 0, 0, MPI_COMM_WORLD);

							printf ("WORKER %*.d: %*.4f - The attack was successful! Sending guessed key to master...\n", 4, rank, 10, get_elapsed_time(start_t));
							MPI_Send(key_guess, 16, MPI_INT, 0, 0, MPI_COMM_WORLD);

							break;
						}
						
						if (access(guessed_key_file_name, F_OK) != -1){
							break;
						}
					
					}
					
					if (access(guessed_key_file_name, F_OK) != -1){
						printf ("WORKER %*.d: %*.4f - Key for config_id = %d already guessed. Terminating...\n", 4, rank, 10, get_elapsed_time(start_t), config_id);
						break;
					}
				}
			}
			
			free(vect11);
			free(vect21);
			free(vect31);
		}
        
		free(vect11_file_path);
		free(vect21_file_path);
		free(vect31_file_path);
		
		free(key_part_path);
		free(key_guess);
        
		printf ("WORKER %*.d: %*.4f - Cleaning up...\n", 4, rank, 10, get_elapsed_time(start_t));
		
		printf ("WORKER %*.d: %*.4f - Done!\n", 4, rank, 10, get_elapsed_time(start_t));
		
	}
	
	MPI_Finalize();
	
	return 0;
}
