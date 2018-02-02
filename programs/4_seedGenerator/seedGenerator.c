/*
 * Technical University of Kosice
 * Department of Electronics and Multimedia Telecommunications
 *
 * Masters Thesis
 * Prime Number Generation for Embedded Cryptographic Applications
 * 
 * Student: Bc. Michaela Risko
 * Supervisor: doc. Ing. Milos Drutarovsky, PhD.
 *
 * REV 2.0 @ 30.01.2018
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>

#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/x509.h"
#include "openssl/rand.h"

#include "bnlib/glob.c"
#include "bnlib/bnutil.c"
#include "bnlib/bneasy.c"
#include "bnlib/fileops.c"

//File path variables
const char* IN_FILE_PATH = "files/in_file.txt";

int main() {
	printf("Program started...\n");
	
	char out_file_path[128];
	char seed_str[128];
	char byte_size_str[16];
	char iterations_str[16];
	FILEOPS_loadParamFromFile(IN_FILE_PATH, "outFilePath", out_file_path);
	FILEOPS_loadParamFromFile(IN_FILE_PATH, "seed", seed_str);
	FILEOPS_loadParamFromFile(IN_FILE_PATH, "byteSize", byte_size_str);
	FILEOPS_loadParamFromFile(IN_FILE_PATH, "iterations", iterations_str);
	printf("...all params loaded...\n");
	int seed = atoi(seed_str);
	int byteSize = atoi(byte_size_str);
	int iter = atoi(iterations_str);
	BNEASY_seedRandomBN(seed);
	BIGNUM* num = NULL;
	FILE* f = NULL;
	int i;
	for(i = 0; i < iter; i++) {
		printf("...generating random number %d...\n", i);
		num = BNEASY_nextRandomBN(byteSize, TRUE, 0);
		printf("...writing random number %d to file...\n", i);
		f = fopen(out_file_path, "a");
		fprintf(f, "RANDOM_NUM_%d \n", i);
		fclose(f);
		
		FILEOPS_writeBNToFile(out_file_path, num, TRUE);
		
		f = fopen(out_file_path, "a");
		fprintf(f, "\n\n");
		fclose(f);
	}
	
	printf("Program terminated with success...");
	return EXIT_SUCCESS;
}
