/*
 * Technical University of Kosice
 * Department of Electronics and Multimedia Telecommunications
 *
 * Masters Thesis
 * Generating Prime Numbers for Embedded Cryptographic Applications
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
	
	char bit_size_str[16];
	char out_file_path[256];
	FILEOPS_loadParamFromFile(IN_FILE_PATH, "bitSize", bit_size_str);
	FILEOPS_loadParamFromFile(IN_FILE_PATH, "outFilePath", out_file_path);
	int numSize = atoi(bit_size_str);
	
	//TODO check selected method for measuring time for longer periods
	clock_t start = clock();
	
	BIGNUM* number = BNEASY_generateRandomBN(numSize);
	printf("Initial %dbit (HEX) number generated:\nnum = " , numSize);
	BNUTIL_cPrintln(number);
	
	bool prime = FALSE;
	while(!prime) {
		prime = BNEASY_isPrime(number);
		if(prime) {
			printf("\nThe generated prime number (HEX):\n");
			BNUTIL_cPrintln(number);
		} else {
			printf("...the number is not a prime, adding 2 and "
				"checking again...\n");
			bool sizeSafe = BNEASY_add(number, 2, TRUE);
			if(!sizeSafe) {
				//If addition caused the number to exceed it's previous size,
				//generate a new number
				number = BNEASY_generateRandomBN(numSize);
			}
			printf("next number = ");
			BNUTIL_cPrintln(number);
		}
	}
	
	clock_t end = clock();
	float seconds = (float)(end - start) / CLOCKS_PER_SEC;
	printf("Execution time: %.3f seconds\n", seconds);
	
	FILE* f = NULL;
	f = fopen(out_file_path, "a");
	char* timestamp = malloc(1024);
	BNUTIL_setTimestampNow(timestamp);
	fprintf(f, "%s --> Random number of size %d found in %f seconds \n", timestamp, numSize, seconds);
	free(timestamp);
	fclose(f);
	
	printf("Program terminated with success...");

	return EXIT_SUCCESS;
}
