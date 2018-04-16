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
 * REV 1.0 @ 08.04.2018
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
const char* OUT_FILE_PATH = "files/out_file.txt";
const char* IN_FILE_PATH = "files/in_file.txt";
const char* BN_FILE_PATH = "files/bn_file.txt";

const int CORE_LOOP = 50;

//global vars
long executionTimeRaw = 0;

/*
 * This function calculates the number of increments of 2 that are needed in
 * order to find a specific number of prime numbers starting from a specific
 * number. The operation is not size-safe.
 * The counter of increments is declared as 'unsigned long' so it is possible
 * for this counter to overflow. Appropriate exception handling is in place.
 * @param fromNum
 *			the number from which the next prime number is to be found
 * @param bnGenCount
 *			the number of prime numbers to be found from 'fromNum'
 *
 * @return the number of increments (by 2) needed in order to find all
 * 			of the requested prime numbers
 */
unsigned long measureGrouping(BIGNUM* fromNum, int bnGenCount) {
	if(bnGenCount < 1) {
		BNUTIL_successCheck(FALSE, "measureGrouping", "function parameter "
			"'count' must be > 0");
	}
	//Create a duplicat number
	BIGNUM* number = BN_dup(fromNum);
	unsigned long  numIncrements = 0;
	int numPrimesFound = 0;
	
	if(BN_is_bit_set(number, 0) == FALSE) {
		//If numFrom is even, add 1
		BNEASY_add(number, 1, FALSE);
	}
	
	clock_t timerStart;
	clock_t timerEnd;
	executionTimeRaw = 0;
	
	////////////////////////////////////////////////////////////////////////////////////////////////////////
//	while(numPrimesFound < count) {
//		timerStart = clock();
//		if(BNEASY_isPrime(number)) {
//			numPrimesFound++;
//			printf("\r...found prime %d/%d...", numPrimesFound, count);
//		}
//		BNEASY_add(number, 2, FALSE);
//		numIncrements++;
//		if(numIncrements == ULONG_MAX) {
//			BNUTIL_successCheck(FALSE, "measureGrouping", "unsigned long "
//				"numIncrements overflow");
//		}
//		timerEnd = clock();
//		executionTimeRaw += timerEnd - timerStart;
//	} 

	BIGNUM* temp = BN_new();
	BIGNUM* wTemp = BN_new();
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM w[CORE_LOOP][2];
	bool init = TRUE;
	int count = 0;
	
	while(count != bnGenCount) {
		timerStart = clock();
		
		int i;
		for(i = 0; i < CORE_LOOP; i++) {
			if(init == TRUE) {
				//create initial row
				temp = BN_dup(fromNum);
				BNEASY_add(temp, -2, FALSE);
				w[i][0] = *temp;
//				printf("w0[%d] = ", i - 1);
//				BNUTIL_cPrintln(&w0[i - 1]);
				init = FALSE;
			} else {
				//copy second row to first
				w[i][0] = w[i][1];
			}
			
			BIGNUM* wTemp = BN_dup(&w[i][0]);
			BNEASY_add(wTemp, 2, FALSE);
			BN_mod(temp, wTemp, BNUTIL_getSmallPrime(i), ctx);
			w[i][1] = *temp;
		}
		
		//is 0 in the column?
		bool hasZero = FALSE;
		for(i = 0; i < CORE_LOOP; i++) {
			if(BN_is_zero(&w[i][1])) {
				hasZero = TRUE;
			}
		}
		
		//if 0 is not in column, do R-M test
		if(hasZero == FALSE) {
			//R-M test
			if(BNEASY_isPrime(number) == TRUE) {
				count++;
			}
		}
		
		
		//n = n + 2
		BNEASY_add(number, 2, FALSE);
		
		timerEnd = clock();
		executionTimeRaw += timerEnd - timerStart;
	}


	printf("\n");
	BN_free(number);
	BN_free(temp);
	BN_free(wTemp);
	BN_CTX_free(ctx);
	
	//remove extra increment after BNEASY_isPrime(number) check
	return numIncrements - 1;
}

/*
 * This procedure writes the program result to a file @ filePath
 *
 * @param filePath
 *			the pointer to a string containing the file path to the file where
 *			text is to be written
 * @param duration
 *			the program execution time to be written to a file
 * @param grouping
 *			the number of increments of 2 needed to find the requested number
 *			of prime numbers
 * @param primeNums
 *			the number of prime numbers that were to be found
 * @param numBits
 *			the number of bits in the generated number
 *
 */
void writeResultToFile(const char* filePath, float duration,
								int grouping, int primeNums, int numBits) {
	printf("writing result to file...\n");
	char timestamp[20];
	BNUTIL_setTimestampNow(timestamp);
	FILEOPS_appendToFile(filePath, timestamp);
	
	char dur[1024];
	char text[] = " Found %d prime numbers (starting at %d bit) in %.3f "
						"seconds with a grouping factor of %lu\n";
	int charsWritten = snprintf(dur, 1024, text, primeNums, numBits,
	duration, grouping);
	if(charsWritten < 0) {
		BNUTIL_successCheck(FALSE, "writeResultToFile", "Error "
								"executing snprintf");
	}
	FILEOPS_appendToFile(filePath, dur);
}

int main() {
	printf("Program started...\n");
		
	char bnGenCount_str[16];
	char bn_str[1024];
	
	printf("...reading params from input file...\n");
	FILEOPS_loadParamFromFile(IN_FILE_PATH, "bnGenCount", bnGenCount_str);
	FILEOPS_loadParamFromFile(IN_FILE_PATH, "bn", bn_str);
	
	int bnGenCount = atoi(bnGenCount_str);
	BIGNUM* bn = NULL;
	BN_hex2bn(&bn, bn_str);
	printf("...all params from input file read successfully...\n");
	
	printf("BIGNUM loaded from file: ");
	BNUTIL_cPrintln(bn);
	printf("Loaded bnGenCount = %d from file...\n", bnGenCount);
	printf("Executing experiment 'measureGrouping'...\n");
//	clock_t start = clock();
	unsigned long grouping = measureGrouping(bn, bnGenCount);
	printf("Experiment finished! Grouping found: %lu\n", grouping);
//	clock_t end = clock();
	float duration = (float)(executionTimeRaw) / CLOCKS_PER_SEC;
	int numBits = BN_num_bytes(bn) * 8;
	writeResultToFile(OUT_FILE_PATH, duration, grouping, bnGenCount, numBits);
	
	printf("Program terminated with success...");

	return EXIT_SUCCESS;
}
