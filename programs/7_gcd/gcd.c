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
 * @param count
 *			the number of prime numbers to be found from 'fromNum'
 *
 * @return the number of increments (by 2) needed in order to find all
 * 			of the requested prime numbers
 */
unsigned long measureGrouping(int primorial, BIGNUM* fromNum, int count) {
	if(count < 1) {
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
	
	BIGNUM* gcd_result = BN_new();
	//constant 1
	BIGNUM* ONE = BN_new();
	BN_set_word(ONE, 1);
	
	BIGNUM* primorial_bn = BN_new();
	int success = BN_set_word(primorial_bn, primorial);
	BNUTIL_successCheck(success, "measureGrouping", "Error setting"
		" Big Number word");
	
	BN_CTX* ctx = BN_CTX_new();
	
	while(numPrimesFound < count) {
//		printf("loop\n");
		timerStart = clock();
		
		BN_gcd(gcd_result, number, primorial_bn, ctx);
//		printf("bn: ");
//		BNUTIL_cPrintln(number);
//		printf("gcd result: ");
//		BNUTIL_cPrintln(gcd_result);
		//int gcdOne = BN_is_one(gcd_result);
		int gcdTest = BN_cmp(ONE, gcd_result);
//		printf("gcdTest: %d \n", gcdTest);
		
		//printf("gcd is 1?: %d \n", gcdOne);
		//testovat ak GCD je rovny 1
		//if(gcdOne == 1) {
		if(gcdTest == 0)
		{
//			printf("true\n");
			if(BNEASY_isPrime(number)) {
			printf("prime found\n");
				numPrimesFound++;
				printf("\r...found prime %d/%d...", numPrimesFound, count);
			}
			numIncrements++;
			if(numIncrements == ULONG_MAX) {
				BNUTIL_successCheck(FALSE, "measureGrouping", "unsigned long "
					"numIncrements overflow");
			}
		} else {
//			printf("false\n");
		}
		
		BNEASY_add(number, 2, FALSE);
		
		timerEnd = clock();
		executionTimeRaw += timerEnd - timerStart;
	} 
	printf("\n");
	BN_free(gcd_result);
	BN_free(number);
	BN_free(primorial_bn);
	BN_free(ONE);
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
		
	char primorial_str[16];
	char bnGenCount_str[16];
	char bn_str[1024];
	
	int primorial;
	int bnGenCount;
	BIGNUM* bn;
	
	printf("...reading params from input file...\n");
	FILEOPS_loadParamFromFile(IN_FILE_PATH, "primorial", primorial_str);
	FILEOPS_loadParamFromFile(IN_FILE_PATH, "bnGenCount", bnGenCount_str);
	FILEOPS_loadParamFromFile(IN_FILE_PATH, "bn", bn_str);
	
	primorial = atoi(primorial_str);
	bnGenCount = atoi(bnGenCount_str);
	bn = NULL;
	BN_hex2bn(&bn, bn_str);
	printf("...all params from input file read successfully...\n");
	
	
//	printf("primorial: %d", primorial);
//	printf("bnGenCount: %d", bnGenCount);
//	printf("primer: ");
//	BNUTIL_cPrintln(bn);
	
	printf("BIGNUM loaded from file: ");
	BNUTIL_cPrintln(bn);
	printf("Loaded bnGenCount = %d from file...\n", bnGenCount);
	printf("Loaded primorial = %d from file...\n", primorial);
	printf("Executing experiment 'measureGrouping'...\n");
//	clock_t start = clock();
	unsigned long grouping = measureGrouping(primorial, bn, bnGenCount);
	printf("Experiment finished! Grouping found: %lu\n", grouping);
//	clock_t end = clock();
	float duration = (float)(executionTimeRaw) / CLOCKS_PER_SEC;
	int numBits = BN_num_bytes(bn) * 8;
	writeResultToFile(OUT_FILE_PATH, duration, grouping, bnGenCount, numBits);
	
	printf("Program terminated with success...");

	return EXIT_SUCCESS;
}
