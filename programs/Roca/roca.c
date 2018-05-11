/*
 * Technical University of Kosice
 * Department of Electronics and Multimedia Telecommunications
 *
 * Masters Thesis
 * Generating Prime Numbers for Embedded Cryptographic Applications
 * 
 * Program
 * roca.c
 *
 * Student: Bc. Michaela Risko
 * Supervisor: doc. Ing. Milos Drutarovsky, PhD.
 *
 * REV 2.1 @ 27.04.2018
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
const int INT_BOUND_LOW = 992;
const int INT_BOUND_HIGH = 1952;

//const int SEED = 32563;
const int SIZE_A = 62; //bits
const int SIZE_K = 37; //bits
const int n = 39;

//The number of numbers generated
int numGenerations = 0;
long numExecutionsRM = 0;

BIGNUM* calculateM(int n) {
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* nextPrime = BN_new();
	BN_one(nextPrime);
	BIGNUM* product = BN_new();
	BN_one(product);
	BNEASY_add(product, 1, FALSE);
	
	int i;
	for(i = 0; i < n - 1; i++) {
		nextPrime = BNUTIL_getSmallPrime(i);
		int success = BN_mul(product, product, nextPrime, ctx);
		BNUTIL_successCheck(success, "calculateM", "Error multiplying "
								"two BIGNUM* instances");
	}
	BN_CTX_free(ctx);
	BN_free(nextPrime);
	return product;
}

BIGNUM* calculateP(BIGNUM* a, BIGNUM* k, BIGNUM* m) {
	// p = k * M + (65537^a mod M)
	BN_CTX* ctx = BN_CTX_new();
	
	//calculate 65537^a mod M --> mdop
	BIGNUM* base = BN_new();
	BN_set_word(base, 65537);
	BIGNUM* modop = BN_new();
	BN_mod_exp(modop, base, a, m, ctx);
	
	//calculate (k * M) --> mulop
	BIGNUM* mulop = BN_new();
	BN_mul(mulop, k, m, ctx);
	
	//calculate addition of mulop and modop
	BIGNUM* result = BN_new();
	BN_add(result, mulop, modop);
	
	BN_free(base);
	BN_free(modop);
	BN_free(mulop);
	BN_CTX_free(ctx);
	
	return result;
}

BIGNUM* generatePrimeRoca() {
	BIGNUM* a;
	BIGNUM* k;
	BIGNUM* m;
	BIGNUM* p;

	m = calculateM(n);
	
	start:
	a = BNEASY_generateRandomBN(SIZE_A);
	k = BNEASY_generateRandomBN(SIZE_K);
	p = calculateP(a, k, m);
	numGenerations++;
	numExecutionsRM++;
	
	if(!BNEASY_isPrime(p)) {
		goto start;
	}
	
	//free memory and exit
	BN_free(a);
	BN_free(k);
	BN_free(m);
	
	return p;
}

/*
 * This procedure writes the program result to a file @ filePath
 *
 * @param filePath
 *			the pointer to a string containing the file path to the file where
 *			text is to be written
 * @param duration
 *			the program execution time to be written to a file
 * @param numGens
 *			the number of times a number was generated using calculateP(...)
 * @param primeNums
 *			the number of prime numbers that were to be found
 * @param numBits
 *			the number of bits in the generated number
 *
 */
void writeResultToFile(const char* filePath, float duration,
								int numGen, int primeNums, int numBits) {
	printf("writing result to file...\n");
	char timestamp[20];
	BNUTIL_setTimestampNow(timestamp);
	FILEOPS_appendToFile(filePath, timestamp);
	
	char dur[1024];
	char text[] = " Found %d prime numbers in %.3f "
						"seconds requiring %d number generations and %ld "
						"primality tests.\n";
	int charsWritten = snprintf(dur, 1024, text, primeNums,
	duration, numGen, numExecutionsRM);
	if(charsWritten < 0) {
		BNUTIL_successCheck(FALSE, "writeResultToFile", "Error "
								"executing snprintf");
	}
	FILEOPS_appendToFile(filePath, dur);
}

int main() {
	printf("Program started...\n");
	printf("Running Roca 1.0\n");
	printf("Running program for generating 1024 bit primes...\n");
	
	printf("...reading params from input file...\n");
	char bnGenCount_str[16];
	FILEOPS_loadParamFromFile(IN_FILE_PATH, "bnGenCount", bnGenCount_str);
	int bnGenCount = atoi(bnGenCount_str);
	printf("...all params from input file read successfully...\n");
	
	printf("...starting algorithm...");
	
	clock_t start = clock();
	int i;
	for(i = 0; i < bnGenCount; i++) {
		generatePrimeRoca();
	}
	clock_t end = clock();
	float duration = (float)(end - start) / CLOCKS_PER_SEC;
	writeResultToFile("files/out_file.txt", duration, numGenerations, bnGenCount, 1024);
	
	printf("Program terminated with success...");
	return EXIT_SUCCESS;
}
























