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
const int INT_BOUND_LOW = 992;
const int INT_BOUND_HIGH = 1952;


const int SEED = 32563;
const int SIZE_A = 62; //bits
const int SIZE_K = 37; //bits

//void getRandomFromInterval() {
//	int r = RAND_MAX;
//	r 
//	printf("%d", r);
//}

BIGNUM* calculateM(int n) {
	BN_CTX* ctx = BN_CTX_new();
	BIGNUM* nextPrime = BN_new();
	BN_one(nextPrime);
	BIGNUM* product = BN_new();
	BN_one(product);
	BNEASY_add(product, 1, FALSE);
	
	printf("product: ");
	BNUTIL_cPrintln(product);
	
	int i;
	for(i = 0; i < n; i++) {
		printf("\n");
		printf("i = %d\n", i);
		nextPrime = BNEASY_findNextPrime(nextPrime, FALSE, TRUE);
		printf("nextPrime: ");
		BNUTIL_cPrintln(nextPrime);
		int success = BN_mul(product, product, nextPrime, ctx);
		BNUTIL_successCheck(success, "calculateM", "Error multiplying "
								"two BIGNUM* instances");
		printf("product: ");
		BNUTIL_cPrintln(product);
	}
	BN_CTX_free(ctx);
	BN_free(nextPrime);
	return product;
}

BIGNUM* calculateP(BIGNUM* a, BIGNUM* k, BIGNUM* m) {
	// p = k * M + (65537^a mod M)
	
	BN_CTX* ctx = BN_CTX_new();
	
	//calculate 65537^a --> res
	BIGNUM* base = BN_new();
	BN_set_word(base, 65537);
	BIGNUM* res = BN_new();
	
	BN_exp(res, base, a, ctx);
	BN_free(base);
	
	//calculate (res mod M) --> modop
	BIGNUM* modop = NULL;
	BN_mod(modop, res, m, ctx);
	
	//calculate (k * M) --> mulop
	BIGNUM* mulop = NULL;
	BN_mul(mulop, k, m, ctx);
	
	//calculate addition of mulop and modop
	BIGNUM* result = NULL;
	BN_add(result, mulop, modop);
	
	BN_free(base);
	BN_free(mulop);
	BN_free(res);
	BN_CTX_free(ctx);
	
	return result;
	return NULL;
}

BIGNUM* generatePrimeRoca() {
	BIGNUM* a;
	BIGNUM* k;
	BIGNUM* m;
	BIGNUM* p;
	
	start:
	a = BNEASY_generateRandomBN(SIZE_A);
	//BNUTIL_cPrintln(a);
	k = BNEASY_generateRandomBN(SIZE_K);
	//BNUTIL_cPrintln(k);
	int n = 39;
	
	m = calculateM(n);
	p = calculateP(a, k, m);
	
	if(!BNEASY_isPrime(p)) {
		goto start;
	}
	
	//free memory and exit
	BN_free(a);
	BN_free(k);
	BN_free(m);
	
	return p;
}

int main() {
	printf("Program started...\n");
	
	BIGNUM* myPrime = generatePrimeRoca();
	BNUTIL_cPrintln(myPrime);
	
	printf("Program terminated with success...");
	return EXIT_SUCCESS;
}
























