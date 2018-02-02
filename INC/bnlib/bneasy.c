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

void BNEASY_seedRandomBN(int seed) {
	srand(seed);
}

/*
 * This function generates the next random BIGNUM* instance seeded by 
 * previously calling the BNEASY_seedRandomBN(...) function. Warning,
 * this function uses the standard C stdlib.h random number generator.
 *
 * @param bytes 
 *			the number of bytes the generated random BIGNUM* instance
 *			should have
 * @param msbSet 
 *			if TRUE, the MSB of the function will be 1, otherwise 0
 * @param bot 
 *			if bot > 0, the generated number will be even, if bot < 0,
 *			the generated number will be odd, if bot == 0, the generated
 *			number will be randomly even or odd.
 *
 * @return the randomly generated BIGNUM* instance
 */
BIGNUM* BNEASY_nextRandomBN(int bytes, bool msbSet, int bot) {
	//int buffSize = 2 * bytes + 1; //1 Byte = 2 Hex chars, + \0
	char buff[4096] = "";	
	int i;
	//generate an array of bytes
	for(i = 0; i < bytes; i++) {
		int random = rand() / (RAND_MAX / 255);
		char randomStr[3];
		snprintf(randomStr, 3, "%02x", random);
		strcat(buff, randomStr);
	}
	BIGNUM* result = NULL;
	BN_hex2bn(&result, buff);
	
	//if the number should be even or odd
	if(bot != 0) {
		if(bot > 0) {
			//set to even number
			int success = BN_clear_bit(result, 0);
			BNUTIL_successCheck(success, "nextRandomBN", "Error "
									"clearing LSB bit");
		} else {
			//set to odd number
			int success = BN_set_bit(result, 0);
			BNUTIL_successCheck(success, "nextRandomBN", "Error "
									"setting LSB bit");
		}
	}
	
	//if MSB is to be set
	if(msbSet) {
		int BITS_IN_BYTE = 8;
		int success = BN_set_bit(result, bytes * BITS_IN_BYTE - 1);
		BNUTIL_successCheck(success, "nextRandomBN", "Error setting MSB bit");
	}
	return result;
}

/*
 * This function generates a random BIGNUM* instance
 * 
 * @param numBits
 *			the number of bits in the generated number
 *
 * @return a random BIGNUM* instance
 */
BIGNUM* BNEASY_generateRandomBN(int numBits) {
	BIGNUM* num = BN_new();
	//If top is -1, the most significant bit of the random number can be zero.
	// If top is 0, it is set to 1, and if top is 1, the two most significant
	//bits of the number will be set to 1, so that the product of two such
	//random numbers will always have 2*bits length
	int TOP = 0;
	//If bottom is true, the number will be odd
	int BOTTOM = 1;
	int success = BN_rand(num, numBits, TOP, BOTTOM);
	//Success / Failure check
	BNUTIL_successCheck(success, "generateRandomBN", "Error generating random "
		"Big Number in OpenSSL library");
	return num;
}

/*
 * This function check whether 'bigNum' is a prime number using the openssl
 * BN_is_prime_ex function
 *
 * @param bigNum 
 *			the number to be checked for a prime
 *
 * @return TRUE if 'bigNum' is a prime, FALSE otherwise
 */
bool BNEASY_isPrime(BIGNUM* bigNum) {
	BN_CTX* ctx = BN_CTX_new();
	bool res = BN_is_prime_ex(bigNum, BN_prime_checks, ctx, NULL);
	BN_CTX_free(ctx);
	return res;
}

/*
 * This function adds number 'num' to the BIGNUM* instance
 *
 * @param bigNum
 *			the number to which the addend is to be added
 * @param num
 *			the addend to be added to 'bigNum'
 * @param sizeSafe
 *			if TRUE, the function will check whether the Big Number has the
 *			same size before and after the operation
 *
 * @return always TRUE if 'sizeSafe' was FALSE, else returns TRUE if 'bigNum'
 * 			has the same size after the operation as it did before the
 *			operation, otherwise returns FALSE
 */
bool BNEASY_add(BIGNUM* bigNum, long num, bool sizeSafe) {
	//save the current bigNum size
	int sizeBeforeOp = BN_num_bits(bigNum);
	BIGNUM* addend = BN_new();
	int success = BN_set_word(addend, num);
	//Success / Failure check
	BNUTIL_successCheck(success, "add", "Error setting Big Number word");
	//Execute BN addition
	success = BN_add(bigNum, bigNum, addend);
	//Success / Failure check
	BNUTIL_successCheck(success, "add", "Error adding two Big Numbers");
	
	BN_free(addend);
	//check whether the size of bigNum changed after the operation, return
	//false if the size increased, and a size-safe operation was requested
	int sizeAfterOp = BN_num_bits(bigNum);
	if(sizeSafe && (sizeBeforeOp != sizeAfterOp)) {
		return FALSE;
	}
	return TRUE;
}

/*
 * This function finds the next prime number from 'fromNum'
 *
 * @param fromNum
 *			the number from which the next prime number is to be found
 * @param sizeSafe
 *			TRUE if function is to guarantee same size of returning BIGNUM*
 *			as 'fromNum', else FALSE. If TRUE, and size overflows, the 
 *			function returns NULL.
 * @param skip
 *			if TRUE, the function will not check 'fromNum' for being a prime,
 *			but will skip to the next odd number and then start checking.
 *
 * @return the prime number following 'fromNum' (inclusive of 'fromNum' if 
 *			'skip' is FALSE. Returns FALSE if 'sizeSafe' is TRUE and the 
 *			operation causes the number to overflow in size.
 */
BIGNUM* BNEASY_findNextPrime(BIGNUM* fromNum, bool sizeSafe, bool skip) {
	//Create a duplicate number
	BIGNUM* number = BN_dup(fromNum);
	if(number == NULL) {
		BNUTIL_successCheck(FALSE, "findNextPrime", "Error "
								"duplicating BIGNUM");
	}
	
	bool safe;
	if(BN_is_bit_set(number, 0) == FALSE) {
		//If numFrom is even, add 1
		safe = BNEASY_add(number, 1, FALSE);
		
		if(sizeSafe == TRUE && safe == FALSE) {
			return NULL;
		}
	} else if(skip) {
		//If numFrom is to be skipped in checking for a prime, add 2
		safe =BNEASY_add(number, 2, FALSE);
		
		if(sizeSafe == TRUE && safe == FALSE) {
			return NULL;
		}
	}
	
	while(!BNEASY_isPrime(number)) {
		bool safe =BNEASY_add(number, 2, TRUE);
		if(sizeSafe == TRUE && safe == FALSE) {
			return NULL;
		}
	}
	return number;
}

///*
// * This function generates a BIGNUM* instance of size 'numSize' which is a
// * global variable. It sets MSB to 1, all other bits to 0
// * 
// * @param numBits
// *			the number of bits in the generated number
// *
// * @return a random BIGNUM* instance
// */
//BIGNUM* BNEASY_generateStrictBN(int numBits) {
//	BIGNUM* strict = BNEASY_generateRandomBN(numBits);
//	int strictSize = BN_num_bits(strict);
//	int success;
//	//clear all bits
//	int i;
//	for(i = 0; i < BN_num_bits(strict); i++) {
//		success = BN_clear_bit(strict, i);
//		BNUTIL_successCheck(success, "generateStrictBN", "Error clearing bit");
//	}
//	//set MSB to 1
//	success = BN_set_bit(strict, strictSize - 1);
//	BNUTIL_successCheck(success, "generateStrictBN", "Error setting bit");
//	
//	return strict;
//}

