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


/*
 * This functions counts how many prime numbers it can find starting from
 * 'fromNum' in 'runSeconds' seconds.
 *
 * @param fromNum
 *			the number from which the next prime number is to be found
 * @param runSeconds
 *			the number of seconds the function is to run
 *
 * @return the number of prime numbers found
 */
int BNEASY_measureCountPerTime(BIGNUM* fromNum, int runSeconds) {
	int primeCount = 0;
	int startTimeSeconds = (int)time(NULL);
	BIGNUM* nextPrime;
	while((int)time(NULL) < startTimeSeconds + runSeconds) {
		nextPrime =BNEASY_findNextPrime(fromNum, FALSE, TRUE);
		BN_free(nextPrime);
		primeCount++;
	}
	return primeCount - 1;;
}

/*
 * This functions measures the time it takes to find 'count' number of prime
 * numbers from 'fromNum'.
 *
 * @param fromNum
 *			the number from which the next prime number is to be found
 * @param count
 *			the number of prime numbers to be found from 'fromNum'
 *
 * @return the time it took to find 'count' number of prime numbers
 * 			from 'fromNum' in seconds
 */
int BNEASY_measureTimePerCount(BIGNUM* fromNum, int count) {
	int startTimeSeconds = (int)time(NULL);
	int primeCount = 0;
	BIGNUM* nextPrime;
	while(primeCount < count) {
		nextPrime =BNEASY_findNextPrime(fromNum, FALSE, TRUE);
		BN_free(nextPrime);
		primeCount++;
	}
	return (int)time(NULL) - startTimeSeconds;
}

int main() {
	//Part 1/2
	int runTime;
	int size;
	int seed;
	
	printf("Running program timer...\n");
	printf("Enter the BIGNUM* size in bytes: ");
	scanf("%d", &size);
	printf("Enter the random number genreator seed: ");
	scanf("%d", &seed);
	printf("Running program 1/2: measureCountPerTime...\n");
	printf("Enter the requested run time in seconds: ");
	scanf("%d", &runTime);
	
	printf("Program running, please wait...\n");
	BNEASY_seedRandomBN(seed);
	BIGNUM* fromNum = BNEASY_nextRandomBN(size, FALSE, 0);
	int primeCount = BNEASY_measureCountPerTime(fromNum, runTime);
	printf("Found %d prime numbers in %d seconds\n", primeCount, runTime);
	
	//Part 2/2
	int count;
	printf("Running program 2/2: measureTimePerCount...\n");
	printf("Enter the number of prime numbers to be found: ");
	scanf("%d", &count);
	printf("Program running, please wait...\n");
	fromNum = BNEASY_nextRandomBN(size, FALSE, 0);
	int time = BNEASY_measureTimePerCount(fromNum, count);
	printf("In %d seconds, found %d prime numbers\n", time, count);
	
	printf("Program terminated with success...");

	return EXIT_SUCCESS;
}
