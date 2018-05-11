/*
 * Technical University of Kosice
 * Department of Electronics and Multimedia Telecommunications
 *
 * Masters Thesis
 * Generating Prime Numbers for Embedded Cryptographic Applications
 *
 * Program
 * PROGRAM 2
 * gcd.c
 *
 * Student: Bc. Michaela Risko
 * Supervisor: doc. Ing. Milos Drutarovsky, PhD.
 *
 * REV 3.0 @ 10.05.2018
 *     - added comments
 *     - added the option of printing primes found to output file
 * REV 2.2 @ 29.04.2018
 *     - corrected error with incorrect primorial usage
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

/*
 * File path variables
 */
//Output file path
const char* OUT_FILE_PATH = "files/out_file.txt";
//Input file path
const char* IN_FILE_PATH = "files/in_file.txt";

/*
 * File path variables
 */
//Store CPU clock ticks for measuring time
long executionTimeRaw = 0;
//Store the number of times that the Rabin-Miller primality test was executed
long numExecutionsRM = 0;
//set to TRUE if found primes are to be printed to the output file, FALSE
//otherwise
bool printPrimes = FALSE;

/*
 * This function calculates the primorial M of the first 'n' primes
 * @param n
 *			the number of primes from which primorial M is to be calculated
 *
 * @return the calculated primorial M
 */
BIGNUM* calculateM(int n) {
	//intialize a context for OpenSSL functions
	BN_CTX* ctx = BN_CTX_new();
	//Initialize a variable for storing a prime
	BIGNUM* nextPrime = BN_new();
	//set the variable to the algebraic number 1
	BN_one(nextPrime);
	//Initialize a variable for storing calculations
	BIGNUM* product = BN_new();
	//set the variable to the algebraic number 1
	BN_one(product);
	//add the algebraic value 1 to the product
	BNEASY_add(product, 1, FALSE);

	int i;
	for(i = 0; i < n; i++) {
		//get the i-th small prime
		nextPrime = BNUTIL_getSmallPrime(i);
		//multiply the current product by the small prime and save the result
		//to 'product'
		int success = BN_mul(product, product, nextPrime, ctx);
		//check for errors during the multiplication operation
		BNUTIL_successCheck(success, "calculateM", "Error multiplying "
								"two BIGNUM* instances");
	}
	//clear allocated memory for OpenSSL
	BN_CTX_free(ctx);
	BN_free(nextPrime);
	return product;
}

/*
 * This function calculates the number of increments of 2 that are needed in
 * order to find a specific number of prime numbers starting from a specific
 * number. The operation is not size-safe.
 * The counter of increments is declared as 'unsigned long' so it is possible
 * for this counter to overflow. Appropriate exception handling is in place.
 * @param primorial
 *			the primorial required for a correct calculation
 * @param fromNum
 *			the number from which the next prime number is to be found
 * @param count
 *			the number of prime numbers to be found from 'fromNum'
 *
 * @return the number of increments (by 2) needed in order to find all
 * 			of the requested prime numbers
 */
unsigned long measureGrouping(int primorial, BIGNUM* fromNum, int count) {
	//validate function input parameters
	if(count < 1) {
		//exit in failure if the number of primes to be found is < 1
		BNUTIL_successCheck(FALSE, "measureGrouping", "function parameter "
			"'count' must be > 0");
	}
	
	//Create a duplicate number from 'fromNum' - this prevents the original
	//function variable 'fromNum' from being modified by the algorithm in this
	//function therefore allowing the variable passed to this function as
	//'fromNum' to retain its original value for use in other functions.
	BIGNUM* number = BN_dup(fromNum);
	//Store the number of times the variable 'number' is inremented by the
	//number 2 in the algorithm below
	unsigned long  numIncrements = 0;
	//Store the number of primes found by the algorithm
	int numPrimesFound = 0;
	//Verify that 'number' is odd if not, set LSB to '1'
	if(BN_is_bit_set(number, 0) == FALSE) {
		//If numFrom is even, add 1
		BNEASY_add(number, 1, FALSE);
	}
	//Store the number of clock ticks at timer start
	clock_t timerStart;
	//Store the number of clock ticks at timer end
	clock_t timerEnd;
	//reset the execution measurement time
	executionTimeRaw = 0;

	//create a variable for storing the calculated GCD result
	BIGNUM* gcd_result = BN_new();
	//create a constant 'ONE' and set its value to 1
	BIGNUM* ONE = BN_new();
	BN_set_word(ONE, 1);

	//create a variable for storing the primorial and set its initial value
	BIGNUM* primorial_bn = BN_new();
	primorial_bn = calculateM(primorial);

	//create a context for OpenSSL functions
	BN_CTX* ctx = BN_CTX_new();

	//Will be set to TRUE when a prime is found in the while loop below,
	//will be reset at start of every while loop iteration to FALSE. This
	//variable is used by logic to print the primes found to the output file
	//if the input file has the input parameter 'printPrimes' set to 1
	bool foundPrimeNow;
	
	//main while loop which terminates when the requested number of primes have
	//been found
	while(numPrimesFound < count) {
		//initialize/reset flag
		foundPrimeNow = FALSE;
		//save current clock ticks for time measurement start
		timerStart = clock();
		//calculate the GCD of 'number' and 'primorial_bn' and store the 
		//result to 'gcd_result'
		BN_gcd(gcd_result, number, primorial_bn, ctx);
		//check whether 'gcd_result' is equal to 1 by comparing it to the
		//variable constant 'ONE'
		int gcdTest = BN_cmp(ONE, gcd_result);
		if(gcdTest == 0)
		{
			//execute R-M test to check if 'number' is a prime
			bool isPrime = BNEASY_isPrime(number);
			//increment the counter of the number of R-M tests executed
			numExecutionsRM++;
			if(isPrime) {
				//set to TRUE to trigger printing of the prime found to the output
				//file
				foundPrimeNow = TRUE;
				//increment the counter of the number of primes found
				numPrimesFound++;
				printf("\r...found prime %d/%d...", numPrimesFound, count);
			}
			//trigger an error if 'numIncrements' counter overflows
			if(numIncrements == ULONG_MAX) {
				BNUTIL_successCheck(FALSE, "measureGrouping", "unsigned long "
					"numIncrements overflow");
			}
		}
		//increment 'number' by 2 to get the next consecutive odd number
		BNEASY_add(number, 2, FALSE);
		//increment the counter of the number of increments of 'number' by 2
		numIncrements++;
		//save the current clock ticks for time measruement end
		timerEnd = clock();
		//calculate the number of clock ticks elapsed between time measruement
		//start and end and save to global variable
		executionTimeRaw += timerEnd - timerStart;
		
		//if found primes are to be printed to the output file and the current
		//'number' was found to be a prime
		if(printPrimes && foundPrimeNow) {
			//reset foundPrimeNow flag
			foundPrimeNow = FALSE;
			//print to the file the prime number which was found in the
			//current while loop iteration
			FILEOPS_appendToFile(OUT_FILE_PATH, "Prime found: ");
			BIO* out = BIO_new_file(OUT_FILE_PATH, "a");
			BN_print(out, number);
			//free BIO* memory
			BIO_free(out);
			FILEOPS_appendToFile(OUT_FILE_PATH, "\n");
		}
	}
	printf("\n");
	//clear allocated memory for OpenSSL
	BN_free(gcd_result);
	BN_free(number);
	BN_free(primorial_bn);
	BN_free(ONE);
	BN_CTX_free(ctx);

	//decrease 'numIncrements' by 1 - extraneous increment occurs after every
	//increment after the last prime has been found
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
	//set 'timestamp' to a string representation of the current date and time
	BNUTIL_setTimestampNow(timestamp);
	//print the current timestamp to the output file
	FILEOPS_appendToFile(filePath, timestamp);

	char dur[1024];
	//create a string to be written to the output file detailng the program
	//output
	char text[] = " Found %d prime numbers (starting at %d bit) in %.3f "
						"seconds with a grouping factor of %lu and %ld "
						"primality tests.\n";
	int charsWritten = snprintf(dur, 1024, text, primeNums, numBits,
	duration, grouping, numExecutionsRM);
	//check if an error occured when building the output string
	if(charsWritten < 0) {
		BNUTIL_successCheck(FALSE, "writeResultToFile", "Error "
								"executing snprintf");
	}
	//append built output string to file
	FILEOPS_appendToFile(filePath, dur);
}

int main() {
	printf("Program started...\n");

	//var for storing string input parameter from file - primorial
	char primorial_str[16];
	//var for storing string input parameter from file - bnGenCount
	char bnGenCount_str[16];
	//var for storing string input parameter from file - bn
	char bn_str[1024];
	//var for storing string input parameter from file - printPrimes
	char printPrimes_str[16];

	int primorial;
	int bnGenCount;
	BIGNUM* bn;

	printf("...reading params from input file...\n");
	//save 'primorial' value from input file to variable 'primorial_str'
	FILEOPS_loadParamFromFile(IN_FILE_PATH, "primorial", primorial_str);
	//save 'bnGenCount' value from input file to variable 'bnGenCount_str'
	FILEOPS_loadParamFromFile(IN_FILE_PATH, "bnGenCount", bnGenCount_str);
	//save 'bn' value from input file to variable 'bn_str'
	FILEOPS_loadParamFromFile(IN_FILE_PATH, "bn", bn_str);
	//save 'printPrimes' value from input file to variable 'printPrimes_str'
	FILEOPS_loadParamFromFile(IN_FILE_PATH, "printPrimes", printPrimes_str);

	//parse 'primorial_str' string for int value of 'primorial'
	primorial = atoi(primorial_str);
	//parse 'bnGenCount_str' string for int value of 'bnGenCount'
	bnGenCount = atoi(bnGenCount_str);
	//parse 'bn_str' string for int value of 'bn'
	bn = NULL;
	BN_hex2bn(&bn, bn_str);
	//parse 'printPrimes_str' string for int value of 'printPrimes'
	printPrimes = atoi(printPrimes_str);
	printf("...all params from input file read successfully...\n");

	//print loaded parameters to the console
	printf("BIGNUM loaded from file: ");
	BNUTIL_cPrintln(bn);
	printf("Loaded bnGenCount = %d from file...\n", bnGenCount);
	printf("Loaded primorial = %d from file...\n", primorial);
	printf("Loaded printPrimes = %d from file...\n", printPrimes);
	printf("Executing experiment 'measureGrouping'...\n");

	//If the primes found are to be printed to the output file, print extra
	//lines at start of output file
	if(printPrimes) {
		char timestamp[20];
		BNUTIL_setTimestampNow(timestamp);
		FILEOPS_appendToFile(OUT_FILE_PATH, timestamp);
		FILEOPS_appendToFile(OUT_FILE_PATH, " New experiment started...\n");
	}

	//execute the main program algorithm and save the result to 'grouping'
	//'grouping' - the number of times the number 2 needs to be added to
	//the number 'fromNum' to find the requested number of primes
	unsigned long grouping = measureGrouping(primorial, bn, bnGenCount);
	printf("Experiment finished! Grouping found: %lu\n", grouping);

	//calculate resultant execution time by dividing the sum of all clock ticks
	//during main algorithm execution buy the number of processor clock ticks
	//in one second
	float duration = (float)(executionTimeRaw) / CLOCKS_PER_SEC;
	//write the program results to the output file
	int numBits = BN_num_bytes(bn) * 8;
	writeResultToFile(OUT_FILE_PATH, duration, grouping, bnGenCount, numBits);

	printf("Program terminated with success...");

	return EXIT_SUCCESS;
}
