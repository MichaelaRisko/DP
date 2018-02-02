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

/*
 * This function asserts the success code parameter and terminates the program
 * with an error message accordingly
 *
 * @param success
 *			a success code
 * @param functionName
 *			a string with the function name to be printed in the event of a
 *			failure for debugging
 * @param message
 *			the error message to be printed
 */
void BNUTIL_successCheck(int success, char* functionName, char* message) {
	if(!success) {
		printf("Program terminated in an error @ function %s with"
			" message...%s...", functionName, message);
		//Terminate the program in a failure
		exit(EXIT_FAILURE);
	}
}

/*
 * This procedure prints a BIGNUM* instance to the console
 *
 * @param bigNum
 *			the number to be printed to the console
 */
void BNUTIL_cPrint(BIGNUM* bigNum) {
	BIO* out;
	out = BIO_new_fp(stdout, BIO_NOCLOSE);
	int success = BN_print(out, bigNum);
	//Success / Failure check
	BNUTIL_successCheck(success, "cPrint", "Error printing a" 
		" Big Number to the console");
}

/*
 * This procedure prints a BIGNUM* instance to the console with a newline
 * character at the end
 *
 * @param bigNum
 *			the number to be printed to the console
 */
void BNUTIL_cPrintln(BIGNUM* bigNum) {
	BNUTIL_cPrint(bigNum);
	printf("\n");
}



/*
 * This procedure sets 'timestamp' to a string containing the date and time
 * of the moment when the function was called in the format:
 * YYYY-MM-DD HH:MM:SS
 *
 * @param timestamp
 *			the variable to which the string timestamp will be set
 */
void BNUTIL_setTimestampNow(char* timestamp) {
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);
	int charsWritten = snprintf(timestamp, 20, "%d-%02d-%02d %02d:%02d:%02d",
							tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
							tm.tm_hour, tm.tm_min, tm.tm_sec);
	if(charsWritten < 0) {
		BNUTIL_successCheck(FALSE, "setTimestampNow", "Error "
					"executing snprintf");
	}
}
