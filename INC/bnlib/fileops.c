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
 * This procedure appends text to a file
 *
 * @param filePath
 *			the pointer to a string containing the file path to the file where
 *			text is to be appended
 * @param text
 *			the pointer to a string containing text to be written to 'file'
 */
void FILEOPS_appendToFile(const char* filePath, char* text) {
	FILE* file = fopen(filePath, "a");
	if(file == NULL) {
		BNUTIL_successCheck(FALSE, "appendToFile", "Error "
			"reading/creating output file");
	}
	int retVal = fprintf(file, text);
	//Do manual return value check, retVal equals number of chars written
	if(retVal < 0) {
		BNUTIL_successCheck(FALSE, "appendToFile", "Error "
			"printing text to output file");
	}
	retVal = fclose(file);
	if(retVal != 0) {
		BNUTIL_successCheck(FALSE, "appendToFile", "Error closing output file");
	}
}

/*
 * This function reads a parameter value from a file. The parameter must be
 * written in the following notation inside the file: 
 *			<paramName1> <value1>
 *			<paramName2> <value3>
 *			<paramName3> <value4>
 *
 * @param filePath
 *			the pointer to a string containing the file path to the file where
 *			text is to be appended
 * @param paramName
 *			the name of the parameter to be read
 * @param result
 *			the pointer to a string where the param value will be stored
 * @return TRUE if the operation was successful, FALSE otherwise
 */
bool FILEOPS_loadParamFromFile(const char* filePath, char* paramName, 
									char* result) {
	FILE* file = fopen(filePath, "r");
	if(file == NULL) {
		BNUTIL_successCheck(FALSE, "loadParamsFromFile", "Error "
								"reading input file");
	}
	char* buff = malloc(1024);
	bool trigger = FALSE;
	while(fscanf(file, "%s", buff) != EOF) {
		if(trigger) {
			strcpy(result, buff);
			free(buff);
			return 1;
		}
		if(strcmp(buff, paramName) == 0) {
			trigger = TRUE;
		}
	}
	free(buff);
	BNUTIL_successCheck(FALSE, "loadParamFromFile", "Error reading param");
	return 0;
}

/*
 * This function writes a BIGNUM variable to a file.
 *
 * @param filePath
 *			the path to the file where the BIGNUM instance is to be written
 * @param num
 *			the BIGNUM instance to be written to the file
 * @param append
 *			set to TRUE to append to file, set to FALSE to overwrite data in
 *			the file
 */
void FILEOPS_writeBNToFile(const char* filePath, BIGNUM* num, bool append) {
	FILE* file;
	if(append) {
		file = fopen(filePath, "a");
	} else {
		file = fopen(filePath, "w");
	}
	if(file == NULL) {
		BNUTIL_successCheck(FALSE, "readBNFromFile", "Error opening file");
	}
	
	int success = BN_print_fp(file, num);
	BNUTIL_successCheck(success, "writeBNToFile", "Error "
		"writing/appending BIGNUM to file");
	fclose(file);
}
