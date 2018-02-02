gcc -m32 -Wall seedGenerator.c ../../applink.c -o seedGenerator -I../../INC -L../../LIB -llibeay32 -lssleay32 
rem gcc -m32 -Wall seedGenerator.c ../../applink.c -o seedGenerator -LC:..\..\OpenSSL\lib -IC:..\..\OpenSSL\include -llibeay32 -lssleay32 

