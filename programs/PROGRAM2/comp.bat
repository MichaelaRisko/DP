gcc -m32 -Wall gcd.c ../../applink.c -o gcd -I../../INC -L../../LIB -llibeay32 -lssleay32 
rem gcc -m32 -Wall gcd.c ../../applink.c -o gcd -LC:..\..\OpenSSL\lib -IC:..\..\OpenSSL\include -llibeay32 -lssleay32 

