gcc -m32 -Wall timer.c ../../applink.c -o timer -I../../INC -L../../LIB -llibeay32 -lssleay32 
rem gcc -m32 -Wall timer.c ../../applink.c -o timer -LC:..\..\OpenSSL\lib -IC:..\..\OpenSSL\include -llibeay32 -lssleay32 

