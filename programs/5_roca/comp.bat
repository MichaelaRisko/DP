gcc -m32 -Wall roca.c ../../applink.c -o roca -I../../INC -L../../LIB -llibeay32 -lssleay32 
rem gcc -m32 -Wall roca.c ../../applink.c -o roca -LC:..\..\OpenSSL\lib -IC:..\..\OpenSSL\include -llibeay32 -lssleay32 

