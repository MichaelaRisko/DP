gcc -m32 -Wall generator.c ../../applink.c -o generator -I../../INC -L../../LIB -llibeay32 -lssleay32 
rem gcc -m32 -Wall generator.c ../../applink.c -o generator -LC:..\..\OpenSSL\lib -IC:..\..\OpenSSL\include -llibeay32 -lssleay32 

