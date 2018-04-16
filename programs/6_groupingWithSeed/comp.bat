gcc -m32 -Wall groupingWithSeed.c ../../applink.c -o groupingWithSeed -I../../INC -L../../LIB -llibeay32 -lssleay32 
rem gcc -m32 -Wall groupingWithSeed.c ../../applink.c -o groupingWithSeed -LC:..\..\OpenSSL\lib -IC:..\..\OpenSSL\include -llibeay32 -lssleay32 

