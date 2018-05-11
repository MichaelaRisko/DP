gcc -m32 -Wall grouping.c ../../applink.c -o grouping -I../../INC -L../../LIB -llibeay32 -lssleay32 
rem gcc -m32 -Wall grouping.c ../../applink.c -o grouping -LC:..\..\OpenSSL\lib -IC:..\..\OpenSSL\include -llibeay32 -lssleay32 

