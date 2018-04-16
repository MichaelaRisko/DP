gcc -m32 -Wall rmMod.c ../../applink.c -o rmMod -I../../INC -L../../LIB -llibeay32 -lssleay32 
rem gcc -m32 -Wall rmMod.c ../../applink.c -o rmMod -LC:..\..\OpenSSL\lib -IC:..\..\OpenSSL\include -llibeay32 -lssleay32 

