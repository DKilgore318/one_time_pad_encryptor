#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <C:\libsodium-win64\include\sodium.h>


#define BUFFER_SIZE 10
#define MAX_ITERATIONS 200
#define MAX_NAME_LENGTH 100

void encode(FILE *fileIn, FILE *fileOut, FILE *cipher, char *inName);
FILE* cipher(int length, char *fileName);
FILE* decode(FILE *fileIn, FILE *cipher);
int findFileLength(FILE *fileIn);