#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libsodium-win64\include\sodium.h"

#define BUFFER_SIZE 10
#define MAX_ITERATIONS 200
#define MAX_NAME_LENGTH 50

typedef struct
{
    long offset;
    char fileName[MAX_NAME_LENGTH + 1];    
} metaData;
#define METADATA_SIZE sizeof(metaData)

void encode(FILE *fileIn, FILE *fileOut, FILE *cipher, char *inName);
FILE* cipher(int length, char *fileName);
FILE* decode(FILE *fileIn, FILE *cipher);
int findFileLength(FILE *fileIn);