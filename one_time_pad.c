#include <string.h>

#include "one_time_pad.h"
// args
//-----
// decode: d fileIn cipherFile
// encode: e fileIn fileOut cipherFile (option)
// make a cipher: c length(in kbytes) name

char buffer[BUFFER_SIZE];

int main(int argc, char *argv[])
{
    int init = sodium_init();
    if (init == -1)
    {
        printf("%s%d\n", "could not init sodium, was: ", init);
        exit(4);
    }
    FILE *fileIn;
    FILE *fileOut;
    FILE *cipherFile;
    if (argc <= 2)
    {
        printf("%s\n", "we require arguments");
        exit(1);
    }
    if (*argv[1] == 'c')
    {
        if (argc != 4)
        {
            printf("%s\n", "improper number of arguments to build a cipher");
            exit(1);
        }
        cipherFile = cipher(atoi(argv[2]), argv[3]);
        fclose(cipherFile);
    }
    else if (*argv[1] == 'e')
    {
        if (argc == 4 || argc == 5)
        {
            if ((fileIn = fopen(argv[2], "rb")) == NULL)
            {
                printf("fileIn does not exist\n");
                exit(2);
            }
            int extLoc;
            char fileOutFull[MAX_NAME_LENGTH];
            for (int i = 0; i < MAX_NAME_LENGTH - 4; i++)
            {
                if (argv[3][i] == '\0')
                {
                    extLoc = i;
                    fileOutFull[i] = '.';
                    fileOutFull[i+1] = 'e';
                    fileOutFull[i+2] = 'n';
                    fileOutFull[i+3] = 'c';
                    fileOutFull[i+4] = '\0';
                    break;
                }
                fileOutFull[i] = argv[3][i];
            }
            //printf("%s\n", &fileOutFull[0]);
            if ((fileOut = fopen(fileOutFull, "wb")) == NULL)
            {
                printf("failed to create fileOut\n");
                fclose(fileIn);
                exit(2);
            }
            if (argc == 4)
            {
                fileOutFull[extLoc] = '\0';
                cipherFile = cipher(findFileLength(fileIn)/1024 + 1, fileOutFull);
            }
            else
            {
                char cipherFull[MAX_NAME_LENGTH];
                for (int i = 0; i < MAX_NAME_LENGTH - 4; i++)
                {
                    if (argv[4][i] == '\0')
                    {
                        cipherFull[i] = '.';
                        cipherFull[i+1] = 'c';
                        cipherFull[i+2] = 'i';
                        cipherFull[i+3] = 'p';
                        cipherFull[i+4] = '\0';
                        break;
                    }
                    cipherFull[i] = argv[4][i];
                }
                if ((cipherFile = fopen(cipherFull, "rb")) == NULL)
                {
                    printf("cipherFile does not exist\n");
                    exit(2);
                }
            }
            encode(fileIn, fileOut, cipherFile, &(argv[2][0]));
        }
        else
        {
            if (argc > 5)
                printf("too many arguments to encode\n");
            else
                printf("too few arguments to encode\n");
            exit(1);
        }
    }
    else if (*argv[1] == 'd')
    {
        if (argc != 4 && argc != 3)
        {
            printf("%s\n", "invalid number of arguments to decode");
            exit(1);
        }
        char fileInFull[MAX_NAME_LENGTH];
        char cipherFull[MAX_NAME_LENGTH];
        // get fileIn name
        for (int i = 0; i < MAX_NAME_LENGTH - 4; i++)
        {
            if (argv[2][i] == '\0')
            {
                fileInFull[i] = '.';
                fileInFull[i+1] = 'e';
                fileInFull[i+2] = 'n';
                fileInFull[i+3] = 'c';
                fileInFull[i+4] = '\0';
                break;
            }
            fileInFull[i] = argv[2][i];
        }
        // if given a cipherFile, get its name
        if (argc == 4)
        {
            for (int i = 0; i < MAX_NAME_LENGTH - 4; i++)
            {
                if (argv[3][i] == '\0')
                {
                    cipherFull[i] = '.';
                    cipherFull[i+1] = 'c';
                    cipherFull[i+2] = 'i';
                    cipherFull[i+3] = 'p';
                    cipherFull[i+4] = '\0';
                    break;
                }
                cipherFull[i] = argv[3][i];
                if (i = MAX_NAME_LENGTH - 3)
                {
                    printf("fileIn name is too long or corrupt\n");
                    exit(3);
                }
            }
        }
        else
        {
            int curLoc = 0;
            while (fileInFull[curLoc] != '.')
            {
                cipherFull[curLoc] = fileInFull[curLoc];
                curLoc++;
            }
            cipherFull[curLoc] = '.';
            cipherFull[curLoc+1] = 'c';
            cipherFull[curLoc+2] = 'i';
            cipherFull[curLoc+3] = 'p';
            cipherFull[curLoc+4] = '\0';
        }
        if ((fileIn = fopen(fileInFull, "rb")) == NULL)
        {
            printf("fileIn does not exist\n");
            exit(2);
        }
        if ((cipherFile = fopen(cipherFull, "rb")) == NULL)
        {
            printf("cipherFile does not exist\n");
            fclose(fileIn);
            exit(2);
        }
        //printf("%s\n%s\n", fileInFull, cipherFull);
        fileOut = decode(fileIn, cipherFile);
        fclose(fileOut);
        fclose(fileIn);
        fclose(cipherFile);
    }
    else
    {
        printf("%s\n", "invalid command");
        exit(1);
    }
}

void encode(FILE *fileIn, FILE *fileOut, FILE *cipherFile, char *inName)
{
    char *buffer;

    // get length of inName
    int nameLen = strlen((const char *)inName);


    // get length of fileIn
    fseek(fileIn, 0, SEEK_END);
    int inLen = ftell(fileIn);
    rewind(fileIn);

    // length of file + name of file
    int totLen = nameLen + inLen + 1;
    //printf("inLen: %d\nnameLen: %d\ntotLen: %d\n", inLen, nameLen, totLen);

    // get length of cipherfile, abort if smaller than fileIn + inName
    fseek(cipherFile, 0, SEEK_END);
    int cipLen = ftell(cipherFile);
    rewind(cipherFile);

    if (cipLen < totLen)
    {
        printf("cipher file not long enough\n");
        exit(1);
    }
    if ((buffer = (char *)malloc(sizeof(char))) == NULL)
        exit(3);
    char curIn;
    char curCipher;

    rewind(fileOut);
    for (int i = 0; i < totLen; i++)
    {
        if (i < nameLen)
            curIn = inName[i];
        else if (i == nameLen)
            curIn = '\0';
        else
            fread((void *)&curIn, 1, 1, fileIn);
        fread((void *)&curCipher, 1, 1, cipherFile);
        *buffer = curIn ^ curCipher;
        //*buffer = curIn;
        fwrite((const void *)buffer, 1, 1, fileOut);
    }
    fclose(fileIn);
    fclose(fileOut);
    fclose(cipherFile);
    free(buffer);
}

FILE *cipher(int len, char* fileName)
{
    len = len * 1024;
    char fileOutFull[MAX_NAME_LENGTH];
    for (int i = 0; i < MAX_NAME_LENGTH - 4; i++)
    {
        if (fileName[i] == '\0')
        {
            fileOutFull[i] = '.';
            fileOutFull[i+1] = 'c';
            fileOutFull[i+2] = 'i';
            fileOutFull[i+3] = 'p';
            fileOutFull[i+4] = '\0';
            break;
        }
        fileOutFull[i] = fileName[i];
    }
    FILE *cip = fopen((const char *)fileOutFull, "wb+");
    char *buffer;
    if ((buffer = (char *)malloc(sizeof(char)*len)) == NULL)
        exit(3);
    *buffer = 0;

    randombytes_buf((void * const) buffer, (const size_t) len);
    fwrite(buffer, 1, len, cip);
    rewind(cip);
    return cip;
}

FILE *decode(FILE *fileIn, FILE *cipher)
{
    FILE *fileOut;
    char outName[100];
    char buffer;
    char curCip;
    char curIn;

    rewind(cipher);

    fseek(fileIn, 0, SEEK_END);
    int inLen = ftell(fileIn);
    rewind(fileIn);
    rewind(cipher);

    int foundName = 0;
    int justFound = 1;
    //printf("inlen: %d\n", inLen);
    for (int i = 0; i < inLen; i++)
    {
        fread((void *)&curIn, 1, 1, fileIn);
        fread((void *)&curCip, 1, 1, cipher);
        buffer = curIn ^ curCip;
        if (foundName == 0)
        {
            if (i >= 100)
            {
                printf("could not find file name\n");
                exit(1);
            }
            outName[i] = buffer;
            if (buffer == '\0')
                foundName = 1;
        }
        else
        {
            if (justFound == 1)
            {
                justFound = 0;
                //printf("filename: %s\n", &outName[0]);
                //printf("i: %d\n", i);
                fileOut = fopen((const char *)(&outName[0]), "wb");
            }
            fwrite((const void *)(&buffer), 1, 1, fileOut);
        }
    }
    return fileOut;
}
int findFileLength(FILE *fileIn)
{
    int len;
    fseek(fileIn, 0, SEEK_END);
    len = ftell(fileIn);
    rewind(fileIn);
    return len;
}