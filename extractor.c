/*  extractor.c - InsydeFlash BIOS image extractor v0.2
    Author: Nikolaj Schlej
    License: WTFPL
    Modified: genBTC , 9/15/2019 
    - v0.3 (adds additional extractions and changes command line arguments)
*/

#define PROGRAM_NAME "InsydeFlashExtractor v0.3+genBTC"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#define ERR_SUCCESS             0
#define ERR_NOT_FOUND           1
#define ERR_FILE_OPEN           2
#define ERR_FILE_READ           3
#define ERR_FILE_WRITE          4
#define ERR_INVALID_PARAMETER   5
#define ERR_OUT_OF_MEMORY       6

const uint8_t IFLASH_BIOSIMG_SIGNATURE[] = { 
    0x24, 0x5F, 0x49, 0x46, 0x4C, 0x41, 0x53, 0x48, 0x5F, 0x42, 0x49, 0x4F,
    0x53, 0x49, 0x4D, 0x47
}; // "$_IFLASH_BIOSIMG"
#define IFLASH_BIOSIMG_SIGNATURE_LENGTH 16 

typedef struct _IFLASH_BIOSIMG_HEADER {
    uint8_t  Signature[IFLASH_BIOSIMG_SIGNATURE_LENGTH];
    uint32_t FullSize;
    uint32_t UsedSize;
} IFLASH_BIOSIMG_HEADER;

const uint8_t IFLASH_INI_IMG_SIGNATURE[] = {
    0x24, 0x5F, 0x49, 0x46, 0x4C, 0x41, 0x53, 0x48, 0x5F, 0x49, 0x4E, 0x49, 
    0x5F, 0x49, 0x4D, 0x47
}; // "$_IFLASH_INI_IMG"
#define IFLASH_INI_IMG_SIGNATURE_LENGTH 16

typedef struct _IFLASH_INI_IMG_HEADER {
    uint8_t  Signature[IFLASH_INI_IMG_SIGNATURE_LENGTH];
    uint32_t FullSize;
    uint32_t UsedSize;
} IFLASH_INI_IMG_HEADER;

const uint8_t IFLASH_EC_IMG_SIGNATURE[] = {
    0x24, 0x5F, 0x49, 0x46, 0x4C, 0x41, 0x53, 0x48, 0x5F, 0x45, 0x43, 0x5F, 
    0x49, 0x4D, 0x47, 0x5F,
}; // "$_IFLASH_EC_IMG_"
#define IFLASH_EC_IMG_SIGNATURE_LENGTH 16

typedef struct _IFLASH_EC_IMG_HEADER {
    uint8_t  Signature[IFLASH_EC_IMG_SIGNATURE_LENGTH];
    uint32_t FullSize;
    uint32_t UsedSize;
} IFLASH_EC_IMG_HEADER;

// also exists: 
//
// _IFLASH_DRV_IMG 
// 0x24, 0x5F, 0x49, 0x46, 0x4C, 0x41, 0x53, 0x48, 0x5F, 0x44, 0x52, 0x56, 0x5F, 0x49, 0x4D, 0x47, 
// _IFLASH_BIOSCER
// 0x24, 0x5F, 0x49, 0x46, 0x4C, 0x41, 0x53, 0x48, 0x5F, 0x42, 0x49, 0x4F, 0x53, 0x43, 0x45, 0x52,


/* Implementation of GNU memmem function using Boyer-Moore-Horspool algorithm
*  Returns pointer to the beginning of found pattern or NULL if not found */
uint8_t* find_pattern(uint8_t* begin, uint8_t* end, const uint8_t* pattern, size_t plen)
{
    size_t scan = 0;
    size_t bad_char_skip[256];
    size_t last;
    size_t slen;

    if (plen == 0 || !begin || !pattern || !end || end <= begin)
        return NULL;

    slen = end - begin;

    for (scan = 0; scan <= 255; scan++)
        bad_char_skip[scan] = plen;

    last = plen - 1;

    for (scan = 0; scan < last; scan++)
        bad_char_skip[pattern[scan]] = last - scan;

    while (slen >= plen)
    {
        for (scan = last; begin[scan] == pattern[scan]; scan--)
            if (scan == 0)
                return begin;

        slen     -= bad_char_skip[begin[last]];
        begin   += bad_char_skip[begin[last]];
    }

    return NULL;
}

/* Entry point */
int main(int argc, char* argv[])
{
    FILE*    in_file;
    FILE*    out_file;
    uint8_t* in_buffer;
    uint8_t* end;
    uint8_t* found;
    long filesize;
    long read;
    IFLASH_BIOSIMG_HEADER* bios_header;
    IFLASH_INI_IMG_HEADER* ini_header;
    IFLASH_EC_IMG_HEADER* ec_header;

    /* Check for arguments count */
    if (argc < 2)
    {
        printf(PROGRAM_NAME);
        printf("\nUsage: %s ISFLASH.BINFILE\n", argv[0]);
        return ERR_INVALID_PARAMETER;
    }

    /* Open input file */
    in_file = fopen(argv[1], "rb");
    if(!in_file)
    {
        perror("Input file can't be opened");
        return ERR_FILE_OPEN;
    }

    /* Get input file size */
    fseek(in_file, 0, SEEK_END);
    filesize = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);

    /* Allocate memory for input buffer */
    in_buffer = (uint8_t*)malloc(filesize);
    if (!in_buffer)
    {
        perror("Can't allocate memory for input file");
        return ERR_OUT_OF_MEMORY;
    }
    
    /* Read the whole input file into input buffer */
    read = fread((void*)in_buffer, sizeof(char), filesize, in_file);
    if (read != filesize)
    {
        perror("Can't read input file");
        return ERR_FILE_READ;
    }
    end = in_buffer + filesize - 1;

//Part 1: $_IFLASH_BIOSIMG
    /* Search for the signature in the input buffer */
    found = find_pattern(in_buffer, end, IFLASH_BIOSIMG_SIGNATURE, IFLASH_BIOSIMG_SIGNATURE_LENGTH);
    if (!found)
    {
        printf("Insyde BIOS image signature not found in input file\n");
        return ERR_NOT_FOUND;
    }

    /* Populate the header and read used size */
    bios_header = (IFLASH_BIOSIMG_HEADER*) found;
    found += sizeof(IFLASH_BIOSIMG_HEADER);
    filesize = bios_header->UsedSize;

    /* Open output file */
    out_file = fopen("BIOSFILE.FD", "wb");
    if (!out_file)
    {
        perror("Output file can't be opened");
        return ERR_FILE_OPEN;
    }

    /* Write BIOS image to output file */
    read = fwrite(found, sizeof(char), filesize, out_file);
    if (read != filesize)
    {
        perror("Can't write output file BIOSFILE.FD");
        return ERR_FILE_WRITE;
    }
    
    /* Done */
    printf("File BIOSFILE.FD successfully extracted\n");

//Part 2: $_IFLASH_INI_IMG
    /* Search for the signature in the input buffer */
    found = find_pattern(in_buffer, end, IFLASH_INI_IMG_SIGNATURE, IFLASH_INI_IMG_SIGNATURE_LENGTH);
    if (!found)
    {
        printf("Insyde platforms.ini file signature not found in input file\n");
        return ERR_NOT_FOUND;
    }

    /* Populate the header and read used size */
    ini_header = (IFLASH_INI_IMG_HEADER*)found;
    found += sizeof(IFLASH_INI_IMG_HEADER);
    filesize = ini_header->UsedSize;

    /* Open output file */
    out_file = fopen("platforms.ini", "wb");
    if (!out_file)
    {
        perror("Output file can't be opened");
        return ERR_FILE_OPEN;
    }

    /* Write INI file image to output file */
    read = fwrite(found, sizeof(char), filesize, out_file);
    if (read != filesize)
    {
        perror("Can't write output file platforms.ini");
        return ERR_FILE_WRITE;
    }

    /* Done */
    printf("File platforms.ini successfully extracted\n");

//Part 3: $_IFLASH_EC_IMG_
    /* Search for the signature in the input buffer */
    found = find_pattern(in_buffer, end, IFLASH_EC_IMG_SIGNATURE, IFLASH_EC_IMG_SIGNATURE_LENGTH);
    if (!found)
    {
        printf("Insyde EC image signature not found in input file\n");
        return ERR_NOT_FOUND;
    }

    /* Populate the header and read used size */
    ec_header = (IFLASH_EC_IMG_HEADER*)found;
    found += sizeof(IFLASH_EC_IMG_HEADER);
    filesize = ec_header->UsedSize;

    /* Open output file */
    out_file = fopen("EC.BIN", "wb");
    if (!out_file)
    {
        perror("Output file can't be opened");
        return ERR_FILE_OPEN;
    }

    /* Write EC image to output file */
    read = fwrite(found, sizeof(char), filesize, out_file);
    if (read != filesize)
    {
        perror("Can't write output file EC.BIN");
        return ERR_FILE_WRITE;
    }

    /* Done */
    printf("File EC.BIN successfully extracted\n");
    return ERR_SUCCESS;
}
