/*  extractor.c - InsydeFlash BIOS image extractor v0.2
    Author: Nikolaj Schlej
    License: WTFPL
    Modified: genBTC , 9/15/2019 
    - v0.3 (adds additional extractions and changes command line arguments)
    - v0.31 (adds the injector for platforms.ini)
*/

#define PROGRAM_NAME "InsydeFlashExtractor v0.31+genBTC\n"

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

    end--;

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
    FILE*    ini_file;
    uint8_t* insyde_buffer;
    uint8_t* ini_file_buffer;
    uint8_t* end;
    uint8_t* end_ini;
    uint8_t* found;
    uint32_t filesize;
    uint32_t filesize_ini;
    uint32_t readsize;
    uint32_t readsize_ini;
    uint32_t headersize;
    IFLASH_BIOSIMG_HEADER* bios_header;
    IFLASH_INI_IMG_HEADER* ini_header;
    IFLASH_EC_IMG_HEADER* ec_header;
    char* read_file_name;
    char* insyde_file_name = "isflash.bin";
    //char* insyde_out_file_name = "isflash-new.bin";
    char* biosFD_file_name = "BIOSFILE.FD";
    char* ini_file_name = "platforms.ini";
    char* EC_file_name = "EC.BIN";
    int inject_ini;

    printf(PROGRAM_NAME);
    /* Check for arguments count */
    if (argc == 1)
    {
        printf("Usage: %s <INPUTBIOSFILE> - Defaulting to %s\n", argv[0], insyde_file_name);
        //return ERR_INVALID_PARAMETER;
        read_file_name = insyde_file_name;
    }
    else {
        read_file_name = argv[1];
    }
    /* Detect if we are injecting the .ini back in */
    inject_ini = (argc >= 3) ? 1 : 0 ;

    /* Open isflash.bin file as input */
    if(fopen_s(&in_file, read_file_name, "r+b"))
    {
        printf("InsydeFlash input file can't be opened: %s", read_file_name);
        return ERR_FILE_OPEN;
    }

    /* Get isflash.bin file size */
    fseek(in_file, 0, SEEK_END);
    filesize = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);

    /* Allocate memory for input buffer */
    insyde_buffer = (uint8_t*)malloc(filesize);
    if (!insyde_buffer)
    {
        printf("Can't allocate memory to read InsydeFlash file: %s", read_file_name);
        return ERR_OUT_OF_MEMORY;
    }
    
    /* Read the whole flash file into input buffer */
    readsize = fread((void*)insyde_buffer, sizeof(char), filesize, in_file);
    if (readsize != filesize)
    {
        printf("Can't read InsydeFlash file: %s", read_file_name);
        return ERR_FILE_READ;
    }
    end = insyde_buffer + filesize;
    //fclose(in_file); //close file for reading

//Part 0A: Inject .INI back in: (if asked for)
    if (inject_ini)
    {
        printf("Starting .ini file re-injection back into %s\n", insyde_file_name);
        /* Open .ini input file */
        if (fopen_s(&ini_file, ini_file_name, "rb"))
        {
            printf("%s input file can't be opened", ini_file_name);
            return ERR_FILE_OPEN;
        }
        /* Get input .ini file size */
        fseek(ini_file, 0, SEEK_END);
        filesize_ini = ftell(ini_file);
        fseek(ini_file, 0, SEEK_SET);

        ini_file_buffer = (uint8_t*)malloc(filesize_ini);
        if (!ini_file_buffer)
        {
            printf("Can't allocate memory to read %s file", ini_file_name);
            return ERR_OUT_OF_MEMORY;
        }

        /* Read the whole .ini file into input buffer */
        readsize_ini = fread((void*)ini_file_buffer, sizeof(char), filesize_ini, ini_file);
        if (readsize_ini != filesize_ini)
        {
            printf("Can't read %s file", ini_file_name);
            return ERR_FILE_READ;
        }
        else
        {
            printf("Read %lu bytes\n", readsize_ini);
        }
        end_ini = ini_file_buffer + readsize_ini;

//PART 0B: copied from Part 2:
        /* Search for the signature in the input buffer */
        found = find_pattern(insyde_buffer, end, IFLASH_INI_IMG_SIGNATURE, IFLASH_INI_IMG_SIGNATURE_LENGTH);
        if (!found)
        {
            printf("Insyde .ini file signature not found in input file\n");
            return ERR_NOT_FOUND;
        }

        /* Populate the header and read used size */
        ini_header = (IFLASH_INI_IMG_HEADER*)found;
        //TODO: check if less, and start zero-ing bytes out.
        ini_header->UsedSize = filesize_ini;    //set the size used header to the new ini's size

        if (filesize_ini > ini_header->FullSize)
        {
            printf(".ini file size %lu exceeds max allowable size %lu", filesize_ini, ini_header->FullSize);
            return ERR_FILE_WRITE;
        }

        // Seek to the found location to start modifying.
        fseek(in_file, found - insyde_buffer, SEEK_SET);

        /* Write Header with new size back*/
        headersize = fwrite(ini_header, sizeof(char), sizeof(IFLASH_INI_IMG_HEADER), in_file);
        if (headersize != sizeof(IFLASH_INI_IMG_HEADER))
        {
            printf("Can't write .ini header to output file: %s", insyde_file_name);
            return ERR_FILE_WRITE;
        }
        else
        {
            printf("Wrote %lu byte header to %lu\n", headersize, found - insyde_buffer);
        }
        /* Write .INI file image to output file */
        filesize = fwrite(ini_file_buffer, sizeof(char), filesize_ini, in_file);
        if (filesize != filesize_ini)
        {
            printf("Write Error - can't write .ini file to modify output file: %s", insyde_file_name);
            return ERR_FILE_WRITE;
        }
        else
        {
            printf("Wrote %lu bytes\n", filesize);
        }
        /* Done */
        printf("File %s successfully injected back into %s\n", ini_file_name, insyde_file_name);
        fclose(in_file);
        return ERR_SUCCESS;
    }


//Part 1: $_IFLASH_BIOSIMG
    /* Search for the signature in the input buffer */
    found = find_pattern(insyde_buffer, end, IFLASH_BIOSIMG_SIGNATURE, IFLASH_BIOSIMG_SIGNATURE_LENGTH);
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
    if (fopen_s(&out_file, biosFD_file_name, "wb"))
    {
        printf("Output %s file can't be opened", biosFD_file_name);
        return ERR_FILE_OPEN;
    }

    /* Write BIOS image to output file */
    readsize = fwrite(found, sizeof(char), filesize, out_file);
    if (readsize != filesize)
    {
        printf("Can't write output file %s", biosFD_file_name);
        return ERR_FILE_WRITE;
    }
    
    /* Done */
    printf("File %s successfully extracted\n", biosFD_file_name);

//Part 2: $_IFLASH_INI_IMG
    /* Search for the signature in the input buffer */
    found = find_pattern(insyde_buffer, end, IFLASH_INI_IMG_SIGNATURE, IFLASH_INI_IMG_SIGNATURE_LENGTH);
    if (!found)
    {
        printf("Insyde .ini file signature not found in input file\n");
        return ERR_NOT_FOUND;
    }

    /* Populate the header and read used size */
    ini_header = (IFLASH_INI_IMG_HEADER*)found;
    found += sizeof(IFLASH_INI_IMG_HEADER);
    filesize = ini_header->UsedSize;

    /* Open output file */
    if (fopen_s(&out_file, ini_file_name, "wb"))
    {
        printf("Output file %s can't be opened", ini_file_name);
        return ERR_FILE_OPEN;
    }

    /* Write INI file image to output file */
    readsize = fwrite(found, sizeof(char), filesize, out_file);
    if (readsize != filesize)
    {
        printf("Can't write output file %s", ini_file_name);
        return ERR_FILE_WRITE;
    }

    /* Done */
    printf("File %s successfully extracted\n", ini_file_name);

//Part 3: $_IFLASH_EC_IMG_
    /* Search for the signature in the input buffer */
    found = find_pattern(insyde_buffer, end, IFLASH_EC_IMG_SIGNATURE, IFLASH_EC_IMG_SIGNATURE_LENGTH);
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
    if (fopen_s(&out_file, EC_file_name, "wb"))
    {
        printf("Output file %s can't be opened", EC_file_name);
        return ERR_FILE_OPEN;
    }

    /* Write EC image to output file */
    readsize = fwrite(found, sizeof(char), filesize, out_file);
    if (readsize != filesize)
    {
        printf("Can't write output file %s", EC_file_name);
        return ERR_FILE_WRITE;
    }

    /* Done */
    printf("File %s successfully extracted\n", EC_file_name);
    return ERR_SUCCESS;
}
