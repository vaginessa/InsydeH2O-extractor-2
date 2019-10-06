/*  extractor.c - InsydeFlash BIOS image extractor v0.2
    Author: Nikolaj Schlej
    License: WTFPL
    Modified: genBTC , 9/15/2019 
    - v0.3 (adds additional extractions and changes command line arguments)
    - v0.31 (adds the injector for platforms.ini)
    - v0.32 removed code redundancy. converted each step down to a common function call. 9/29
*/

#define PROGRAM_NAME "InsydeFlashExtractor v0.32+genBTC\n"

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

#define IFLASH_SIGNATURE_LENGTH 16 

typedef struct _IFLASH_HEADER {
    uint8_t  Signature[IFLASH_SIGNATURE_LENGTH];
    uint32_t FullSize;
    uint32_t UsedSize;
} IFLASH_HEADER;

const uint8_t IFLASH_BIOSIMG_SIGNATURE[] = { 
    0x24, 0x5F, 0x49, 0x46, 0x4C, 0x41, 0x53, 0x48, 0x5F, 
    0x42, 0x49, 0x4F, 0x53, 0x49, 0x4D, 0x47
}; // $_IFLASH_BIOSIMG

const uint8_t IFLASH_INI_IMG_SIGNATURE[] = {
    0x24, 0x5F, 0x49, 0x46, 0x4C, 0x41, 0x53, 0x48, 0x5F, 
    0x49, 0x4E, 0x49, 0x5F, 0x49, 0x4D, 0x47
}; // $_IFLASH_INI_IMG

const uint8_t IFLASH_EC_IMG_SIGNATURE[] = {
    0x24, 0x5F, 0x49, 0x46, 0x4C, 0x41, 0x53, 0x48, 0x5F, 
    0x45, 0x43, 0x5F, 0x49, 0x4D, 0x47, 0x5F,
}; // $_IFLASH_EC_IMG_

const uint8_t IFLASH_DRV_IMG_SIGNATURE[] = {
    0x24, 0x5F, 0x49, 0x46, 0x4C, 0x41, 0x53, 0x48, 0x5F, 
    0x44, 0x52, 0x56, 0x5F, 0x49, 0x4D, 0x47
}; // $_IFLASH_DRV_IMG 

const uint8_t IFLASH_BIOSCER_SIGNATURE[] = {
    0x24, 0x5F, 0x49, 0x46, 0x4C, 0x41, 0x53, 0x48, 0x5F, 
    0x42, 0x49, 0x4F, 0x53, 0x43, 0x45, 0x52
};  // $_IFLASH_BIOSCER

/* (Author: Nikolaj Schlej) Implementation of GNU memmem function using Boyer-Moore-Horspool algorithm
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


typedef struct _GetFile {
    char * file_name;
    FILE * the_file;
    uint8_t * buffer;
    uint8_t * end;
    uint8_t * found;
    uint32_t filesize;
    int returnStatus;
} GetFile;

//prototype include (extractor.h)
int extract_file(uint8_t* insyde_buffer, uint8_t* end, const char* file_name, const uint8_t* signature);
GetFile read_GetFile(const char* file_name);

/* Entry point */
int main(int argc, char* argv[])
{
    char* insyde_file_name = "isflash.bin";
    char* biosFD_file_name = "BIOSFILE.FD";
    char* ini_file_name = "platforms.ini";
    char* EC_file_name = "EC.BIN";
    char* drvimg_file_name = "drv_img.bin";
    char* bios_cert_file_name = "CERT.pem";
    int inject_ini;
    GetFile File1, File2;

    printf(PROGRAM_NAME);
    /* Check for arguments count */
    if (argc == 1)
    {
        printf("Usage: %s <INPUTBIOSFILE> - Defaulting to %s\n", argv[0], insyde_file_name);
    }
    else {
        insyde_file_name = argv[1];
    }

    /* Read File in, create buffer*/
    File1 = read_GetFile(insyde_file_name);
    if (File1.returnStatus != 0) return File1.returnStatus;

    inject_ini = (argc >= 3) ? 1 : 0 ;
//INJECTOR: Detect if we are injecting the .ini back in, from command line
    if (inject_ini)
    {
        //Part 1: Inject .INI back in: (if asked for)
        printf("Starting .ini file re-injection back into %s\n", insyde_file_name);
        File2 = read_GetFile(ini_file_name);
        if (File2.returnStatus != 0) return File2.returnStatus;

        //PART 2: Write & Replace the embedded ini file, in-place
        // Read:
        /* Search for the signature in the input buffer */
        File2.found = find_pattern(File2.buffer, File2.end, IFLASH_INI_IMG_SIGNATURE, IFLASH_SIGNATURE_LENGTH);
        if (!File2.found)
        {
            printf("Insyde .ini file signature not found in input file\n");
            return ERR_NOT_FOUND;
        }

        /* Populate the header and read used size */
        IFLASH_HEADER* ini_header = (IFLASH_HEADER*)File2.found;
        //TODO: check if less, and start zero-ing bytes out.
        ini_header->UsedSize = File2.filesize;    //set the size used header to the new ini's size

        if (File2.filesize > ini_header->FullSize)
        {
            printf(".ini file size %lu exceeds max allowable size %lu", File2.filesize, ini_header->FullSize);
            return ERR_FILE_WRITE;
        }
        // Write:
        /* Seek to the found location to start modifying */
        fseek(File1.the_file, File2.found - File2.buffer, SEEK_SET);

        /* Write Header with new size back */
        uint32_t headersize = fwrite(ini_header, sizeof(char), sizeof(IFLASH_HEADER), File1.the_file);
        if (headersize != sizeof(IFLASH_HEADER))
        {
            printf("Can't write .ini header to output file: %s", insyde_file_name);
            return ERR_FILE_WRITE;
        }
        else
        {
            printf("Wrote %lu byte header to %lu\n", headersize, File2.found - File2.buffer);
        }
        /* Write .INI file image to output file */
        uint32_t filesize = fwrite(File2.buffer, sizeof(char), File2.filesize, File1.the_file);
        if (filesize != File2.filesize)
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
        fclose(File1.the_file);
        return ERR_SUCCESS;
    }
//EXTRACTOR:
    //Part 1: $_IFLASH_BIOSIMG
    extract_file(File1.buffer, File1.end, biosFD_file_name, IFLASH_BIOSIMG_SIGNATURE);
    //Part 2: $_IFLASH_INI_IMG
    extract_file(File1.buffer, File1.end, ini_file_name, IFLASH_INI_IMG_SIGNATURE);
    //Part 3: $_IFLASH_EC_IMG_
    extract_file(File1.buffer, File1.end, EC_file_name, IFLASH_EC_IMG_SIGNATURE);
    //Part 4: $_IFLASH_BIOSCER
    extract_file(File1.buffer, File1.end, bios_cert_file_name, IFLASH_BIOSCER_SIGNATURE);
    //Part 5: $_IFLASH_DRV_IMG (most of the file)
    //extract_file(insyde_buffer, end, drvimg_file_name, IFLASH_DRV_IMG_SIGNATURE);
    return;
}

int extract_file(uint8_t* insyde_buffer, uint8_t* end, const char* file_name, const uint8_t* signature)
{
    /* Search for the signature in the input buffer */
    uint8_t* found = find_pattern(insyde_buffer, end, signature, IFLASH_SIGNATURE_LENGTH);
    if (!found)
    {
        printf("Insyde image signature not found in input file\n");
        return ERR_NOT_FOUND;
    }

    /* Populate the header and read used size */
    IFLASH_HEADER* header = (IFLASH_HEADER*)found;
    found += sizeof(IFLASH_HEADER);
    uint32_t filesize = header->UsedSize;

    /* Open output file */
    FILE*    out_file;
    if (fopen_s(&out_file, file_name, "wb"))
    {
        printf("Output file %s can't be opened", file_name);
        return ERR_FILE_OPEN;
    }

    /* Write image to output file */
    uint32_t readsize = fwrite(found, sizeof(char), filesize, out_file);
    if (readsize != filesize)
    {
        printf("Can't write output file %s", file_name);
        return ERR_FILE_WRITE;
    }

    /* Done */
    printf("File %s successfully extracted\n", file_name);
    fclose(out_file); //close file for reading
    return ERR_SUCCESS;
}

GetFile read_GetFile(const char* file_name)
{
    GetFile File1;
    File1.file_name = file_name;
    /* Open isflash.bin file as input */
    if (fopen_s(&File1.the_file, file_name, "r+b"))
    {
        printf("InsydeFlash input file can't be opened: %s", file_name);
        File1.returnStatus = ERR_FILE_OPEN;
        return File1;
    }

    /* Get isflash.bin file size */
    fseek(File1.the_file, 0, SEEK_END);
    File1.filesize = ftell(File1.the_file);
    fseek(File1.the_file, 0, SEEK_SET);

    /* Allocate memory for input buffer */
    File1.buffer = (uint8_t*)malloc(File1.filesize);
    if (!File1.buffer)
    {
        printf("Can't allocate memory to read InsydeFlash file: %s", file_name);
        File1.returnStatus = ERR_OUT_OF_MEMORY;
        return File1;
    }

    /* Read the whole flash file into input buffer */
    uint32_t readsize = fread((void*)File1.buffer, sizeof(char), File1.filesize, File1.the_file);
    if (readsize != File1.filesize)
    {
        printf("Can't read InsydeFlash file: %s", file_name);
        File1.returnStatus = ERR_FILE_READ;
        return File1;
    }
    File1.end = File1.buffer + File1.filesize;
    File1.returnStatus = ERR_SUCCESS;
    return File1;
    //fclose(the_file); //close file for reading
}