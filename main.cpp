#include <stdio.h>
#include <stdlib.h>

#include "openssl/sha.h"
#include <string>
#include <elf.h>
#include <sys/mman.h>
#include <fcntl.h>

#include <sys/types.h>
#include <unistd.h>

#include <iomanip>
#include <sstream>
#include <string.h>

/*
int mydata_offset(Elf64_Shdr *shdr, char *strTab, int shNum, uint8_t *data)
{
  int   i;

  for(i = 0; i < shNum; i++) {
    size_t k;
    // printf("%02d: %s Offset %lx\n", i, &strTab[shdr[i].sh_name],
    //    shdr[i].sh_offset);
    /* for (k = shdr[i].sh_offset; k < shdr[i].sh_offset + shdr[i].sh_size; k++) {
       printf("%x", data[k]);
     }
     printf("\n");
     for (k = shdr[i].sh_offset; k < shdr[i].sh_offset + shdr[i].sh_size; k++) {
       printf("%c", data[k]);
     }
     printf("\n");
  }
}*/

int mydata_offset(Elf64_Shdr *shdr, char *strTab, int shNum, uint8_t *data) {
  int   i;

  for(i = 0; i < shNum; i++) {
    //size_t k;
     if (!strcmp(&strTab[shdr[i].sh_name], ".my_hash")) {
         //printf ("\n%lx\n", shdr[i].sh_offset);
         return  shdr[i].sh_offset;
     }
  }
}

void sha256_hash_string (unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65]){
    int i = 0;

    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }

    outputBuffer[64] = 0;
}

int filesize(int fd)
{
  return (lseek(fd, 0, SEEK_END));
}

void sha256_string(char *string, char outputBuffer[65])
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    int i = 0;
    for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}

int sha256_file(char *path, char outputBuffer[65]) {
    FILE *file = fopen(path, "rb");
    if(!file) return -534;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const int bufSize = 32768;
    unsigned char *buffer = (unsigned char*)malloc(bufSize);
    int bytesRead = 0;
    if(!buffer) return ENOMEM;
    while((bytesRead = fread(buffer, 1, bufSize, file)))
    {
        SHA256_Update(&sha256, buffer, bytesRead);
    }
    SHA256_Final(hash, &sha256);

    sha256_hash_string(hash, outputBuffer);
    fclose(file);
    free(buffer);
    return 0;
}


int main(int argc, char *argv[]) {

    void  *data;
    Elf64_Ehdr    *elf;
    Elf64_Shdr    *shdr;
    int       fd;
    char      *strtab;

//Определение смещения секции .mydata
    fd = open("/date_hash1", O_RDONLY);
    data = mmap(NULL, filesize(fd), PROT_READ, MAP_SHARED, fd, 0);
    elf = (Elf64_Ehdr *) data;
    shdr = (Elf64_Shdr *) ((uint8_t *)data + elf->e_shoff);
    strtab = (char *)((uint8_t *)data + shdr[elf->e_shstrndx].sh_offset);

    int offset = mydata_offset(shdr, strtab, elf->e_shnum, (uint8_t*)data);
    close(fd);



    //static char buffer[65];
    //sha256_file("/date_hash0", buffer);
    //cout << buffer << endl;

    FILE *file = fopen("/date_hash1", "rb");
    if(!file) return -534;

    int bytesRead = 0;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    //SHA256_Update(&sha256, buffer, bytesRead);
    //SHA256_Final(hash, &sha256);

    int bufSize = 32768;
    unsigned char *buffer1 = (unsigned char*)malloc(bufSize);

    if(!buffer1) return ENOMEM;
    int position = 0;
    while((bytesRead = fread(buffer1, 1, bufSize, file)))
    {
        SHA256_Update(&sha256, buffer1, bytesRead);
        position += bytesRead;
        if (bufSize < 32768) {
            break;
        }
        if (offset - position < 32768) {
            bufSize = offset - position;
            }
    }
    bytesRead = fread(buffer1, 1, 65, file);
    bufSize = 32768;
    bytesRead = fread(buffer1, 1, bufSize, file);
    SHA256_Update(&sha256, buffer1, bytesRead);

    SHA256_Final(hash, &sha256);
    static char output_Buffer[65];
    sha256_hash_string(hash, output_Buffer);
    fclose(file);
    free(buffer1);

    unsigned char hash1[SHA256_DIGEST_LENGTH];
    unsigned char *buffer2 = (unsigned char*)malloc(bufSize);
    file = fopen("/date_hash0", "rb");
    fd = open("/date_hash0", O_RDONLY);
    data = mmap(NULL, filesize(fd), PROT_READ, MAP_SHARED, fd, 0);
    elf = (Elf64_Ehdr *) data;
    shdr = (Elf64_Shdr *) ((uint8_t *)data + elf->e_shoff);
    strtab = (char *)((uint8_t *)data + shdr[elf->e_shstrndx].sh_offset);

    offset = mydata_offset(shdr, strtab, elf->e_shnum, (uint8_t*)data);
    close(fd);
    position = 0;
    while((bytesRead = fread(buffer2, 1, bufSize, file)))
    {
        SHA256_Update(&sha256, buffer2, bytesRead);
        position += bytesRead;
        if (bufSize < 32768) {
            break;
        }
        if (offset - position < 32768) {
            bufSize = offset - position;
            }
    }
    bytesRead = fread(buffer2, 1, 65, file);
    bufSize = 32768;
    bytesRead = fread(buffer2, 1, bufSize, file);
    SHA256_Update(&sha256, buffer1, bytesRead);
    static char output_Buffer1[65];
    SHA256_Final(hash1, &sha256);
    sha256_hash_string(hash, output_Buffer1);
    //fclose(file);

    free(buffer2);

    fclose(file);
//    system("cp ~/qt_projects/test2/date /date1");

    return 0;
}
