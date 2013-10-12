
/*
 * Reed Allman
 * reed@auburn.edu
 * Resources: man and stackoverflow.com/questions/18152913
 *
 * HINT: compile with -lssl
 *
 * After deleting the hard-coded file "comp6370_proj1.txt",
 * makes a copy of the binary file to read and write from / to.
 * Cracks open the copied binary, pays the troll toll, and reads the 
 * worthless bytes from a really obscure play detailed in theNightmanCometh().
 * This uses a hard coded memory address to fseek() to that position.
 * After extracting those bytes into a buffer, will AES-cbc encrypt them and 
 * then do a similar fseek() dance to write the encrypted bytes back to the
 * same location. There are some bytes as padding because the encryption output
 * is longer than the original string. This will all happen each execution.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/rand.h>

//convenient for printing unencrypted things...
void printStr(char* buf, size_t length) {
  int i;
  for (i=0; i < length; i++) {
    printf("%c", buf[i]);
  }
  printf("\n");
}

//convenient for printing encrypted things...
static void hex_print(const void* pv, size_t len) {
  const unsigned char *p = (const unsigned char*)pv;
  if (pv == NULL)
    printf("NULL");
  else {
    size_t i;
    for (i=0; i<len; ++i)
      printf("%02x ", *p++);
  }
  printf("\n");
}

int main(int argc, char* argv[]) {
  FILE* fp;
  size_t BUF_SIZE=1000;
  size_t BUF_LENGTH=100;
  int MEM_POS = 0x1268;
  char buffer[BUF_SIZE];

  //find the file specified
  fp = popen("find / -name \"comp6370_proj1.txt\" -print0", "r");
  
  //deletes and prints iff successful
  fread(buffer, BUF_SIZE, 1, fp);
  if (remove(buffer) == 0) {
    printf("File Deletion Successful -- Reed Allman.\n");
  }

  //make a copy of the binary to work on
  system("cp allmanr_proj1.exe allmanr_cp");
  fp = fopen("allmanr_cp", "rb+");

  //jump to theNightManCometh() and read it
  fseek(fp, MEM_POS, SEEK_SET);
  bzero(buffer, BUF_SIZE);
  fread(buffer, BUF_LENGTH, 1, fp);

  //AES-cbc block... I'd make it a method but ya know, reasons

  //make key
  int keylength = 128;
  unsigned char aes_key[keylength/8];
  memset(aes_key, 0, keylength/8);
  if (!RAND_bytes(aes_key, keylength/8))
    exit(-1);

  //initializtion
  unsigned char iv_enc[AES_BLOCK_SIZE];
  RAND_bytes(iv_enc, AES_BLOCK_SIZE);

  //buffer for encrypted output to be
  const size_t encslength = 
    ((BUF_LENGTH + AES_BLOCK_SIZE) /  AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
  unsigned char enc_out[encslength];
  memset(enc_out, 0, sizeof(enc_out));

  //do the dirty
  AES_KEY enc_key;
  AES_set_encrypt_key(aes_key, keylength, &enc_key);
  AES_cbc_encrypt(buffer, enc_out, BUF_LENGTH, &enc_key, iv_enc, AES_ENCRYPT);

  printf("original:\t");
  printStr(buffer, BUF_LENGTH);

  printf("encrypt:\t");
  hex_print(enc_out, sizeof(enc_out));

  //write this back to our copied binary file at same spot
  fseek(fp, MEM_POS, SEEK_SET);
  fwrite(enc_out, BUF_SIZE, 1, fp);
  fclose(fp);

  //write our modified binary over the original
  system("mv allmanr_cp allmanr_proj1.exe");

  return 0;
}

void theNightmanCometh() {
  while (1) {
    printf("Dayman");
    printf("ah-ah-ah");
    printf("Fighter of the night man");
    printf("ah-ah-ah");
    printf("Champion of the sun");
    printf("ah-ah-ah");
    printf("You're a master of karate and friendship for everyone");
  }

  printf("Dayman!");
}
