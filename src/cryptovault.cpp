/*
* CryptoVault.cpp
* CryptoVault File Locker
*
* Author: Mohammad Ghasembeigi
* URL: http://mohammadg.com
*/

#include <iostream>
#include <openssl/aes.h>

#define DEBUG
#pragma warning(disable:4996)

int main(int argc, char *argv[])
{
  int bytes_read, bytes_written;
  unsigned char indata[AES_BLOCK_SIZE*2];
  unsigned char outdata[AES_BLOCK_SIZE*2];

  /* ckey and ivec are the two 128-bits keys necesary to
  en- and recrypt your data.  Note that ckey can be
  192 or 256 bits as well */
  unsigned char ckey[] = "thiskeyisverybadthiskeyisverybad";
  unsigned char ivec[] = "dontusethisinput";

  /* data structure that contains the key itself */
  AES_KEY key;

  /* set the encryption key */
  AES_set_encrypt_key(ckey, 256, &key);

  /* set where on the 128 bit encrypted block to begin encryption*/
  int num = 0;

  FILE *ifp = fopen("test_enc.png", "rb");
  FILE *ofp = fopen("test_orig.png", "wb");

  while (true) {
    bytes_read = fread(indata, 1, AES_BLOCK_SIZE*2, ifp);

    AES_cfb128_encrypt(indata, outdata, bytes_read, &key, ivec, &num, 
      AES_DECRYPT); //or AES_DECRYPT

    bytes_written = fwrite(outdata, 1, bytes_read, ofp);
    if (bytes_read < AES_BLOCK_SIZE*2) {
      std::cout << bytes_read << std::endl;
      break;
    }
  }

  fclose(ifp);
  fclose(ofp);

  std::cout << "END";

#ifdef DEBUG
  std::cin.get();
  std::cin.ignore();
#endif

  return EXIT_SUCCESS;
}
