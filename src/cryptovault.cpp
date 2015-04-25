/*
* CryptoVault.cpp
* CryptoVault File Locker
*
* Author: Mohammad Ghasembeigi
* URL: http://mohammadg.com
*/

#include <iostream>
#include "AES_Locker.h"
#include "FileWriter.h"
#include "HWIDManager.h"
#include "Helper.h"
#include <cassert>

#include <osrng.h>

#pragma warning(disable:4996)

int main(int argc, char *argv[])
{

  //Get master key (fixed)
  std::string masterKey = "55555555555555555555555555555555";

  //Make filewriter
  CV::FileWriter fw;
  fw.encryptFile("test.png", "test_out.png", masterKey);
  

  //**************************

  //Make filewriter
  CV::FileWriter fw2;
  fw2.decryptFile("test_out.png", "test_orig.png", masterKey);

  /*
  //Gather a HWID
  //This will be sent to along with keys to identify this machine
  CV::HWIDManager hwidm;
  hwidm.generateHWID(); //generate HWID for this machine

  //Generate random block
  //The salt should be at least the same length as the output hash function
  //For SHA256 this should be 256 bits.
  //We use 512 bits instead.
  CryptoPP::AutoSeededRandomPool prng_hwid;
  byte randBlock[512];
  prng_hwid.GenerateBlock(randBlock, sizeof(randBlock));
  assert(sizeof(randBlock) == 512);

  std::string randBlockStr(randBlock, randBlock + sizeof(randBlock));
  assert(randBlockStr.size() == 512);

  //Get sha256 hash of sequence of random 512 bits in ascii form (sequence of unsigned chars)
  std::string hashedKey = CV::sha256_ascii(randBlockStr);
  assert(hashedKey.size() == SHA256_DIGEST_LENGTH);

  //Generate unique (and random) ivec
  //The ivec will be 256 bytes long (or 2048 bits)
  std::string ivecStr;
  ivecStr.reserve(256);
  byte ivec[CryptoPP::AES::BLOCKSIZE * 16];

  CryptoPP::AutoSeededRandomPool prng;
  prng.GenerateBlock(ivec, sizeof(ivec));
  ivecStr.assign(ivec, ivec + sizeof(ivec));

  //Create 256bit AES locker with sha256 HWID hash as ckey
  //CV::AESLocker<256> AESLocker(hashedKey, ivecStr);

  std::ifstream ifs("test.txt", std::ifstream::binary);
  std::ofstream ofs("test_out.txt", std::ifstream::binary);

  //Output CRYPTOVAULT Tag to beginning of encrypted file
  //ofs << FILE_HEADER_TAG;

  //FOR TESTING
  std::string testkey = "11111111111111111111111111111111";
  std::string testivec = "1111111111111111";
  CV::AESLocker<256> AESLocker(testkey, testivec);

  //Generate random key + ivec
  byte dataKey[32] = {
    0x4e, 0x79, 0x4d, 0x08, 0x0c, 0x89, 0x2c, 0xcf, 0xb8, 0x3e, 0x7a, 0x73, 0x28, 0x19, 0xe8, 0xde,
    0x46, 0xfc, 0xb2, 0xf7, 0xac, 0xac, 0x70, 0x06, 0xf2, 0x2f, 0x9f, 0x6e, 0x00, 0x00, 0x00, 0x00
  };

  //CryptoPP::AutoSeededRandomPool dataKeyPrng;
  //dataKeyPrng.GenerateBlock(dataKey, sizeof(dataKey));

  for (size_t i = 0; i < 32; ++i)
    ofs << dataKey[i];


  ofs << "\n\n\n\n\n";




  byte dataIvec[128];
  CryptoPP::AutoSeededRandomPool dataIvecPrng;
  dataIvecPrng.GenerateBlock(dataIvec, sizeof(dataIvec));

  byte encdataKey[48] = { 0 };
  byte encdataIvec[128];
  AESLocker.encrypt_bytearray(dataKey, 32, encdataKey);
  //AESLocker.encrypt_bytearray(dataIvec, encdataIvec);

  for (size_t i = 0; i < 48; ++i)
    ofs << encdataKey[i];

  
  ofs << "\n\n\n\n\n";

  byte decdataKey[32];
  AESLocker.encrypt_bytearray(encdataKey, 48, decdataKey);

  for (size_t i = 0; i < 32; ++i)
    ofs << decdataKey[i];


  //AESLocker.encrypt_file(ifs, ofs);
  ifs.close();
  ofs.close();
 
  
  std::ifstream ifs2 = std::ifstream("test_out.txt", std::ifstream::binary);
  std::ofstream ofs2 = std::ofstream("test_orig.txt", std::ifstream::binary);

  //Read back cryptovault file tag
  char str[13];
  ifs2.read(str, 12);
  str[12] = '\0';

  //If file tag is missing, do not decrypt file
  if (strcmp(str, FILE_HEADER_TAG) != 0) {
    std::cerr << "Error: File tag missing.";
    return 1;
  }

  AESLocker.decrypt_file(ifs2, ofs2);
  ifs.close();
  ofs.close();

  
  std::cout << "Integrity: " << AESLocker.GetLastResult() << std::endl;
  */

#ifdef _DEBUG
  std::cin.get();
  std::cin.ignore();
#endif

  return 0;
}
