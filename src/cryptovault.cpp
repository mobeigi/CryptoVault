/*
* CryptoVault.cpp
* CryptoVault File Locker
*
* Author: Mohammad Ghasembeigi
* URL: http://mohammadg.com
*/

#include <iostream>
#include "AES_Locker.h"
#include "HWIDManager.h"
#include "Helper.h"
#include <cassert>

#include <osrng.h>

#define FILE_HEADER_TAG "CRYPTOVAULT~"

#pragma warning(disable:4996)

int main(int argc, char *argv[])
{
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
  CV::AESLocker<256> AESLocker(hashedKey, ivecStr);

  std::ifstream ifs("test.wmv", std::ifstream::binary);
  std::ofstream ofs("test_out.wmv", std::ifstream::binary);

  //Output CRYPTOVAULT Tag to beginning of encrypted file
  ofs << FILE_HEADER_TAG;

  AESLocker.encrypt_file(ifs, ofs);
  ifs.close();
  ofs.close();
 
  
  std::ifstream ifs2 = std::ifstream("test_out.wmv", std::ifstream::binary);
  std::ofstream ofs2 = std::ofstream("test_orig.wmv", std::ifstream::binary);

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
  

#ifdef _DEBUG
  std::cin.get();
  std::cin.ignore();
#endif

  return 0;
}
