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

#pragma warning(disable:4996)

int main(int argc, char *argv[])
{
  //Gather a HWID
  CV::HWIDManager hwidm;
  hwidm.generateHWID(); //generate HWID for this machine

  //Get sha256 hash of HWID in ascii form (sequence of unsigned chars)
  std::string hashedHWID = CV::sha256_ascii(hwidm.hwid);
  assert(hashedHWID.size() == SHA256_DIGEST_LENGTH);

  //Generate unique (and random) ivec
  //The ivec will be 256 bytes long (or 2048 bits)
  std::string ivecStr;
  ivecStr.reserve(256);
  byte ivec[CryptoPP::AES::BLOCKSIZE * 16];

  CryptoPP::AutoSeededRandomPool prng;
  prng.GenerateBlock(ivec, sizeof(ivec));
  ivecStr.assign(ivec, ivec + sizeof(ivec));

  std::cout << ivecStr.size();

  //Create 256bit AES locker with sha256 HWID hash as ckey
  CV::AESLocker<256> AESLocker(hashedHWID, ivecStr);

  std::ifstream ifs("test.wmv", std::ifstream::binary);
  std::ofstream ofs("test_out.wmv", std::ifstream::binary);
  AESLocker.encrypt_file(ifs, ofs);
  ifs.close();
  ofs.close();
 
  
  std::ifstream ifs2 = std::ifstream("test_out.wmv", std::ifstream::binary);
  std::ofstream ofs2 = std::ofstream("test_orig.wmv", std::ifstream::binary);
  AESLocker.decrypt_file(ifs2, ofs2);
  ifs.close();
  ofs.close();

  std::cout << AESLocker.GetLastResult() << std::endl;
  

#ifdef _DEBUG
  std::cin.get();
  std::cin.ignore();
#endif

  return 0;
}
