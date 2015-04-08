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

#define DEBUG

#pragma warning(disable:4996)

int main(int argc, char *argv[])
{
  //Gather a HWID
  CV::HWIDManager hwidm;
  hwidm.generateHWID(); //generate HWID for this machine

  //Get sha256 hash of HWID in ascii form (sequence of unsigned chars)
  std::string hashedHWID = CV::sha256_ascii(hwidm.hwid);
  assert(hashedHWID.size() == SHA256_DIGEST_LENGTH);

  //Create 256bit AES locker with sha256 HWID hash as ckey
  CV::AESLocker<256> AESLocker(hashedHWID, "dontusethisinput");
  AESLocker.set_encrypt_key();

  std::ifstream ifs("test.wmv", std::ifstream::binary);
  std::ofstream ofs("test_out.wmv", std::ifstream::binary);
  AESLocker.encrypt_file(ifs, ofs);
  ifs.close();
  ofs.close();

  ifs = std::ifstream("test_out.wmv", std::ifstream::binary);
  ofs = std::ofstream("test_orig.wmv", std::ifstream::binary);
  AESLocker.decrypt_file(ifs, ofs);
  ifs.close();
  ofs.close();
  

#ifdef DEBUG
  std::cin.get();
  std::cin.ignore();
#endif

  return 0;
}
