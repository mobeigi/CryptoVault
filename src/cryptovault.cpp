/*
* CryptoVault.cpp
* CryptoVault File Locker
*
* Author: Mohammad Ghasembeigi
* URL: http://mohammadg.com
*/

#include <iostream>
#include "AES_Locker.h"

#define DEBUG
#pragma warning(disable:4996)

int main(int argc, char *argv[])
{
  CV::AESLocker<256> AESLocker("thiskeyisverybadthiskeyisverybad", "dontusethisinput");
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
