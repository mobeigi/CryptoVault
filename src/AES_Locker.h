/*
* AES_Locker.h
* Allow encryption/decryption of arbitary size files
*
* Author: Mohammad Ghasembeigi
* URL: http://mohammadg.com
*/

#ifndef __CryptoVault_AESLocker__
#define __CryptoVault_AESLocker__

#include <string>
#include <iostream>
#include <fstream>
#include <openssl/aes.h>

//CV (cryptovault) namespace
namespace CV
{
  /*
  * AES Locker class is used to encrypt and decrypt files using cfb128 standards.
  */
  
  template <unsigned int N = 128> 
  class AESLocker {
  public:
    //Contructor
    AESLocker::AESLocker(std::string ckey, std::string ivec) : ckey(ckey), ivec(ivec), ENCRYPTION_KEY_LENGTH(N) {
      static_assert(N == 128 || N == 192 || N == 256, "N must be either 128, 192 or 256.");
    }

    //Encryption

    /*
    * Sets encryption key to correct encryption type
    */
    int AESLocker::set_encrypt_key();

    /*
    * Given a input file stream, encrypts a file using AES cfb128 and outputs result via output file stream
    */
    bool AESLocker::encrypt_file(std::ifstream &ifs, std::ofstream &ofs);

    /*
    * Given a input file stream, decrypts a file using AES cfb128 and outputs result via output file stream
    */
    bool AESLocker::decrypt_file(std::ifstream &ifs, std::ofstream &ofs);

  private:
    std::string ckey;
    const std::string ivec;
    size_t ENCRYPTION_KEY_LENGTH;
    static const size_t FILE_BLOCK_SIZE = AES_BLOCK_SIZE;
    AES_KEY key;
  };

}

#endif

//Implementation is stored in the template file;
#include "AES_Locker.tem"