/*
* AES_Locker.h
* Allow encryption/decryption of arbitary size files
* Uses the Crypto++ Library
* Author: Mohammad Ghasembeigi
* URL: http://mohammadg.com
*/

#ifndef __CryptoVault_AESLocker__
#define __CryptoVault_AESLocker__

#include <string>
#include <iostream>
#include <fstream>
#include "gcm.h"
#include "aes.h"
#include "files.h"


//CV (cryptovault) namespace
namespace CV
{
  /*
  * AES Locker class is used to encrypt and decrypt files
  */
  
  template <unsigned int N = 128>
  class AESLocker {
  public:

    //Default Constructor
    AESLocker() : ENCRYPTION_KEY_LENGTH(N) {
      static_assert(N == 128 || N == 192 || N == 256, "N must be either 128, 192 or 256.");
    }

    /*
    * Constructor used to initilise encryption key and initialization vector
    */
    AESLocker(std::string key, std::string ivec);

    /*
    * Delegating constructor which takes authenticationTagSize
    */
    AESLocker(std::string key, std::string ivec, size_t authenticationTagSize) : AESLocker(key, ivec) {
      this->TAG_SIZE = authenticationTagSize;
    };

    //Member Functions

    /*
    * Given a input file stream, encrypts a file using AES GCM mode and outputs result via output file stream
    */
    bool AESLocker::encrypt_file(std::ifstream &ifs, std::ofstream &ofs);

    /*
    * Given a byte array, encrypts contents and outputs result to output array
    */
    bool AESLocker::encrypt_bytearray(const byte *input, size_t inputSize, byte *output);

    /*
    * Given a input file stream, decrypts a file using AES GCM mode and outputs result via output file stream
    */
    bool AESLocker::decrypt_file(std::ifstream &ifs, std::ofstream &ofs);

    /*
    * Given a byte array, decrypts contents and outputs result to output array
    */
    bool AESLocker::decrypt_bytearray(const byte *input, size_t inputSize, byte *output);

    /*
    * Gets result of last decryption process
    */
    inline bool GetLastResult() { return this->INTEGRITY_OK; }

  private:
    int TAG_SIZE = 12; //default 12
    std::vector<byte> ivec;
    CryptoPP::SecByteBlock key; //encryption key
    size_t ENCRYPTION_KEY_LENGTH;
    bool INTEGRITY_OK = false;
  };

}

//Implementation is stored in the template file;
#include "AES_Locker.tem"

#endif