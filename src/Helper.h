/*
* AES_Locker.h
* Allow encryption/decryption of arbitary size files
*
* Author: Mohammad Ghasembeigi
* URL: http://mohammadg.com
*/

#ifndef __CryptoVault_Helper__
#define __CryptoVault_Helper__

#include "openssl\sha.h"
#include <sstream>
#include <iomanip>
#include <fstream>

namespace CV
{
  /*
  * Produces the 32-length SHA256 hash of input string
  */
  static std::string sha256_ascii(const std::string plaintext)
  {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, plaintext.c_str(), plaintext.size());
    SHA256_Final(hash, &sha256);

    return std::string(hash, hash + SHA256_DIGEST_LENGTH);
  }

  /*
  * Produces the 64-length SHA256 hash of input string expressed in hex
  */
  static std::string sha256_hex(const std::string plaintext)
  {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, plaintext.c_str(), plaintext.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
      ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return ss.str();
  }

  /*
  * Get file size
  */
  static std::ifstream::pos_type getFilesize(const char* filename)
  {
    std::ifstream in(filename, std::ifstream::ate | std::ifstream::binary);
    return in.tellg();
  }
}

#endif