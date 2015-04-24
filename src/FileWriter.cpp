/*
* HWIDManager.cpp
* Writes the cryptovault file header for an encrypted file.
*
* Author: Mohammad Ghasembeigi
* URL: http://mohammadg.com
*/

#include "FileWriter.h"
#include "AES_Locker.h"

#include <cassert>
#include <osrng.h>

namespace CV
{
  bool FileWriter::encryptFile(std::ifstream &ifs, std::ofstream &ofs, std::string masterKey) {
    //Write cryptovault identifier tag [14 bytes]
    assert(cryptovaultTag.size() == 14);
    ofs << this->cryptovaultTag;

    //Write header IV for this file, unencrypted [16 bytes]
    byte headerIV[16];
    CryptoPP::AutoSeededRandomPool headerIVPrng;
    headerIVPrng.GenerateBlock(headerIV, sizeof(headerIV));

    for (size_t i = 0; i < 16; ++i)
      ofs << headerIV[i];

    //Write data key + data ivec + data tag [32+16+16 = 64 bytes]
    std::string headerIVStr;
    headerIVStr.reserve(16);
    headerIVStr.assign(headerIV, headerIV + 16);

    //Create AES locker for this file using master key + randomly generated IV for this file
    CV::AESLocker<256> AESLocker(masterKey, headerIVStr);

    //Randomly generate a 48 byte block of data
    //We will use the first 32 bytes of this block as the data key
    //And the remaining 16 bytes as the ivec key
    byte dataBlock[48];
    CryptoPP::AutoSeededRandomPool dataBlockPrng;
    dataBlockPrng.GenerateBlock(dataBlock, sizeof(dataBlock));

    byte encDataBlock[48 + 16]; //encrypted block with tag size
    AESLocker.encrypt_bytearray(dataBlock, 48, encDataBlock);

    for (size_t i = 0; i < (48 + 16); ++i)
      ofs << encDataBlock[i];

    //Write Filesize [8 bytes]
    //Dummy data for now
    byte dummyFileSize[8] = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };

    for (size_t i = 0; i < 8; ++i)
      ofs << encDataBlock[i];

    //Get data key and data ivec from datablock
    byte dataKey[32];
    byte dataIvec[16];
    memcpy(dataKey, dataBlock, 32);
    memcpy(dataKey, dataBlock + 32, 16);

    std::string dataKeyStr;
    std::string dataIvecStr;
    dataKeyStr.assign(dataKey, dataKey + 32);
    dataIvecStr.assign(dataIvec, dataIvec + 16);

    //Greate new AES object to encrypt actual file contents with
    CV::AESLocker<256> DataLocker(dataKeyStr, dataIvecStr);

    //Write encrypted data + tag [X bytes + 16 bytes]
    DataLocker.encrypt_file(ifs, ofs);

    return true;
  }


  bool FileWriter::decryptFile(std::ifstream &ifs, std::ofstream &ofs, std::string masterKey) {

    //Check for cryptovault identifier tag
    char readCryptovaultTag[15];
    ifs.read(readCryptovaultTag, 14);
    readCryptovaultTag[14] = '\0';

    //If file tag is missing, do not decrypt file
    if (strcmp(readCryptovaultTag, this->cryptovaultTag.c_str()) != 0) {
      return false;
    }
    
    //Read public IV generated for this file
    byte headerIV[16];
    ifs.read((char *)headerIV, 16);

    std::string headerIVStr;
    headerIVStr.reserve(16);
    headerIVStr.assign(headerIV, headerIV + 16);

    //Get encrypted data key + data ivec + data tag block [32+16+16 = 64 bytes]
    //We will have to unencrypt this to get our actual data key + data ivec
    byte encryptedDataBlock[64];
    ifs.read((char *)encryptedDataBlock, 64);

    //Read file size (ignore for now)
    ifs.ignore(8);

    //Create AES locker for this file using master key + randomly generated IV for this file
    CV::AESLocker<256> AESLocker(masterKey, headerIVStr);

    byte dataBlock[48];
    AESLocker.decrypt_bytearray(encryptedDataBlock, 64, dataBlock);

    //Check for integrity
    if (!AESLocker.GetLastResult())
      return false;

    //Convert data block into data key and data ivec (so we can decrypt file contents)
    byte dataKey[32];
    byte dataIvec[16];
    memcpy(dataKey, dataBlock, 32);
    memcpy(dataKey, dataBlock + 32, 16);

    std::string dataKeyStr;
    std::string dataIvecStr;
    dataKeyStr.assign(dataKey, dataKey + 32);
    dataIvecStr.assign(dataIvec, dataIvec + 16);

    //Greate new AES object to encrypt actual file contents with
    CV::AESLocker<256> DataUnLocker(dataKeyStr, dataIvecStr);

    //Decrypt encrypted data
    DataUnLocker.decrypt_file(ifs, ofs);

    return DataUnLocker.GetLastResult();
  }
}