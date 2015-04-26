/*
* HWIDManager.cpp
* Writes the cryptovault file header for an encrypted file.
*
* Author: Mohammad Ghasembeigi
* URL: http://mohammadg.com
*/

#include "FileWriter.h"
#include "AES_Locker.h"
#include "Helper.h"

#include <osrng.h>

namespace CV
{
  bool FileWriter::encryptFile(std::string inputFile, std::string outputFile, std::string masterKey) {
    //Get file size before opening file for encryption
    uint64_t fileSize = CV::getFilesize(inputFile.c_str());

    //Open file streams
    std::ifstream ifs(inputFile, std::ifstream::binary);
    std::ofstream ofs(outputFile, std::ifstream::binary);

    //Write cryptovault identifier tag [14 bytes]
    ofs << this->cryptovaultTag;

    //Write header IV for this file, unencrypted [16 bytes]
    byte headerIV[HEADERIVECSIZE];
    CryptoPP::AutoSeededRandomPool headerIVPrng;
    headerIVPrng.GenerateBlock(headerIV, sizeof(headerIV));

    for (size_t i = 0; i < HEADERIVECSIZE; ++i)
      ofs << headerIV[i];

    //Write data key + data ivec + data tag [32+16+16 = 64 bytes]
    std::string headerIVStr;
    headerIVStr.assign(headerIV, headerIV + HEADERIVECSIZE);

    //Create AES locker for this file using master key + randomly generated IV for this file
    CV::AESLocker<256> HeaderKeyIVLocker(masterKey, headerIVStr, DATATAGSIZE);

    //Randomly generate a 48 byte block of data
    //We will use the first 32 bytes of this block as the data key
    //And the remaining 16 bytes as the ivec key
    byte dataBlock[(DATAKEYSIZE + DATAIVECSIZE)];
    CryptoPP::AutoSeededRandomPool dataBlockPrng;
    dataBlockPrng.GenerateBlock(dataBlock, sizeof(dataBlock));

    byte encDataBlock[(DATAKEYSIZE + DATAIVECSIZE) + DATATAGSIZE]; //encrypted block with tag size
    HeaderKeyIVLocker.encrypt_bytearray(dataBlock, (DATAKEYSIZE + DATAIVECSIZE), encDataBlock);

    for (size_t i = 0; i < ((DATAKEYSIZE + DATAIVECSIZE) + DATATAGSIZE); ++i)
      ofs << encDataBlock[i];

    //Write Filesize [8 bytes]
    //Convert file size from 8 bit int to byte array
    std::vector<byte> fileSizeVec(FILESIZENUMBYTES);
    for (int i = 0; i < 8; i++)
      fileSizeVec[i] = (fileSize >> (i * 8));

    ofs.write((char *)fileSizeVec.data(), FILESIZENUMBYTES);

    //Get data key and data ivec from datablock
    byte dataKey[DATAKEYSIZE];
    byte dataIvec[DATAIVECSIZE];
    memcpy(dataKey, dataBlock, DATAKEYSIZE);
    memcpy(dataKey, dataBlock + DATAKEYSIZE, DATAIVECSIZE);

    std::string dataKeyStr;
    std::string dataIvecStr;
    dataKeyStr.assign(dataKey, dataKey + DATAKEYSIZE);
    dataIvecStr.assign(dataIvec, dataIvec + DATAIVECSIZE);

    //Greate new AES object to encrypt actual file contents with
    CV::AESLocker<256> DataLocker(dataKeyStr, dataIvecStr, ENCDATATAGSIZE);

    //Write encrypted data + tag [X bytes + 16 bytes]
    DataLocker.encrypt_file(ifs, ofs);

    ifs.close();
    ofs.close();

    return true;
  }


  bool FileWriter::decryptFile(std::string inputFile, std::string outputFile, std::string masterKey) {
    //Open file streams
    std::ifstream ifs(inputFile, std::ifstream::binary);
    std::ofstream ofs(outputFile, std::ifstream::binary);

    //Check for cryptovault identifier tag
    char readCryptovaultTag[IDENTIFIERTAGSIZE + 1];
    ifs.read(readCryptovaultTag, IDENTIFIERTAGSIZE);
    readCryptovaultTag[IDENTIFIERTAGSIZE] = '\0';

    //If file tag is missing, do not decrypt file
    if (strcmp(readCryptovaultTag, this->cryptovaultTag.c_str()) != 0) {
      return false;
    }
    
    //Read public IV generated for this file
    byte headerIV[HEADERIVECSIZE];
    ifs.read((char *)headerIV, HEADERIVECSIZE);

    std::string headerIVStr;
    headerIVStr.assign(headerIV, headerIV + HEADERIVECSIZE);

    //Get encrypted data key + data ivec + data tag block [32+16+16 = 64 bytes]
    //We will have to unencrypt this to get our actual data key + data ivec
    byte encryptedDataBlock[(DATAKEYSIZE + DATAIVECSIZE + DATATAGSIZE)];
    ifs.read((char *)encryptedDataBlock, (DATAKEYSIZE + DATAIVECSIZE + DATATAGSIZE));

    //Read file size of original file
    std::vector<byte> fileSizeVec(FILESIZENUMBYTES);
    ifs.read((char *)fileSizeVec.data(), FILESIZENUMBYTES);

    //Get file size (little endian)
    uint64_t fileSize = (fileSizeVec[7] << 56) | (fileSizeVec[6] << 48) | (fileSizeVec[5] << 40) | (fileSizeVec[4] << 32) |
                        (fileSizeVec[3] << 24) | (fileSizeVec[2] << 16) | (fileSizeVec[1] << 8) | (fileSizeVec[0]);

    //Create AES locker for this file using master key + randomly generated IV for this file
    CV::AESLocker<256> HeaderKeyIVLocker(masterKey, headerIVStr, DATATAGSIZE);

    byte dataBlock[(DATAKEYSIZE + DATAIVECSIZE)];
    HeaderKeyIVLocker.decrypt_bytearray(encryptedDataBlock, (DATAKEYSIZE + DATAIVECSIZE + DATATAGSIZE), dataBlock);

    //Check for integrity
    if (!HeaderKeyIVLocker.GetLastResult())
      return false;

    //Convert data block into data key and data ivec (so we can decrypt file contents)
    byte dataKey[DATAKEYSIZE];
    byte dataIvec[DATAIVECSIZE];
    memcpy(dataKey, dataBlock, DATAKEYSIZE);
    memcpy(dataKey, dataBlock + DATAKEYSIZE, DATAIVECSIZE);

    std::string dataKeyStr;
    std::string dataIvecStr;
    dataKeyStr.assign(dataKey, dataKey + DATAKEYSIZE);
    dataIvecStr.assign(dataIvec, dataIvec + DATAIVECSIZE);

    //Greate new AES object to encrypt actual file contents with
    CV::AESLocker<256> DataUnLocker(dataKeyStr, dataIvecStr, ENCDATATAGSIZE);

    //Decrypt encrypted data
    DataUnLocker.decrypt_file(ifs, ofs);

    //Close file streams
    ifs.close();
    ofs.close();

    return DataUnLocker.GetLastResult();
  }
}