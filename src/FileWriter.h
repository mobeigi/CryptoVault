/*
* FileWriter.h
* Writes the cryptovault file header for an encrypted file.
*
* Author: Mohammad Ghasembeigi
* URL: http://mohammadg.com
*
* File Header Information (size and offsets):
* 0x00 CRYPTOVAULT__~ string [14 bytes, identifies Cryptovault program and version number]
* 0x0E Header IV [16 bytes, unencrypted IV to decrypt file]
* 0x1E Data Key [32 bytes, encrypted]
* 0x3E Data IV [16 bytes, encrypted]
* 0x4E Data Tag [16 bytes]
* 0x5E Filesize [8 bytes, little endian, file size of original file]
* 0x66 Encrypted Data [X bytes, encrypted file contents]
* 0x__ Encrypted Data Tag [16 bytes]
*
* Total Byte Size: 118 bytes + file size
*/

#ifndef __CryptoVault_FileWriter__
#define __CryptoVault_FileWriter__

#include <fstream>
#include <string>

#define IDENTIFIERTAGSIZE 14
#define HEADERIVECSIZE 16
#define DATAKEYSIZE 32
#define DATAIVECSIZE HEADERIVECSIZE
#define DATATAGSIZE 16
#define ENCDATATAGSIZE DATATAGSIZE
#define FILESIZENUMBYTES 8

//CV (cryptovault) namespace
namespace CV
{
  /*
  * FileWriter class which stores some important constants and methods to write and parse headers
  */
  class FileWriter {
  public:
    FileWriter::FileWriter() {};


    /*
    * Function that will write the file header and encrypted file contents
    */
    bool FileWriter::encryptFile(std::string inputFile, std::string outputFile, std::string masterKey);


    /*
    * Function that will parse the cryptovault encrypted file and decrypt it
    */
    bool FileWriter::decryptFile(std::string inputFile, std::string outputFile, std::string masterKey);

  private:
    const std::string cryptovaultTag = "CRYPTOVAULT10~";
  };


}

#endif