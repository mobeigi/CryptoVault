/*
* FileWriter.h
* Writes the cryptovault file header for an encrypted file.
*
* Author: Mohammad Ghasembeigi
* URL: http://mohammadg.com
*
* File Header Information:
* CV1~ [14 bytes, identifies Cryptovault program and version number]
* Header IV [16 bytes, unencrypted IV to decrypt file]
* Data Key [32 bytes, encrypted]
* Data IV [16 bytes, encrypted]
* Data Tag [16 bytes]
* Filesize [8 bytes, file size]
* Encrypted Data [X bytes, encrypted file contents]
* Encrypted Data Tag [16 bytes]
*
* Total Byte Size: 118 bytes + file size
*/

#ifndef __CryptoVault_FileWriter__
#define __CryptoVault_FileWriter__

#include <fstream>
#include <string>

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
    bool FileWriter::encryptFile(std::ifstream &ifs, std::ofstream &ofs, std::string masterKey);


    /*
    * Function that will parse the cryptovault encrypted file and decrypt it
    */
    bool FileWriter::decryptFile(std::ifstream &ifs, std::ofstream &ofs, std::string masterKey);

  private:
    const std::string cryptovaultTag = "CRYPTOVAULT10~";
  };


}

#endif