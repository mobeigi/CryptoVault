/*
* HWIDManager.h
* Allow generation of a unique identifer for running machine.
*
* Author: Mohammad Ghasembeigi
* URL: http://mohammadg.com
*/

#ifndef __CryptoVault_HWIDManager__
#define __CryptoVault_HWIDManager__

#include <string>

//CV (cryptovault) namespace
namespace CV
{  
   /*
   * HWIDManager class stored HWID components as well as combined HWID for running machine
   */
  class HWIDManager {
  public:
    HWIDManager::HWIDManager() {};

    /*
    * Generate HWID for running machine by querying WMI
    */
    void HWIDManager::generateHWID();

    /*
    * The resultant hwid string.
    * This string is the concatenation of each HWID component
    */
    std::string hwid;

    /*
    * The CPU Processor ID. This will NOT be unique amongst CPUs of the same brand and model.
    */
    std::string CPUProcessorID;

    /*
    * The manufacturer serial number of the primary storage disk on the machine. 
    */
    std::string HDDSerialNumber;

  private:
    /*
    * Makes actual calls to WMI to find values for each HWID component
    */
    void getHWIDComponents();
  };
}

#endif