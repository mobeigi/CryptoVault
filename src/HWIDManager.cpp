/*
* HWIDManager.cpp
* Allow generation of a unique identifer for running machine.
*
* Author: Mohammad Ghasembeigi
* URL: http://mohammadg.com
*/

#include "HWIDManager.h"

#include <windows.h>
#include <atlbase.h>
#include <atlstr.h>
#include <comutil.h>
#include <WbemIdl.h>
#include <iostream>

# pragma comment(lib, "wbemuuid.lib")

namespace CV
{
  void HWIDManager::generateHWID() {
    CString strResult;
    try
    {
      // 1. Initialize COM 
      // http://msdn.microsoft.com/en-us/library/windows/desktop/aa390885(v=vs.85).aspx
      HRESULT hr = ::CoInitializeEx(0, COINIT_MULTITHREADED);

      ATLENSURE_SUCCEEDED(hr);

      UINT nDriveNumber = 0; //get primary drive
      this->getHWIDComponents();
    }
    catch (CAtlException& e)
    {
      std::cerr << "Error: Unable to initlize COM for WMI queries.";
      exit(1);
    }

    // Uninitialize COM
    CoUninitialize();

    //Set HWID to concatenation of each HWID component
    this->hwid = this->CPUProcessorID + this->HDDSerialNumber;
  }

  void HWIDManager::getHWIDComponents() {
    // Format physical drive path (may be '\\.\PhysicalDrive0', '\\.\PhysicalDrive1' and so on).
    CString strDrivePath;
    strDrivePath.Format(_T("\\\\.\\PhysicalDrive%u"), 0);

    // Set the default process security level 
    // http://msdn.microsoft.com/en-us/library/windows/desktop/aa393617(v=vs.85).aspx
    HRESULT hr = ::CoInitializeSecurity(
      NULL,                        // Security descriptor    
      -1,                          // COM negotiates authentication service
      NULL,                        // Authentication services
      NULL,                        // Reserved
      RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication level for proxies
      RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation level for proxies
      NULL,                        // Authentication info
      EOAC_NONE,                   // Additional capabilities of the client or server
      NULL);                       // Reserved

    ATLENSURE_SUCCEEDED(hr);

    // Create a connection to WMI namespace
    // http://msdn.microsoft.com/en-us/library/windows/desktop/aa389749(v=vs.85).aspx
    //Initialize the IWbemLocator interface
    CComPtr<IWbemLocator> pIWbemLocator;
    hr = ::CoCreateInstance(CLSID_WbemLocator, 0,
      CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pIWbemLocator);

    ATLENSURE_SUCCEEDED(hr);

    // Call IWbemLocator::ConnectServer for connecting to WMI 
    CComPtr<IWbemServices> pIWbemServices;
    hr = pIWbemLocator->ConnectServer(L"ROOT\\CIMV2",
      NULL, NULL, 0, NULL, 0, 0, &pIWbemServices);

    ATLENSURE_SUCCEEDED(hr);

    // Set the security levels on WMI connection
    // http://msdn.microsoft.com/en-us/library/windows/desktop/aa393619(v=vs.85).aspx
    hr = ::CoSetProxyBlanket(
      pIWbemServices,
      RPC_C_AUTHN_WINNT,
      RPC_C_AUTHZ_NONE,
      NULL,
      RPC_C_AUTHN_LEVEL_CALL,
      RPC_C_IMP_LEVEL_IMPERSONATE,
      NULL,
      EOAC_NONE);

    ATLENSURE_SUCCEEDED(hr);

    // Execute a WQL (WMI Query Language) query to get physical media info
    const BSTR szQueryLanguage = L"WQL";
    const BSTR szQuery = L"SELECT Tag, SerialNumber FROM Win32_PhysicalMedia";

    CComPtr<IEnumWbemClassObject> pIEnumWbemClassObject;
    hr = pIWbemServices->ExecQuery(
      szQueryLanguage,                                       // Query language
      szQuery,                                               // Query
      WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,   // Flags
      NULL,                                                  // Context
      &pIEnumWbemClassObject);                               // Enumerator

    ATLENSURE_SUCCEEDED(hr);

    // Get each enumerator element until find the desired physical drive 
    ULONG uReturn = 0;
    while (pIEnumWbemClassObject)
    {
      CComPtr<IWbemClassObject> pIWbemClassObject;
      hr = pIEnumWbemClassObject->Next(WBEM_INFINITE, 1, &pIWbemClassObject, &uReturn);
      if (0 == uReturn || FAILED(hr))
        break;

      variant_t vtTag;           // unique tag, e.g. '\\.\PHYSICALDRIVE0'
      variant_t vtresult;  // manufacturer-provided serial number

      hr = pIWbemClassObject->Get(L"Tag", 0, &vtTag, NULL, NULL);
      ATLENSURE_SUCCEEDED(hr);

      CString strTag(vtTag.bstrVal);

      if (!strTag.CompareNoCase(strDrivePath)) { // physical drive found
        hr = pIWbemClassObject->Get(L"SerialNumber", 0, &vtresult, NULL, NULL);

        ATLENSURE_SUCCEEDED(hr);
        CString wmiResult = vtresult.bstrVal;
        this->HDDSerialNumber = wmiResult.GetString();
        break;
      }
    }

    // Execute a WQL (WMI Query Language) query to get processor info
    const BSTR szQuery2 = L"SELECT ProcessorID FROM Win32_Processor";

    CComPtr<IEnumWbemClassObject> pIEnumWbemClassObject2;
    hr = pIWbemServices->ExecQuery(
      szQueryLanguage,                                       // Query language
      szQuery2,                                               // Query
      WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,   // Flags
      NULL,                                                  // Context
      &pIEnumWbemClassObject2);                               // Enumerator

    ATLENSURE_SUCCEEDED(hr);

    //Get CPU device
    ULONG uReturn2 = 0;
    
    CComPtr<IWbemClassObject> pIWbemClassObject;
    hr = pIEnumWbemClassObject2->Next(WBEM_INFINITE, 1, &pIWbemClassObject, &uReturn2);
   
    variant_t vtresult;  // will hold processor id

    hr = pIWbemClassObject->Get(L"ProcessorID", 0, &vtresult, NULL, NULL);

    ATLENSURE_SUCCEEDED(hr);
    CString wmiResult = vtresult.bstrVal;
    this->CPUProcessorID = wmiResult.GetString();
    
  }

}