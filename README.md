CryptoVault File Locker
===========
CryptoVault is a replica of ransomware malware software (such as CryptoLocker) created ONLY FOR EDUCATIONAL PURPOSES.
Please read the disclaimer.

Version
----
1.0

CryptoVault 1.0 Encrypted File Format
----

| Offset Hex    | Offset Dec    | Size  | Header Name | Data Interpretation  | Purpose  |
| ---------- |:-----------:| :-----:|  :-----:|  :-----:| :-----    |
| 00      | 0 | 14 bytes | CVIDENTITY | string | Identifier tag which identifies CryptoVault program and version number. The identifier tag is the string "CRYPTOVAULT**NN**~" where NN represents the software version. The first digit represents the major version and the second digit represents the minor version. For example, 10 identifies version 1.0 |
| 0E     | 14      |   16 bytes | CVHEADERIV| unencrypted bits | Randomly generated header initialization vector for file.|
| 1E | 30      |  32 bytes | CVDATAKEY|  encrypted bits | Randomly generated data key which has been encrypted using master key and CVHEADERIV.|
| 3E | 62      |  16 bytes | CVDATAIV | encrypted bits | Randomly generated data initialization vector which has been encrypted using master key and CVHEADERIV.|
| 4E | 78      |  16 bytes | CVDATATAG | integrity tag | Tag generated as a result of encryption of CVDATAKEY and CVDATAIV.|
| 5E | 94      |  8 bytes | CVFILESIZE | little endian stored bits | File size of original unencrypted file.|
| 66 | 102      |  N bytes | CVENCRYPTEDDATA| encrypted data | N bytes of encrypted data where N is equivalent to CVFILESIZE. |
| 66 + N | 102 + N      |  16 bytes | CVENCRYPTEDDATATAG | integrity tag | Tag generated as a result of encryption of CVENCRYPTEDDATA.|

**Total size of encrypted file:** 118 bytes + N bytes (where N is the file size of the original unencrypted file).

Disclaimer
----
TBA

License
----
All rights reserved.
