## aes_crypt

aes_crypt is a library for Dart and Flutter developers
that uses 256-bit AES algorithm to encrypt/decrypt files and binary data. 
It is fully compatible with the 
[AES Crypt file format](https://www.aescrypt.com/aes_file_format.html).

This library writes version 2 of the AES Crypt file specification. Backwards compatibility 
with the older two versions (reading old .aes files) is implemented but untested. 
Output .aes files are fully compatible with any software using the AES Crypt standard file format.
This library is accompanied by clients and libraries for different operating systems
and programming languages.

For more information about AES Crypt and AES Crypt compatible 
applications for other platforms, please visit [AESCrypt's official website](https://www.aescrypt.com).  
 
## Features

- 256-bit AES encryption format
- File-to-file encryption and decryption
- Memory-to-file encryption, file-to-memory decryption
- Password can be in Unicode (like "密碼 パスワード пароль كلمة السر" )
- Encrypted files have .aes extension which clients on other operating systems recognize
- Compatible software available for Windows, Linux, Mac OS, Android and iOS 
(http://www.aescrypt.com/download.html)

## Usage


## Future plans

- support asynchronous operations
- support streams
- support key files
- decrease memory consumption

## Bugs

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: http://example.com/issues/replaceme

## Acknowledgments

- to Phil Nicholls for [PHP-AES-File-Encryption library](https://github.com/philios33/PHP-AES-File-Encryption) 
- to IgoAtM for [PHP aesCrypt complient class](https://forums.packetizer.com/viewtopic.php?f=72&t=403)

I've used some ideas from these libraries for my implementation.
