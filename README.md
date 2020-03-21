# aes_crypt 

## Introduction

aes_crypt is a library for Dart and Flutter developers
that uses 256-bit AES algorithm to encrypt/decrypt files and binary data. 
It is fully compatible with the 
[AES Crypt file format](https://www.aescrypt.com/aes_file_format.html).
It can be used to integrate AES Crypt functionality into your own Dart or Flutter applications.

This library writes and reads version 2 (latest) of the AES Crypt file specification. Backwards compatibility 
with reading the version 1 is implemented but untested. 
Output .aes files are fully compatible with any software using the AES Crypt standard file format.
This library is accompanied by clients and libraries for different operating systems
and programming languages.
For more information about AES Crypt and AES Crypt compatible 
applications for other platforms, please visit [AESCrypt's official website](https://www.aescrypt.com).  
 
## Features

- 256-bit AES encryption format.
- File-to-file encryption and decryption.
- Memory-to-file encryption, file-to-memory decryption.
- Password can be in Unicode (like "密碼 パスワード пароль كلمة السر").
- Support for asynchronous file system reading/writing.
- Encrypted files have .aes extension which clients on other operating systems recognize.
- Compatible software available for Windows, Linux, Mac OS, Android and iOS 
(https://www.aescrypt.com/download/).

## Usage

Notice: All functions having 'Sync' at the end of their names are synchronous.
If you need asynchronous ones, please just remove 'Sync' from the end of function name.

Add import:
```dart
import 'dart:typed_data';
import 'package:aes_crypt/aes_crypt.dart';
```

Initialization:
```dart
var crypt = AesCrypt('my cool password');
```
or
```dart
var crypt = AesCrypt();
crypt.setPassword('my cool password');
```

Optionally you can set overwrite mode for the file write operations:
```dart
// Overwrite the file if it exists.
crypt.setOverwriteMode(AesCryptOwMode.on);

// If the file exists, thrown an exception 'AesCryptException' with the 'type' property
// set as 'AesCryptExceptionType.destFileExists' (see example1.dart in 'example' folder).
// It is default mode.
crypt.setOverwriteMode(AesCryptOwMode.warn);

// If the file exists, adds index '(1)' to its' name and tries to save. If such file also 
// exists, adds '(2)' to its name, then '(3)', etc. 
crypt.setOverwriteMode(AesCryptOwMode.rename);
```

File encryption/decryption:
```dart
// Encrypts the file srcfile.txt and saves encrypted file under original name with '.aes'
// extention added (srcfile.txt.aes). You can specify relative or direct path to it.
// To save the file into current directory specify it either as './srcfile.txt' or as 'srcfile.txt'.
crypt.encryptFileSync('srcfile.txt');

// Encrypts the file srcfile.txt and saves encrypted file under the name enc_file.txt.aes
crypt.encryptFileSync('srcfile.txt', 'enc_file.txt.aes');

// Decrypts the file srcfile.txt.aes and saves decrypted file under the name srcfile.txt
crypt.decryptFileSync('srcfile.txt.aes');

// Decrypts the file srcfile.txt.aes and saves decrypted file under the name dec_file.txt
crypt.decryptFileSync('srcfile.txt.aes', 'dec_file.txt');
```

String encryption/decryption:
```dart
String decryptedString;

// String to be encrypted
String srcString = 'some string';

// Encrypts the string as UTF8 string and saves it into 'mytext.txt.aes' file.
crypt.encryptStringToFileSync(srcString, 'mytext.txt.aes');

// Encrypts the string as UTF16 Big Endian string and saves it into 'mytext.txt.aes' file.
crypt.encryptStringToFileSync(srcString, 'mytext.txt.aes', , utf16: true);

// Decrypt the file and interprets it as UTF8 string
decryptedString = crypt.decryptStringFromFileSync('mytext.txt.aes');

// Decrypt the file and interprets it as UTF16 string in Big Endian order
decryptedString = crypt.decryptStringFromFileSync('mytext.txt.aes', utf16: true);
```

Binary data encryption/decryption:
```dart
// Binary data to be encrypted
Uint8List srcData = Uint8List.fromList([1,2,3,4,5]);

// Encrypts the data and saves it into mydata.bin.aes file.
crypt.encryptDataToFileSync(srcData, 'mydata.bin.aes');

// Decrypt the data from 'mydata.bin.aes' file
Uint8List decryptedData = crypt.decryptDataFromFileSync('mydata.bin.aes');
```

AES encryption/decryption:
```dart
// The encryption key. It should be 128, 192 or 256 bits long.
Uint8List key = Uint8List.fromList([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]); // 128 bits

// The initialization vector used in advanced cipher modes. It must be 128 bits long.
Uint8List iv = Uint8List.fromList([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]);

// The block cipher mode of operation. It can be one of the next values:
//    AesMode.ecb - ECB (Electronic Code Book)
//    AesMode.cbc - CBC (Cipher Block Chaining)
//    AesMode.cfb - CFB (Cipher Feedback)
//    AesMode.ofb - OFB (Output Feedback)
// By default the mode is AesMode.cbc
AesMode mode = AesMode.cbc; // Ok. I know it's meaningless here.

// Sets the encryption key and IV.
crypt.aesSetKeys(key, iv);
// Sets cipher mode
crypt.aesSetMode(mode);

// If you wish you can set the key, IV and cipher mode in one function.
//crypt.aesSetParams(key, iv, mode);

// The binary data to be encrypted
Uint8List srcData = Uint8List.fromList([1,2,3,4,5]);

// Encrypts the data. Padding scheme - null byte (0x00).
Uint8List encryptedData = crypt.aesEncrypt(srcData);
// Decrypts the data
Uint8List decryptedData = crypt.aesDecrypt(encryptedData);
```

SHA256 and HMAC-SHA256 computation:
```dart
// The source data
Uint8List srcData = Uint8List.fromList([1,2,3,4,5,6,7,8,9]);

// Computes SHA256 hash
Uint8List hash = crypt.sha256(srcData);

// Secret cryptographic key for HMAC
Uint8List key = Uint8List.fromList([1,2,3]);

// Computes HMAC-SHA256 code
Uint8List hmac = crypt.hmacSha256(key, srcData);
```


## Future plans

- reducing the memory usage for large file processing
- asynchronous encrypting/decrypting
- support streams
- support for key files

## Support

Please file feature requests and bugs at the [issue tracker][tracker].

[tracker]: http://example.com/issues/replaceme

## Acknowledgments

- to Phil Nicholls for [PHP-AES-File-Encryption library](https://github.com/philios33/PHP-AES-File-Encryption) 
- to IgoAtM for [PHP aesCrypt complient class](https://forums.packetizer.com/viewtopic.php?f=72&t=403)
- to author of [phpAES](http://www.phpaes.com) library ([github](https://github.com/phillipsdata/phpaes))
- to authors of [phpseclib](http://phpseclib.sourceforge.net/) ([github](https://github.com/phpseclib/phpseclib))
- to Steven Roose for [pointycastle](https://pub.dev/packages/pointycastle) Dart library ([github](https://github.com/PointyCastle/pointycastle))
