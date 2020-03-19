import 'dart:io';

import 'package:aes_crypt/aes_crypt.dart';

// Synchronous file encryption/decryption example

void main() {
  String srcFilepath = './example/testfile.txt';
  String encFilepath;
  String decFilepath;

  print('Unencrypted source file: $srcFilepath');
  print('File content: ' + File(srcFilepath).readAsStringSync() + '\n');

  // Create an instance of AesCrypt class.
  var crypt = AesCrypt();

  // Set password for encryption/decryption.
  // Optionally you can specify your password when creating an instance
  // of AesCrypt class like:
  // var crypt = AesCrypt('my cool password');
  crypt.setPassword('my cool password');

  // Set mode for file naming.
  // It's optional. By default the mode is 'AesCryptFnMode.auto'.
  crypt.setFilenamingMode(AesCryptFnMode.warn);

  try {
    // Encrypt './example/testfile.txt' file and save it to a file with an extension
    // '.aes' added. In this case it will be './example/testfile.txt.aes'.
    // It returns a path to encrypted file.
    encFilepath = crypt.encryptFileSync('./example/testfile.txt');
    print('The encryption has been completed successfully.');
    print('Encrypted file: $encFilepath');
  } on AesCryptException catch (e) {
    // It goes here if the file naming mode set as 'AesCryptFnMode.warn'
    // and encrypted file already exists.
    if (e.type == AesCryptExceptionType.destFileExists) {
      print('The encryption has been completed unsuccessfully.');
      print(e.message);
    }
    return;
  }

  print('');

  try {
    // Decrypt the file which has been just encrypted.
    // It returns a path to decrypted file.
    decFilepath = crypt.decryptFileSync(encFilepath);
    print('The decryption has been completed successfully.');
    print('Decrypted file 1: $decFilepath');
    print('File content: ' + File(decFilepath).readAsStringSync() + '\n');
  } on AesCryptException catch (e) {
    // It goes here if the file naming mode set as AesCryptFnMode.warn
    // and decrypted file already exists.
    if (e.type == AesCryptExceptionType.destFileExists) {
      print('The decryption has been completed unsuccessfully.');
      print(e.message);
    }
  }

  print('');

  try {
    // Decrypt the file to another name.
    decFilepath = crypt.decryptFileSync(encFilepath, './example/testfile_new.txt');
    print('The decryption has been completed successfully.');
    print('Decrypted file 2: $decFilepath');
    print('File content: ' + File(decFilepath).readAsStringSync());
  } on AesCryptException catch (e) {
    if (e.type == AesCryptExceptionType.destFileExists) {
      print('The decryption has been completed unsuccessfully.');
      print(e.message);
    }
  }

  print('');

  try {
    // Decrypt the file to the same name as previous one but in another
    // file naming mode 'AesCryptFnMode.auto'. See what will happens.
    crypt.setFilenamingMode(AesCryptFnMode.auto);
    decFilepath = crypt.decryptFileSync(encFilepath, './example/testfile_new.txt');
    print('The decryption has been completed successfully.');
    print('Decrypted file 3: $decFilepath');
    print('File content: ' + File(decFilepath).readAsStringSync() + '\n');
  } on AesCryptException catch (e) {
    if (e.type == AesCryptExceptionType.destFileExists) {
      print('The decryption has been completed unsuccessfully.');
      print(e.message);
    }
  }


  print('Done.');
}
