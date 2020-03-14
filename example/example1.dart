import 'dart:io';

import 'package:aes_crypt/aes_crypt.dart';

void main() {
  String passphrase = 'пассворд';
  String dec_filepath = './example/testfile1.txt';
  String enc_filepath;

  print('Unencrypted source file: $dec_filepath');
  print('File content: ' + File(dec_filepath).readAsStringSync() + '\n');

  var aes = AESCrypt();

  // Uncomment line below to set standard extension tags used in the AES file format.
  // - created_by: This is a developer-defined text string that identifies the software
  //   product, manufacturer, or other useful information (such as software version).
  // - created_date: This indicates the date that the file was created.
  //   The format of the date string is YYYY-MM-DD.
  // - created_time: This indicates the time that the file was created. The format of the date string
  //   is in 24-hour format like HH:MM:SS (e.g, 21:15:04). The time zone is UTC.
  //aes.setUserData(created_by: 'Some string', created_date: '2000-01-01', created_time: '00:00:00');

  try {
    enc_filepath = aes.encryptFileSync(passphrase, dec_filepath);
  } on AESCryptException catch (e) {
    print('Error: $e');
    return;
  }
  print('Encrypted file: $enc_filepath');

  try {
    dec_filepath = aes.decryptFileSync(passphrase, enc_filepath);
  } on AESCryptException catch (e) {
    print('Error: $e');
    return;
  }
  print('Decrypted file: $dec_filepath');
  print('File content: ' + File(dec_filepath).readAsStringSync() + '\n');

  print('Done.');
}
