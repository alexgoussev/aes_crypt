import 'dart:typed_data';
import 'dart:convert';

import 'package:aes_crypt/aes_crypt.dart';

void main() {
  Uint8List decrypted_data;
  String decrypted_string;
  String passphrase = 'пассворд';
  String source_string =
      'Варкалось. Хливкие шорьки пырялись по наве, и хрюкотали зелюки, как мюмзики в мове. '
      'Twas brillig, and the slithy toves did gyre and gimble in the wabe: All mimsy were the borogoves, and the mome raths outgrabe.';
  String enc_filepath = './example/testfile2.txt.aes';

  print('Source string: $source_string');

  var aes = AESCrypt();

  try {
    enc_filepath = aes.encryptDataToFileSync(passphrase, utf8.encode(source_string), enc_filepath);
  } on AESCryptException catch (e) {
    print('Error: $e');
    return;
  }
  print('Encrypted file: $enc_filepath');

  try {
    decrypted_data = aes.decryptDataFromFileSync(passphrase, enc_filepath);
  } on AESCryptException catch (e) {
    print('Error: $e');
    return;
  }
  decrypted_string = utf8.decode(decrypted_data);
  print('Decrypted string: $decrypted_string');

  print('\nDone.');
}
