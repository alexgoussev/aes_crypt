import 'dart:io';
import 'dart:convert';
import 'dart:typed_data';

import 'package:aes_crypt/aes_crypt.dart';
import 'package:test/test.dart';

void main() {
  AESCrypt aes = AESCrypt();

  aes.password = 'passw 密碼 パスワード пароль كلمة السر';

  group('A group of tests', () {
    test('Test `encryptFileSync` and `decryptFileSync` functions', () {
      String dec_filepath = './test/testfile1.txt';
      String source_data1 = File(dec_filepath).readAsStringSync();

      String enc_filepath = aes.encryptFileSync(dec_filepath);
      dec_filepath = aes.decryptFileSync(enc_filepath);
      File(enc_filepath).deleteSync();
      String source_data2 = File(dec_filepath).readAsStringSync();
      File(dec_filepath).deleteSync();
      expect(source_data2, equals(source_data1));

    });

    test('Test `encryptFile` and `decryptFile` functions', () async {
      String dec_filepath = './test/testfile1.txt';
      String source_data1 = await File(dec_filepath).readAsString();

      String enc_filepath = await aes.encryptFile(dec_filepath);
      dec_filepath = await aes.decryptFile(enc_filepath);
      await File(enc_filepath).delete();
      String source_data2 = await File(dec_filepath).readAsString();
      await File(dec_filepath).delete();

      expect(source_data2, equals(source_data1));
    });

    test('Test `encryptDataToFileSync` and `decryptDataFromFileSync` functions', () {
      String source_string =
          'Варкалось. Хливкие шорьки пырялись по наве, и хрюкотали зелюки, как '
          'мюмзики в мове. (Jabberwocky by Lewis Carroll, russian translation)';
      String enc_filepath = './test/testfile2.txt.aes';

      enc_filepath = aes.encryptDataToFileSync(utf8.encode(source_string), enc_filepath);
      Uint8List decrypted_data = aes.decryptDataFromFileSync(enc_filepath);
      File(enc_filepath).deleteSync();
      String decrypted_string = utf8.decode(decrypted_data);

      expect(decrypted_string, equals(source_string));
    });

    test('Test `encryptDataToFile` and `decryptDataFromFile` functions', () async {
      String source_string =
          'Варкалось. Хливкие шорьки пырялись по наве, и хрюкотали зелюки, как '
          'мюмзики в мове. (Jabberwocky by Lewis Carroll, russian translation)';
      String enc_filepath = './test/testfile2.txt.aes';

      enc_filepath = await aes.encryptDataToFile(utf8.encode(source_string), enc_filepath);
      Uint8List decrypted_data = await aes.decryptDataFromFile(enc_filepath);
      await File(enc_filepath).delete();
      String decrypted_string = utf8.decode(decrypted_data);

      expect(decrypted_string, equals(source_string));
    });

  });
}
