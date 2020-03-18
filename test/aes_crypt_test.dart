import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:aes_crypt/aes_crypt.dart';
import 'package:test/test.dart';

void main() {
  var random = Random();

  AesCrypt aes = AesCrypt();
  aes.password = 'passw 密碼 パスワード пароль كلمة السر';


  group('A group of tests', () {
    test('Test `encryptFileSync()` and `decryptFileSync()` functions', () {
      String src_filepath = './test/testfile.txt';
      String source_data1 = File(src_filepath).readAsStringSync();
      String enc_filepath = aes.encryptFileSync(src_filepath);
      String dec_filepath = aes.decryptFileSync(enc_filepath);
      File(enc_filepath).deleteSync();
      String source_data2 = File(dec_filepath).readAsStringSync();
      File(dec_filepath).deleteSync();
      expect(source_data2, equals(source_data1));

    });

    test('Test `encryptFile()` and `decryptFile()` functions', () async {
      String src_filepath = './test/testfile.txt';
      String source_data1 = await File(src_filepath).readAsString();
      String enc_filepath = await aes.encryptFile(src_filepath);
      String dec_filepath = await aes.decryptFile(enc_filepath);
      await File(enc_filepath).delete();
      String source_data2 = await File(dec_filepath).readAsString();
      await File(dec_filepath).delete();

      expect(source_data2, equals(source_data1));
    });


    test('Test `decryptFileSync()` functions on a file encypted by AES Crypt software', () {
      String dec_filepath = './test/testfile.txt';
      String enc_filepath = './test/testfile.txt.aes';
      String source_data1 = File(dec_filepath).readAsStringSync();
      dec_filepath = aes.decryptFileSync(enc_filepath);
      String source_data2 = File(dec_filepath).readAsStringSync();
      File(dec_filepath).deleteSync();
      expect(source_data2, equals(source_data1));
    });


    int srcDataLen = 100003;
    var srcData = Uint8List.fromList(List<int>.generate(srcDataLen, (i) => random.nextInt(256)));
    String enc_filepath = './test/testfile2.txt.aes';

    test('Test `encryptDataToFileSync()` and `decryptDataFromFileSync()` functions', () {
      enc_filepath = aes.encryptDataToFileSync(srcData, enc_filepath);
      Uint8List decrypted_data = aes.decryptDataFromFileSync(enc_filepath);
      File(enc_filepath).deleteSync();
      expect(srcData.isEqual(decrypted_data), equals(true));
    });

    test('Test `encryptDataToFile()` and `decryptDataFromFile()` functions', () async {
      enc_filepath = await aes.encryptDataToFile(srcData, enc_filepath);
      Uint8List decrypted_data = await aes.decryptDataFromFile(enc_filepath);
      await File(enc_filepath).delete();
      expect(srcData.isEqual(decrypted_data), equals(true));
    });

  });
}


extension _Uint8ListExtension on Uint8List {
  bool isEqual(Uint8List other) {
    if (identical(this, other)) return true;
    if (this != null && other == null) return false;
    int length = this.length;
    if (length != other.length) return false;
    for (int i = 0; i < length; i++) {
      if (this[i] != other[i]) return false;
    }
    return true;
  }
}