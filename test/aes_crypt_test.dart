import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:aes_crypt/aes_crypt.dart';
import 'package:test/test.dart';

void main() {
  var random = Random();

  AesCrypt crypt = AesCrypt();
  crypt.setPassword('passw 密碼 パスワード пароль كلمة السر ꜩꝕ 𐌰𐍉 𝕬𝖃');
  crypt.setOverwriteMode(AesCryptOwMode.warn);


  group('A group of tests', () {

    test('Test `encryptFileSync()` and `decryptFileSync()` functions', () {
      String src_filepath = './test/testfile.txt';
      String enc_filepath = './test/testfile2.txt.aes';
      String source_data1 = File(src_filepath).readAsStringSync();
      enc_filepath = crypt.encryptFileSync(src_filepath, enc_filepath);
      String dec_filepath = crypt.decryptFileSync(enc_filepath);
      File(enc_filepath).deleteSync();
      String source_data2 = File(dec_filepath).readAsStringSync();
      File(dec_filepath).deleteSync();
      expect(source_data2, equals(source_data1));

    });

    test('Test `encryptFile()` and `decryptFile()` functions', () async {
      String src_filepath = './test/testfile.txt';
      String enc_filepath = './test/testfile2.txt.aes';
      String source_data1 = await File(src_filepath).readAsString();
      enc_filepath = await crypt.encryptFile(src_filepath, enc_filepath);
      String dec_filepath = await crypt.decryptFile(enc_filepath);
      await File(enc_filepath).delete();
      String source_data2 = await File(dec_filepath).readAsString();
      await File(dec_filepath).delete();
      expect(source_data2, equals(source_data1));
    });


    test('Test `decryptFileSync()` functions on a file encypted by AES Crypt software', () {
      String src_filepath = './test/testfile.txt';
      String enc_filepath = './test/testfile.txt.aes';
      String dec_filepath = './test/testfile2.txt';
      String source_data1 = File(src_filepath).readAsStringSync();
      dec_filepath = crypt.decryptFileSync(enc_filepath, dec_filepath);
      String source_data2 = File(dec_filepath).readAsStringSync();
      File(dec_filepath).deleteSync();
      expect(source_data2, equals(source_data1));
    });


    int srcDataLen = 100016;
    var srcData = Uint8List.fromList(List<int>.generate(srcDataLen, (i) => random.nextInt(256)));
    String enc_filepath = './test/testfile2.txt.aes';

    test('Test `encryptDataToFileSync()` and `decryptDataFromFileSync()` functions', () {
      enc_filepath = crypt.encryptDataToFileSync(srcData, enc_filepath);
      Uint8List decrypted_data = crypt.decryptDataFromFileSync(enc_filepath);
      File(enc_filepath).deleteSync();
      expect(srcData.isEqual(decrypted_data), equals(true));
    });

    test('Test `encryptDataToFile()` and `decryptDataFromFile()` functions', () async {
      enc_filepath = await crypt.encryptDataToFile(srcData, enc_filepath);
      Uint8List decrypted_data = await crypt.decryptDataFromFile(enc_filepath);
      await File(enc_filepath).delete();
      expect(srcData.isEqual(decrypted_data), equals(true));
    });


    String decString;
    String srcString = 'hglakj 密碼 パスワード фбмгцз كلمة السر ꜩꝕ 𐌰𐍉 𝕬𝖃 aalkjhflaeiuwoefdnscvsmnskdjfhoweqirhowqefasdnl';
    String encFilepath = './test/testfile2.txt.aes';

    test('Encrypt/decrypt UTF8 string <=> file', () {
      crypt.encryptStringToFileSync(srcString, encFilepath); // bom = false
      decString = crypt.decryptStringFromFileSync(encFilepath);
      File(encFilepath).delete();
      expect(decString, equals(srcString));
    });

    test('Encrypt/decrypt UTF8 string with BOM <=> file', () {
      crypt.encryptStringToFileSync(srcString, encFilepath, bom: true); // bom = true
      decString = crypt.decryptStringFromFileSync(encFilepath);
      File(encFilepath).delete();
      expect(decString, equals(srcString));
    });


    test('Encrypt/decrypt UTF16 BE string <=> file', () {
      crypt.encryptStringToFileSync(srcString, encFilepath, utf16: true); // bom = false, endian = Endian.big
      decString = crypt.decryptStringFromFileSync(encFilepath, utf16: true);
      File(encFilepath).delete();
      expect(decString, equals(srcString));
    });

    test('Encrypt/decrypt UTF16 BE string with BOM <=> file', () {
      crypt.encryptStringToFileSync(srcString, encFilepath, utf16: true, bom: true); // bom = true, endian = Endian.big
      decString = crypt.decryptStringFromFileSync(encFilepath);
      File(encFilepath).delete();
      expect(decString, equals(srcString));
    });

    test('Encrypt/decrypt UTF16 LE string <=> file', () {
      crypt.encryptStringToFileSync(srcString, encFilepath, utf16: true, endian: Endian.little); // bom = false, endian = Endian.little
      decString = crypt.decryptStringFromFileSync(encFilepath, utf16: true, endian: Endian.little);
      File(encFilepath).delete();
      expect(decString, equals(srcString));
    });

    test('Encrypt/decrypt UTF16 LE string with BOM <=> file', () {
      crypt.encryptStringToFileSync(srcString, encFilepath, utf16: true, endian: Endian.little, bom: true); // bom = true, endian = Endian.little
      decString = crypt.decryptStringFromFileSync(encFilepath);
      File(encFilepath).delete();
      expect(decString, equals(srcString));
    });

//    test('', () {
//      expect(true, equals(true));
//    });

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