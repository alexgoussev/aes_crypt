import 'dart:math';
import 'dart:typed_data';
import 'package:pointycastle/export.dart';

import 'package:aes_crypt/aes_crypt.dart';
import 'package:test/test.dart';

void main() {
  var random = Random();
  AesCrypt crypt = AesCrypt();

  int srcDataLen = 262144;
  var srcData = Uint8List.fromList(List<int>.generate(srcDataLen, (i) => random.nextInt(256)));

  Uint8List iv = Uint8List.fromList(List<int>.generate(16, (i) => random.nextInt(256)));
  Uint8List key = Uint8List.fromList(List<int>.generate(32, (i) => random.nextInt(256)));
  crypt.aesSetKeys(key, iv);

  group('A group of tests', () {

    test('Test SHA256', () {
      Uint8List hash1 = SHA256Digest().process(srcData);
      Uint8List hash2 = crypt.sha256(srcData);
      expect(hash1.isEqual(hash2), equals(true));
    });

    test('Test HMAC SHA256', () {
      var hmac = HMac(SHA256Digest(), 64)..init(KeyParameter(key));
      Uint8List hash1 = hmac.process(srcData);
      Uint8List hash2 = crypt.hmacSha256(key, srcData);
      expect(hash1.isEqual(hash2), equals(true));
    });


    test('Test AES CBC encryption/decryption', () {
      crypt.aesSetMode(AesMode.cbc);
      Uint8List encData = crypt.aesEncrypt(srcData);
      Uint8List decData = crypt.aesDecrypt(encData);
      expect(srcData.isEqual(decData), equals(true));
    });

    test('Test AES ECB encryption/decryption', () {
      crypt.aesSetMode(AesMode.ecb);
      Uint8List encData = crypt.aesEncrypt(srcData);
      Uint8List decData = crypt.aesDecrypt(encData);
      expect(srcData.isEqual(decData), equals(true));
    });

    test('Test AES CFB encryption/decryption', () {
      crypt.aesSetMode(AesMode.cfb);
      Uint8List encData = crypt.aesEncrypt(srcData);
      Uint8List decData = crypt.aesDecrypt(encData);
      expect(srcData.isEqual(decData), equals(true));
    });

    test('Test AES OFB encryption/decryption', () {
      crypt.aesSetMode(AesMode.ofb);
      Uint8List encData = crypt.aesEncrypt(srcData);
      Uint8List decData = crypt.aesDecrypt(encData);
      expect(srcData.isEqual(decData), equals(true));
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