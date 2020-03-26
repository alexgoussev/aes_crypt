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

  group('Hashes', () {

    test('SHA256', () {
      Uint8List hash1 = SHA256Digest().process(srcData);
      Uint8List hash2 = crypt.sha256(srcData);
      expect(hash1.isEqual(hash2), equals(true));
    });

    test('HMAC SHA256', () {
      var hmac = HMac(SHA256Digest(), 64)..init(KeyParameter(key));
      Uint8List hash1 = hmac.process(srcData);
      Uint8List hash2 = crypt.hmacSha256(key, srcData);
      expect(hash1.isEqual(hash2), equals(true));
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