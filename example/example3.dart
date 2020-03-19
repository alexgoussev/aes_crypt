import 'dart:math';
import 'dart:typed_data';

import 'package:aes_crypt/aes_crypt.dart';

// Asynchronous data encryption/decryption example

void main() async {
  var random = Random();

  String encFilepath = './example/testfile2.txt.aes';

  int srcDataLen = 120;
  Uint8List srcData = Uint8List.fromList(List<int>.generate(srcDataLen, (i) => random.nextInt(256)));

  // Creates an instance of AesCrypt class.
  var crypt = AesCrypt('my cool password');

  // Sets overwriting mode for file naming (just for an examplpe).
  crypt.setFilenamingMode(AesCryptFnMode.overwrite);

  print('Source data: ${srcData}\n');

  // Encrypts source data and save it to a file './example/testfile2.txt.aes'.
  await crypt.encryptDataToFile(srcData, encFilepath);

  // Decrypt source data back.
  Uint8List decData = await crypt.decryptDataFromFile(encFilepath);

  print('Decrypted data: ${decData}');
}
