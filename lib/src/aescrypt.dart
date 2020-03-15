part of aes_crypt;

enum AESCryptFnMode { auto, warn, overwrite }

enum AESCryptExceptionType { destFileExists }

enum _Action { encrypting, decripting }

enum _HmacType { HMAC, HMAC1, HMAC2 }
extension _HmacTypeExtension on _HmacType {
  String get name => this.toString().replaceFirst(this.runtimeType.toString() + '.', '');
}

class AESCrypt {
  static const _debug = false;
  static const String _encFileExt = '.aes';

  final _secureRandom = FortunaRandom();
  final Map<String, List<int>> _user_data = {};

  AESCryptFnMode _fnMode = AESCryptFnMode.auto;

  AESCrypt() {
    var random = Random.secure();
    List<int> seeds = List<int>.generate(32, (i) => random.nextInt(256));
    _secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));

    setUserData();
  }

  void setFilenamingMode(AESCryptFnMode mode) => _fnMode = mode;

  void setUserData({String created_by = 'Dart aes_crypt package', String created_date = '', String created_time =''}) {
    String key;
    if (created_by.isNotEmpty) {
      key = 'CREATED_BY';
      _user_data[key] = created_by.toUTF8Bytes();
      if (key.length + _user_data[key].length + 1 > 255) {
        throw AESCryptArgumentError('User data `$key` is too long. Total length should not exceed 255 bytes.');
      }
    }
    if (created_date.isNotEmpty) {
      key = 'CREATED_DATE';
      _user_data[key] = created_date.toUTF8Bytes();
      if (key.length + _user_data[key].length + 1 > 255) {
        throw AESCryptArgumentError('User data `$key` is too long. Total length should not exceed 255 bytes.');
      }
    }
    if (created_time.isNotEmpty) {
      key = 'CREATED_TIME';
      _user_data[key] = created_time.toUTF8Bytes();
      if (key.length + _user_data[key].length + 1 > 255) {
        throw AESCryptArgumentError('User data `$key` is too long. Total length should not exceed 255 bytes.');
      }
    }
  }


  String encryptDataToFileSync(String passphrase, List<int> source_data, String dest_file) {
    dest_file = dest_file.trim();

    AESCryptArgumentError.checkNotNullOrEmpty(passphrase, 'Empty passphrase.');
    AESCryptArgumentError.checkNotNullOrEmpty(dest_file, 'Empty encrypted file path.');

    _log('ENCRYPTION', 'Started');

    final Uint8List pass = passphrase.toUTF16BytesLE();
    _log('PASSPHRASE', pass);

    final Uint8List header = Uint8List.fromList(<int>[65, 69, 83, 2, 0]);

    final Uint8List userdata_bin = _getBinaryUserData();

    // Create a random IV using the aes implementation
    // IV is based on the block size which is 128 bits (16 bytes) for AES
    final Uint8List iv_1 = _createIV();
    _log('IV_1', iv_1);

    // Use this IV and password to generate the first encryption key
    // We don't need to use AES for this as its just lots of sha hashing
    final Uint8List enc_key_1 = _createKey(iv_1, pass);
    _log('KEY_1', enc_key_1);

    // Create another set of keys to do the actual file encryption
    final Uint8List iv_2 = _createIV();
    _log('IV_2', iv_2);

    // The file format uses AES 256 (which is the key length)
    final Uint8List enc_key_2 = createRandomKey();
    _log('KEY_2', enc_key_2);

    // Encrypt the second set of keys using the first keys
    final Uint8List encrypted_keys = encryptData(iv_2.addList(enc_key_2), iv_1, enc_key_1);
    _log('ENCRYPTED KEYS', encrypted_keys);

    // Calculate HMAC1 using the first enc key
    final Uint8List hmac_1 = _hmacSha256(enc_key_1, encrypted_keys);
    _log('HMAC_1', hmac_1);

    // Do data encryption

    final Uint8List file_size_modulo = Uint8List.fromList([source_data.length % 16]);
    _log('FILE SIZE MODULO', file_size_modulo);

    final Uint8List source_data_padded = Uint8List(source_data.length + (16 - source_data.length % 16));
    source_data_padded.setAll(0, source_data);
    final Uint8List encrypted_data = encryptData(source_data_padded, iv_2, enc_key_2);
    source_data_padded.fillByZero();
    final Uint8List hmac_2 = _hmacSha256(enc_key_2, encrypted_data);
    _log('HMAC2', hmac_2);

    // Write encrypted data to file

    List<Uint8List> datablocks = [header, userdata_bin, iv_1, encrypted_keys, hmac_1, encrypted_data, file_size_modulo, hmac_2];

    dest_file = _modifyDestinationFilename(dest_file);
    File outFile = File(dest_file);
    RandomAccessFile raf;
    try {
      raf = outFile.openSync(mode: FileMode.writeOnlyAppend);
    } on FileSystemException catch(e) {
      throw AESCryptIOException('Failed to open file $dest_file for writing.', e.path, e.osError);
    }
    try {
      datablocks.forEach((d) { raf.writeFromSync(d); });
    } on FileSystemException catch(e) {
      raf.closeSync();
      datablocks.forEach((d) { d.fillByZero(); });
      throw AESCryptIOException('Failed to write encrypted data to file $dest_file.', e.path, e.osError);
    }
    raf.closeSync();

    datablocks.forEach((d) { d.fillByZero(); });
    _log('ENCRYPTION', 'Complete');
    return dest_file;
  }


  String encryptFileSync(String passphrase, String source_file, [String dest_file = '']) {
    source_file = source_file.trim();
    dest_file = dest_file.trim();

    AESCryptArgumentError.checkNotNullOrEmpty(passphrase, 'Empty passphrase.');
    AESCryptArgumentError.checkNotNullOrEmpty(source_file, 'Empty source file path.');
    if (source_file == dest_file) throw AESCryptArgumentError('Source file path and encrypted file path are the same.');

    File inFile = File(source_file);
    if (!inFile.existsSync()) {
      throw AESCryptIOException('Source file $source_file does not exist.', source_file);
    } else if (!inFile.isReadable()) {
      throw AESCryptIOException('Source file $source_file is not readable.', source_file);
    }

    _log('ENCRYPTION', 'Started');

    final Uint8List pass = passphrase.toUTF16BytesLE();
    _log('PASSPHRASE', pass);

    final Uint8List header = Uint8List.fromList(<int>[65, 69, 83, 2, 0]);

    final Uint8List userdata_bin = _getBinaryUserData();

    // Create a random IV using the aes implementation
    // IV is based on the block size which is 128 bits (16 bytes) for AES
    final Uint8List iv_1 = _createIV();
    _log('IV_1', iv_1);

    // Use this IV and password to generate the first encryption key
    // We don't need to use AES for this as its just lots of sha hashing
    final Uint8List enc_key_1 = _createKey(iv_1, pass);
    _log('KEY_1', enc_key_1);

    // Create another set of keys to do the actual file encryption
    final Uint8List iv_2 = _createIV();
    _log('IV_2', iv_2);

    // The file format uses AES 256 (which is the key length)
    final Uint8List enc_key_2 = createRandomKey();
    _log('KEY_2', enc_key_2);

    // Encrypt the second set of keys using the first keys
    final Uint8List encrypted_keys = encryptData(iv_2.addList(enc_key_2), iv_1, enc_key_1);
    _log('ENCRYPTED KEYS', encrypted_keys);

    // Calculate HMAC1 using the first enc key
    final Uint8List hmac_1 = _hmacSha256(enc_key_1, encrypted_keys);
    _log('HMAC_1', hmac_1);

    // Do file encryption

    int inFileLength = inFile.lengthSync();
    final Uint8List source_data = Uint8List(inFileLength + (16 - inFileLength % 16));

    final Uint8List file_size_modulo = Uint8List.fromList([inFileLength % 16]);
    _log('FILE SIZE MODULO', file_size_modulo);

    RandomAccessFile f;
    try {
      f = inFile.openSync(mode: FileMode.read);
    } on FileSystemException catch(e) {
      throw AESCryptIOException('Failed to open file $source_file for reading.', e.path, e.osError);
    }
    try {
      f.readIntoSync(source_data);
    } on FileSystemException catch(e) {
      f.closeSync();
      throw AESCryptIOException('Failed to read file $source_file', e.path, e.osError);
    }
    f.closeSync();

    final Uint8List encrypted_data = encryptData(source_data, iv_2, enc_key_2);
    source_data.fillByZero();
    final Uint8List hmac_2 = _hmacSha256(enc_key_2, encrypted_data);
    _log('HMAC2', hmac_2);

    // Write encrypted data to file

    List<Uint8List> datablocks = [header, userdata_bin, iv_1, encrypted_keys, hmac_1, encrypted_data, file_size_modulo, hmac_2];

    dest_file = _makeDestFilenameFromSource(source_file, dest_file, _Action.encrypting);
    File outFile = File(dest_file);
    RandomAccessFile raf;
    try {
      raf = outFile.openSync(mode: FileMode.writeOnlyAppend);
    } on FileSystemException catch(e) {
      throw AESCryptIOException('Failed to open file $dest_file for writing.', e.path, e.osError);
    } try {
      datablocks.forEach((d) { raf.writeFromSync(d); });
    } on FileSystemException catch(e) {
      raf.closeSync();
      datablocks.forEach((d) { d.fillByZero(); });
      throw AESCryptIOException('Failed to write encrypted data to file $dest_file.', e.path, e.osError);
    }
    raf.closeSync();

    datablocks.forEach((d) { d.fillByZero(); });
    _log('ENCRYPTION', 'Complete');
    return dest_file;
  }


  Uint8List decryptDataFromFileSync(String passphrase, String source_file) {
    Uint8List decrypted_data_full;
    RandomAccessFile f;
    int file_size_modulo;

    source_file = source_file.trim();

    AESCryptArgumentError.checkNotNullOrEmpty(passphrase, 'Empty passphrase.');
    AESCryptArgumentError.checkNotNullOrEmpty(source_file, 'Empty source file path.');

    File inFile = File(source_file);
    if (!inFile.existsSync()) {
      throw AESCryptIOException('Source file $source_file does not exist.');
    }

    try {
      f = inFile.openSync(mode: FileMode.read);
    } on FileSystemException catch(e) {
      throw AESCryptIOException('Failed to open file $source_file for reading.', e.path, e.osError);
    }

    _log('DECRYPTION', 'Started');

    final Uint8List head = _readChunkBytesSync(f, 3, 'file header');
    final Uint8List expected_head = Uint8List.fromList([65, 69, 83]);
    if (head.isNotEqual(expected_head)) {
      throw AESCryptDataException('The chunk `file header` was expected to be ${expected_head.toHexString()} but found ${head.toHexString()}');
    }

    final int version_chunk = _readChunkIntSync(f, 1, 'version byte');
    switch(version_chunk) {
      case 0: // file version 0
        file_size_modulo = _readChunkIntSync(f, 1, 'file size modulo');
        if (file_size_modulo < 0 || file_size_modulo >= 16) {
          throw AESCryptDataException('Invalid file size modulo: $file_size_modulo');
        }

        final Uint8List iv = _readChunkBytesSync(f, 16, 'IV');
        _log('IV', iv);
        final Uint8List encrypted_data = _readChunkBytesSync(f, f.lengthSync() - (5+16) - 32, 'encrypted data');
        final Uint8List hmac = _readChunkBytesSync(f, 32, 'HMAC');
        _log('HMAC', hmac);

        final Uint8List pass = passphrase.toUTF16BytesLE();
        _log('PASSPHRASE', pass);

        final Uint8List enc_keys = _createKey(iv, pass);
        _log('ENCRYPTED KEYS', enc_keys);

        decrypted_data_full = decryptData(encrypted_data, iv, enc_keys);

        // Here the HMAC is (probably) used to verify the decrypted data
        // Test this using known encrypted files using version 0
        _validateHMAC(enc_keys, decrypted_data_full, hmac, _HmacType.HMAC);
        break;
      case 1: // file version 1
      case 2: // file version 2
        _readChunkIntSync(f, 1, 'reserved byte', 0);

        // User data
        if (version_chunk == 2) {
          int ext_length = _readChunkIntSync(f, 2, 'extension length');
          while (ext_length != 0) {
            _readChunkBytesSync(f, ext_length, 'extension content');
            ext_length = _readChunkIntSync(f, 2, 'extension length');
          }
        }

        // Initialization Vector (IV) used for encrypting the IV and symmetric key
        // that is actually used to encrypt the bulk of the plaintext file.
        final Uint8List iv_1 = _readChunkBytesSync(f, 16, 'IV 1');
        _log('IV_1', iv_1);

        // Encrypted IV and 256-bit AES key used to encrypt the bulk of the file
        // 16 octets - initialization vector
        // 32 octets - encryption key
        final Uint8List enc_keys = _readChunkBytesSync(f, 48, 'Encrypted Keys');
        _log('ENCRYPTED KEYS', enc_keys);

        // HMAC
        final Uint8List hmac_1 = _readChunkBytesSync(f, 32, 'HMAC 1');
        _log('HMAC_1', hmac_1);

        final Uint8List pass = passphrase.toUTF16BytesLE();
        _log('PASSPHRASE', pass);

        final Uint8List enc_key_1 = _createKey(iv_1, pass);
        _log('KEY DERIVED FROM IV_1 & PASSPHRASE', enc_key_1);

        _validateHMAC(enc_key_1, enc_keys, hmac_1, _HmacType.HMAC1);

        final Uint8List encrypted_data = _readChunkBytesSync(f, f.lengthSync() - f.positionSync() - 33, 'encrypted data');
        _log('ENCRYPTED DATA', encrypted_data);

        file_size_modulo = _readChunkIntSync(f, 1, 'file size modulo');
        _log('FILE SIZE MODULO', file_size_modulo);
        if (file_size_modulo < 0 || file_size_modulo >= 16) {
          throw AESCryptDataException('Invalid file size modulos: $file_size_modulo');
        }

        final Uint8List hmac_2 = _readChunkBytesSync(f, 32, 'HMAC 2');
        _log('HMAC_2', hmac_2);

        final Uint8List decrypted_keys = decryptData(enc_keys, iv_1, enc_key_1);
        _log('DECRYPTED_KEYS', decrypted_keys);
        final Uint8List iv_2 = decrypted_keys.sublist(0, 16);
        _log('IV_2', iv_2);
        final Uint8List enc_key_2 = decrypted_keys.sublist(16);
        _log('ENCRYPTION KEY 2', enc_key_2);

        _validateHMAC(enc_key_2, encrypted_data, hmac_2, _HmacType.HMAC2);

        decrypted_data_full = decryptData(encrypted_data, iv_2, enc_key_2);
        break;
      default:
        f.closeSync();
        throw AESCryptDataException('Invalid version chunk: $version_chunk');
    }

    f.closeSync();

    Uint8List decrypted_data = Uint8List.fromList(decrypted_data_full.sublist(0, decrypted_data_full.length - (16 - file_size_modulo)));
    decrypted_data_full.fillByZero();
    return decrypted_data;
  }


  String decryptFileSync(String passphrase, String source_file, [String dest_file = '']) {
    Uint8List decrypted_data_full;
    RandomAccessFile f;
    int file_size_modulo;

    source_file = source_file.trim();
    dest_file = dest_file.trim();

    AESCryptArgumentError.checkNotNullOrEmpty(passphrase, 'Empty passphrase.');
    AESCryptArgumentError.checkNotNullOrEmpty(source_file, 'Empty source file path.');
    if (source_file == dest_file) throw AESCryptArgumentError('Source file path and decrypted file path are the same.');

    File inFile = File(source_file);
    if (!inFile.existsSync()) {
      throw FileSystemException('Source file $source_file does not exist.');
    }

    _log('DECRYPTION', 'Started');

    try {
      f = inFile.openSync(mode: FileMode.read);
    } on FileSystemException catch(e) {
      throw FileSystemException('Failed to open file $source_file for reading.', e.path, e.osError);
    }

    final Uint8List head = _readChunkBytesSync(f, 3, 'file header');
    final Uint8List expected_head = Uint8List.fromList([65, 69, 83]);
    if (head.isNotEqual(expected_head)) {
      throw AESCryptDataException('The chunk `file header` was expected to be ${expected_head.toHexString()} but found ${head.toHexString()}');
    }

    final int version_chunk = _readChunkIntSync(f, 1, 'version byte');
    switch(version_chunk) {
      case 0: // file version 0
        file_size_modulo = _readChunkIntSync(f, 1, 'file size modulo');
        if (file_size_modulo < 0 || file_size_modulo >= 16) {
          throw AESCryptDataException('Invalid file size modulo: $file_size_modulo');
        }

        final Uint8List iv = _readChunkBytesSync(f, 16, 'IV');
        _log('IV', iv);
        final Uint8List encrypted_data = _readChunkBytesSync(f, f.lengthSync() - (5+16) - 32, 'encrypted data');
        final Uint8List hmac = _readChunkBytesSync(f, 32, 'HMAC');
        _log('HMAC', hmac);

        final Uint8List pass = passphrase.toUTF16BytesLE();
        _log('PASSPHRASE', pass);

        final Uint8List enc_keys = _createKey(iv, pass);
        _log('ENCRYPTED KEYS', enc_keys);

        decrypted_data_full = decryptData(encrypted_data, iv, enc_keys);

        // Here the HMAC is (probably) used to verify the decrypted data
        // Test this using known encrypted files using version 0
        _validateHMAC(enc_keys, decrypted_data_full, hmac, _HmacType.HMAC);
        break;
      case 1: // file version 1
      case 2: // file version 2
        _readChunkIntSync(f, 1, 'reserved byte', 0);

        // User data
        if (version_chunk == 2) {
          int ext_length = _readChunkIntSync(f, 2, 'extension length');
          while (ext_length != 0) {
            _readChunkBytesSync(f, ext_length, 'extension content');
            ext_length = _readChunkIntSync(f, 2, 'extension length');
          }
        }

        // Initialization Vector (IV) used for encrypting the IV and symmetric key
        // that is actually used to encrypt the bulk of the plaintext file.
        final Uint8List iv_1 = _readChunkBytesSync(f, 16, 'IV 1');
        _log('IV_1', iv_1);

        // Encrypted IV and 256-bit AES key used to encrypt the bulk of the file
        // 16 octets - initialization vector
        // 32 octets - encryption key
        final Uint8List enc_keys = _readChunkBytesSync(f, 48, 'Encrypted Keys');
        _log('ENCRYPTED KEYS', enc_keys);

        // HMAC
        final Uint8List hmac_1 = _readChunkBytesSync(f, 32, 'HMAC 1');
        _log('HMAC_1', hmac_1);

        final Uint8List pass = passphrase.toUTF16BytesLE();
        _log('PASSPHRASE', pass);

        final Uint8List enc_key_1 = _createKey(iv_1, pass);
        _log('KEY DERIVED FROM IV_1 & PASSPHRASE', enc_key_1);

        _validateHMAC(enc_key_1, enc_keys, hmac_1, _HmacType.HMAC1);

        final Uint8List encrypted_data = _readChunkBytesSync(f, f.lengthSync() - f.positionSync() - 33, 'encrypted data');
        _log('ENCRYPTED DATA', encrypted_data);

        file_size_modulo = _readChunkIntSync(f, 1, 'file size modulo');
        _log('FILE SIZE MODULO', file_size_modulo);
        if (file_size_modulo < 0 || file_size_modulo >= 16) {
          throw AESCryptDataException('Invalid file size modulos: $file_size_modulo');
        }

        final Uint8List hmac_2 = _readChunkBytesSync(f, 32, 'HMAC 2');
        _log('HMAC_2', hmac_2);

        final Uint8List decrypted_keys = decryptData(enc_keys, iv_1, enc_key_1);
        _log('DECRYPTED_KEYS', decrypted_keys);
        final Uint8List iv_2 = decrypted_keys.sublist(0, 16);
        _log('IV_2', iv_2);
        final Uint8List enc_key_2 = decrypted_keys.sublist(16);
        _log('ENCRYPTION KEY 2', enc_key_2);

        _validateHMAC(enc_key_2, encrypted_data, hmac_2, _HmacType.HMAC2);

        decrypted_data_full = decryptData(encrypted_data, iv_2, enc_key_2);
        break;
      default:
        f.closeSync();
        throw AESCryptDataException('Invalid version chunk: $version_chunk');
    }

    f.closeSync();

    _log('WRITE', 'Started');
    dest_file = _makeDestFilenameFromSource(source_file, dest_file, _Action.decripting);
    File outFile = File(dest_file);
    RandomAccessFile raf;
    try {
      raf = outFile.openSync(mode: FileMode.writeOnly);
    } on FileSystemException catch(e) {
      throw AESCryptIOException('Failed to open $source_file for writing.', e.path, e.osError);
    } try {
      raf.writeFromSync(decrypted_data_full, 0, decrypted_data_full.length - (16 - file_size_modulo));
    } on FileSystemException catch(e) {
      raf.closeSync();
      throw AESCryptIOException('Failed to write to file $source_file.', e.path, e.osError);
    }
    raf.closeSync();

    _log('DECRYPTION', 'Completed');
    decrypted_data_full.fillByZero();
    return dest_file;
  }


  //Converts the given extension data in to binary data
  Uint8List _getBinaryUserData() {
    List<int> output = [];

    int len;
    for (MapEntry<String, List<int>> me in _user_data.entries) {
      len = me.key.length + 1 + me.value.length;
      output.addAll([0, len]);
      output.addAll([...utf8.encode(me.key), 0, ...me.value]);
    }

    //Also insert a 128 byte container
    output.addAll([0, 128]);
    output.addAll(List<int>.filled(128, 0));

    //2 finishing NULL bytes to signify end of extensions
    output.addAll([0, 0]);

    return Uint8List.fromList(output);
  }


//*************************** AES FUNCTIONS ***************************

  Uint8List _createIV() => _secureRandom.nextBytes(16);

  Uint8List createRandomKey([int length = 32]) => _secureRandom.nextBytes(length);

  Uint8List encryptData(Uint8List data, Uint8List iv, Uint8List key) {
    if (![16, 24, 32].contains(key.length)) {
      throw AESCryptArgumentError('Invalid key length for AES. Provided ${key.length} bytes, expected 32 bytes.');
    } else if (iv.length != 16) {
      throw AESCryptArgumentError('Invalid IV length for AES. Provided ${iv.length} bytes, expected 16 bytes.');
    } else if (data.length % 16 != 0) {
      throw AESCryptArgumentError('Invalid data length ${data.length} for AES.');
    }

    CBCBlockCipher cbc = CBCBlockCipher(AESFastEngine())
      ..init(true, ParametersWithIV(KeyParameter(key), iv));

    Uint8List encData = Uint8List(data.length);

    int offset = 0;
    while (offset < data.length) {
      offset += cbc.processBlock(data, offset, encData, offset);
    }
    assert(offset == data.length);

    return encData;
  }

  Uint8List decryptData(Uint8List data, Uint8List iv, Uint8List key) {
    if (![16, 24, 32].contains(key.length)) {
      throw AESCryptArgumentError('Invalid key length for AES. Provided ${key.length} bytes, expected 32 bytes.');
    } else if (iv.length != 16) {
      throw AESCryptArgumentError('Invalid IV length for AES. Provided ${iv.length} bytes, expected 16 bytes.');
    } else if (data.length % 16 != 0) {
      throw AESCryptArgumentError('Invalid data length ${data.length} for AES.');
    }

    CBCBlockCipher cbc = CBCBlockCipher(AESFastEngine())
      ..init(false, ParametersWithIV(KeyParameter(key), iv));

    Uint8List decData = Uint8List(data.length);

    int offset = 0;
    while (offset < data.length) {
      offset += cbc.processBlock(data, offset, decData, offset);
    }
    assert(offset == data.length);

    return decData;
  }


//************************** PRIVATE MEMBERS **************************

  String _makeDestFilenameFromSource(String source_file, String dest_file, _Action action) {
    assert(!source_file.isNullOrEmpty);

    if (dest_file.isNullOrEmpty) {
      switch(action) {
        case _Action.encrypting:
          dest_file = source_file + _encFileExt;
          break;
        case _Action.decripting:
          if (source_file != _encFileExt && source_file.endsWith(_encFileExt)) {
            dest_file = source_file.substring(0, source_file.length - 4);
          } else {
            dest_file = source_file + '.decrypted';
          }
          break;
      }
    }

    return _modifyDestinationFilename(dest_file);
  }

  
  String _modifyDestinationFilename(String dest_file) {
    switch(_fnMode) {
      case AESCryptFnMode.auto:
        int i = 1;
        while (_isPathExists(dest_file))	{
          dest_file = dest_file.replaceAllMapped(RegExp(r'(.*/)?([^\.]*?)(\(\d+\)\.|\.)(.*)'),
                  (Match m) => '${m[1]??''}${m[2]}($i).${m[4]}');
          ++i;
        }
        break;
      case AESCryptFnMode.warn:
        if (_isPathExists(dest_file)) {
          throw AESCryptException('Destination file $dest_file already exists.', AESCryptExceptionType.destFileExists);
        }
        break;
      case AESCryptFnMode.overwrite:
        if (FileSystemEntity.typeSync(dest_file) != FileSystemEntityType.file) {
          throw AESCryptArgumentError('Destination path $dest_file is not a file and can not be overwriten.');
        }
        File(dest_file).deleteSync();
        break;
    }

    return dest_file;
  }
  
  
  int _readChunkIntSync(RandomAccessFile f, int num_bytes, String chunk_name, [int expected_value]) {
    int result;
    Uint8List data;

    try {
      data = f.readSync(num_bytes);
    } on FileSystemException catch(e) {
      throw FileSystemException('Failed to read chunk `$chunk_name` of $num_bytes bytes.', e.path, e.osError);
    }
    if (data.length != num_bytes) {
      throw AESCryptDataException('Failed to read chunk `$chunk_name` of $num_bytes bytes, only found ${data.length} bytes.');
    }

    switch (num_bytes) {
      case 1:
        result = data[0];
        break;
      case 2:
        result = data[0]<<8 | data[1];
        break;
      case 3:
        result = data[0]<<16 | data[1]<<8 | data[2];
        break;
      case 4:
        result = data[0]<<24 | data[1]<<16 | data[2]<<8 | data[3];
        break;
    }

    if (expected_value != null && result != expected_value) {
      throw AESCryptDataException('The chunk `$chunk_name` was expected to be 0x${expected_value.toRadixString(16).toUpperCase()} but found 0x${data.toHexString()}');
    }

    return result;
  }

  Uint8List _readChunkBytesSync(RandomAccessFile f, int num_bytes, String chunk_name) {
    Uint8List data;
    try {
      data = f.readSync(num_bytes);
    } on FileSystemException catch(e) {
      throw AESCryptIOException('Failed to read chunk `$chunk_name` of $num_bytes bytes.', e.path, e.osError);
    }
    if (data.length != num_bytes) {
      throw AESCryptDataException('Failed to read chunk `$chunk_name` of $num_bytes bytes, only found ${data.length} bytes.');
    }
    return data;
  }

  Uint8List _createKey(Uint8List iv, Uint8List pass) {
    Uint8List key = Uint8List(32);
    key.setAll(0, iv);
    int len = 32 + pass.length;
    Uint8List buff = Uint8List(len);
    SHA256Digest sha256 = new SHA256Digest();
    for (int i=0; i < 8192; i++) {
      buff.setAll(0, key);
      buff.setRange(32, len, pass);
      key = sha256.process(buff);
    }
    return key;
  }

  void _validateHMAC(Uint8List key, Uint8List data, Uint8List hash, _HmacType ht) {
    Uint8List calculated = _hmacSha256(key, data);
    if (hash.isNotEqual(calculated)) {
      _log('CALCULATED HMAC', calculated);
      _log('ACTUAL HMAC', hash);
      switch(ht) {
        case _HmacType.HMAC1:
          throw AESCryptDataException('Failed to validate integrity of encryption keys. Wrong `${ht.name}`. Incorrect password or corrupted file.');
          break;
        case _HmacType.HMAC2:
          throw AESCryptDataException('Failed to validate integrity of encrypted data. Wrong `${ht.name}`. The file is corrupted.');
          break;
        case _HmacType.HMAC:
          throw AESCryptDataException('Failed to validate integrity of decrypted data. Wrong `${ht.name}`. Incorrect password or corrupted file.');
          break;
      }
    }
  }

  void _log(String name, dynamic msg) {
    if (_debug) {
      print('$name - ${msg is Uint8List ? msg.toHexString() : msg }');
    }
  }

  Uint8List _hmacSha256(Uint8List key, Uint8List data) {
    final HMac hmac = HMac(SHA256Digest(), 64)
      ..init(KeyParameter(key));
    return hmac.process(data);
  }

  bool _isPathExists(String path) {
    return FileSystemEntity.typeSync(path) != FileSystemEntityType.notFound;
  }

}


/// Error thrown when a function is passed an unacceptable argument.
class AESCryptArgumentError extends ArgumentError {
  /// Creates a new AESCryptArgumentError with an error message `message`
  /// describing the erroneous argument.
  AESCryptArgumentError(String message) : super(message);

  /// Throws AESCryptArgumentError if `argument` is: null `Object`, empty `String` or empty `Iterable`
  static void checkNotNullOrEmpty(Object argument, String message) {
    if (
      argument == null ||
      ((argument is String)? argument.isEmpty : false) ||
      ((argument is Iterable)? argument.isEmpty : false)
    ) throw AESCryptArgumentError(message);
  }
}


/// Exception thrown when a file operation fails.
class AESCryptIOException extends FileSystemException {
  /// Creates a new AESCryptIOException with an error message `message`,
  /// optional file system path `path` and optional OS error `osError`.
  const AESCryptIOException(String message, [String path = '', OSError osError]) : super(message, path, osError);
}


/// Exception thrown when an integrity of encrypted data is compromised.
class AESCryptDataException implements Exception {
  /// Message describing the problem.
  final String message;

  /// Creates a new AESCryptDataException with an error message `message`.
  const AESCryptDataException(this.message);

  /// Returns a string representation of this object.
  @override
  String toString() => message;
}


/// Exception thrown when ...
class AESCryptException implements Exception {
  /// Message describing the problem.
  final String message;

  /// Type of an exeption.
  final AESCryptExceptionType type;

  /// Creates a new AESCryptException with an error message `message` and type `type`.
  const AESCryptException(this.message, this.type);

  /// Returns a string representation of this object.
  @override
  String toString() => message;
}
