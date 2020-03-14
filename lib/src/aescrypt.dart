part of aes_crypt;

enum _Action { encrypting, decripting }

enum AESCryptFnMode { auto, warn, overwrite }

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
        throw AESCryptException('User data `$key` is too long. Maximum total size of user data is 255 bytes.');
      }
    }
    if (created_date.isNotEmpty) {
      key = 'CREATED_DATE';
      _user_data[key] = created_date.toUTF8Bytes();
      if (key.length + _user_data[key].length + 1 > 255) {
        throw AESCryptException('User data `$key` is too long. Maximum total size of user data is 255 bytes.');
      }
    }
    if (created_time.isNotEmpty) {
      key = 'CREATED_TIME';
      _user_data[key] = created_time.toUTF8Bytes();
      if (key.length + _user_data[key].length + 1 > 255) {
        throw AESCryptException('User data `$key` is too long. Maximum total size of user data is 255 bytes.');
      }
    }
  }


  String encryptDataToFileSync(String passphrase, List<int> source_data, String dest_file) {
    if (passphrase.isNullOrEmpty) {
      throw AESCryptException('Empty passphrase is not allowed');
    }
    if (dest_file.isNullOrEmpty) {
      throw AESCryptException('Empty encrypted file path');
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

    final Uint8List source_data_padded = Uint8List(source_data.length + (16 - source_data.length % 16));
    source_data_padded.setAll(0, source_data);

    final Uint8List encrypted_data = encryptData(source_data_padded, iv_2, enc_key_2);
    source_data_padded.fillByZero();

    final Uint8List file_size_modulo = Uint8List.fromList([source_data.length % 16]);
    _log('FILE SIZE MODULO', file_size_modulo);

    final Uint8List hmac_2 = _hmacSha256(enc_key_2, encrypted_data);
    _log('HMAC2', hmac_2);

    dest_file = _modifyDestinationFilename(dest_file);
    File outFile = File(dest_file);
    RandomAccessFile raf;
    try {
      raf = outFile.openSync(mode: FileMode.writeOnlyAppend);
    } on FileSystemException {
      throw new AESCryptException('Could not open $dest_file in `write` mode');
    }
    List<Uint8List> datablocks = [header, userdata_bin, iv_1, encrypted_keys, hmac_1, encrypted_data, file_size_modulo, hmac_2];
    try {
      datablocks.forEach((e) { raf.writeFromSync(e); });
    } on FileSystemException {
      raf.closeSync();
      datablocks.forEach((e) { e.fillByZero(); });
      throw new AESCryptException('Could not write encrypted data to file $dest_file');
    }

    raf.closeSync();
    datablocks.forEach((e) { e.fillByZero(); });
    _log('ENCRYPTION', 'Complete');
    return dest_file;
  }


  String encryptFileSync(String passphrase, String source_file, [String dest_file = '']) {
    if (passphrase.isNullOrEmpty) {
      throw AESCryptException('Empty passphrase is not allowed');
    }

    source_file = source_file.trim();
    dest_file = dest_file.trim();

    if (source_file.isNullOrEmpty) {
      throw AESCryptException('Empty source file path');
    }
    if (source_file == dest_file) {
      throw AESCryptException('Source file path and encrypted file path are the same');
    }

    File inFile = new File(source_file);
    if (!inFile.existsSync()) {
      throw AESCryptException('Source file $source_file does not exists');
    }
    if (!inFile.isReadable()) {
      throw AESCryptException('Source file $source_file is not readable');
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
    try {
      var raf = inFile.openSync(mode: FileMode.read);
      raf.readIntoSync(source_data);
      raf.closeSync();
    } on FileSystemException {
      throw AESCryptException('Cannot read file content: $source_file');
    }

    final Uint8List encrypted_data = encryptData(source_data, iv_2, enc_key_2);
    source_data.fillByZero();

    final Uint8List file_size_modulo = Uint8List.fromList([inFileLength % 16]);
    _log('FILE SIZE MODULO', file_size_modulo);

    final Uint8List hmac_2 = _hmacSha256(enc_key_2, encrypted_data);
    _log('HMAC2', hmac_2);

    dest_file = _makeDestFilenameFromSource(source_file, dest_file, _Action.encrypting);
    File outFile = File(dest_file);
    RandomAccessFile raf;
    try {
      raf = outFile.openSync(mode: FileMode.writeOnlyAppend);
    } on FileSystemException {
      throw new AESCryptException('Could not open $dest_file in `write` mode');
    }
    List<Uint8List> datablocks = [header, userdata_bin, iv_1, encrypted_keys, hmac_1, encrypted_data, file_size_modulo, hmac_2];
    try {
      datablocks.forEach((e) { raf.writeFromSync(e); });
    } on FileSystemException {
      raf.closeSync();
      datablocks.forEach((e) { e.fillByZero(); });
      throw new AESCryptException('Could not write encrypted data to file $dest_file');
    }

    raf.closeSync();
    datablocks.forEach((e) { e.fillByZero(); });
    _log('ENCRYPTION', 'Complete');
    return dest_file;
  }


  Uint8List decryptDataFromFileSync(String passphrase, String source_file) {
    Uint8List decrypted_data_full;
    RandomAccessFile f;
    int file_size_modulo;

    source_file = source_file.trim();

    if (passphrase.isNullOrEmpty) {
      throw AESCryptException('Empty passphrase is not allowed');
    }
    if (source_file.isNullOrEmpty) {
      throw AESCryptException('Empty encrypted file path');
    }
    File inFile = File(source_file);
    if (!inFile.existsSync()) {
      throw AESCryptException('Source file $source_file does not exist');
    }
    try { f = inFile.openSync(mode: FileMode.read); } on FileSystemException {
      throw AESCryptException('Cannot open file for reading: $source_file');
    }

    _log('DECRYPTION', 'Started');

    final Uint8List head = _readChunkBytesSync(f, 3, 'file header');
    final Uint8List expected_head = Uint8List.fromList([65, 69, 83]);
    if (head.isNotEqual(expected_head)) {
      throw AESCryptException('The chunk `file header` was expected to be ${expected_head.toHexString()} but found ${head.toHexString()}');
    }

    final int version_chunk = _readChunkIntSync(f, 1, 'version byte');
    switch(version_chunk) {
      case 0: // This file uses version 0 of the standard
        file_size_modulo = _readChunkIntSync(f, 1, 'file size modulo');
        if (file_size_modulo < 0 || file_size_modulo >= 16) {
          throw AESCryptException('Invalid file size modulo: $file_size_modulo');
        }

        final Uint8List iv = _readChunkBytesSync(f, 16, 'IV');
        _log('IV', iv);
        final Uint8List encrypted_data = _readChunkBytesSync(f, f.lengthSync() - (5+16) - 32, 'encrypted data');
        final Uint8List hmac = _readChunkBytesSync(f, 32, 'HMAC');
        _log('HMAC', hmac);

        //Start with the IV padded to 32 bytes
        final Uint8List pass = passphrase.toUTF16BytesLE();
        _log('PASSPHRASE', pass);

        final Uint8List enc_keys = _createKey(iv, pass);
        _log('ENCRYPTED KEYS', enc_keys);

        decrypted_data_full = decryptData(encrypted_data, iv, enc_keys);

        // TODO: Test this using known encrypted files using version 0
        // Here the HMAC is (probably) used to verify the decrypted data
        _validateHMAC(enc_keys, decrypted_data_full, hmac, 'HMAC');
        break;
      case 1: // This file uses version 1 of the standard
      case 2: // This file uses version 2 of the standard (The latest standard at the time of writing)
      // Reserved (set to 0x00)
        _readChunkIntSync(f, 1, 'reserved byte', 0);

        if (version_chunk == 2) {
          // User data
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

        _validateHMAC(enc_key_1, enc_keys, hmac_1, 'HMAC 1');

        final Uint8List encrypted_data = _readChunkBytesSync(f, f.lengthSync() - f.positionSync() - 33, 'encrypted data');
        _log('ENCRYPTED DATA', encrypted_data);

        file_size_modulo = _readChunkIntSync(f, 1, 'file size modulo');
        _log('FILE SIZE MODULO', file_size_modulo);
        if (file_size_modulo < 0 || file_size_modulo >= 16) {
          throw AESCryptException('Invalid file size modulos: $file_size_modulo');
        }

        final Uint8List hmac_2 = _readChunkBytesSync(f, 32, 'HMAC 2');
        _log('HMAC_2', hmac_2);

        final Uint8List decrypted_keys = decryptData(enc_keys, iv_1, enc_key_1);
        _log('DECRYPTED_KEYS', decrypted_keys);
        final Uint8List iv_2 = decrypted_keys.sublist(0, 16);
        _log('IV_2', iv_2);
        final Uint8List enc_key_2 = decrypted_keys.sublist(16);
        _log('ENCRYPTION KEY 2', enc_key_2);

        _validateHMAC(enc_key_2, encrypted_data, hmac_2, 'HMAC 2');

        // All keys were correct, we can be sure that the decrypted data will be correct
        decrypted_data_full = decryptData(encrypted_data, iv_2, enc_key_2);
        break;
      default:
        f.closeSync();
        throw AESCryptException('Invalid version chunk: $version_chunk');
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

    if (source_file.isNullOrEmpty) {
      throw AESCryptException('Empty source file path');
    }
    if (source_file == dest_file) {
      throw AESCryptException('Source file path and decrypted file path are the same');
    }

    File inFile = File(source_file);
    if (!inFile.existsSync()) {
      throw AESCryptException('Source file $source_file does not exist');
    }

    _log('DECRYPTION', 'Started');

    try { f = inFile.openSync(mode: FileMode.read); } on FileSystemException {
      throw AESCryptException('Cannot open file for reading: $source_file');
    }

    final Uint8List head = _readChunkBytesSync(f, 3, 'file header');
    final Uint8List expected_head = Uint8List.fromList([65, 69, 83]);
    if (head.isNotEqual(expected_head)) {
      throw AESCryptException('The chunk `file header` was expected to be ${expected_head.toHexString()} but found ${head.toHexString()}');
    }

    final int version_chunk = _readChunkIntSync(f, 1, 'version byte');
    switch(version_chunk) {
      case 0: // This file uses version 0 of the standard
        file_size_modulo = _readChunkIntSync(f, 1, 'file size modulo');
        if (file_size_modulo < 0 || file_size_modulo >= 16) {
          throw AESCryptException('Invalid file size modulo: $file_size_modulo');
        }

        final Uint8List iv = _readChunkBytesSync(f, 16, 'IV');
        _log('IV', iv);
        final Uint8List encrypted_data = _readChunkBytesSync(f, f.lengthSync() - (5+16) - 32, 'encrypted data');
        final Uint8List hmac = _readChunkBytesSync(f, 32, 'HMAC');
        _log('HMAC', hmac);

        //Start with the IV padded to 32 bytes
        final Uint8List pass = passphrase.toUTF16BytesLE();
        _log('PASSPHRASE', pass);

        final Uint8List enc_keys = _createKey(iv, pass);
        _log('ENCRYPTED KEYS', enc_keys);

        decrypted_data_full = decryptData(encrypted_data, iv, enc_keys);

        // TODO: Test this using known encrypted files using version 0
        // Here the HMAC is (probably) used to verify the decrypted data
        _validateHMAC(enc_keys, decrypted_data_full, hmac, 'HMAC');
        break;
      case 1: // This file uses version 1 of the standard
      case 2: // This file uses version 2 of the standard (The latest standard at the time of writing)
        // Reserved (set to 0x00)
        _readChunkIntSync(f, 1, 'reserved byte', 0);

        if (version_chunk == 2) {
          // User data
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

        _validateHMAC(enc_key_1, enc_keys, hmac_1, 'HMAC 1');

        final Uint8List encrypted_data = _readChunkBytesSync(f, f.lengthSync() - f.positionSync() - 33, 'encrypted data');
        _log('ENCRYPTED DATA', encrypted_data);

        file_size_modulo = _readChunkIntSync(f, 1, 'file size modulo');
        _log('FILE SIZE MODULO', file_size_modulo);
        if (file_size_modulo < 0 || file_size_modulo >= 16) {
          throw AESCryptException('Invalid file size modulos: $file_size_modulo');
        }

        final Uint8List hmac_2 = _readChunkBytesSync(f, 32, 'HMAC 2');
        _log('HMAC_2', hmac_2);

        final Uint8List decrypted_keys = decryptData(enc_keys, iv_1, enc_key_1);
        _log('DECRYPTED_KEYS', decrypted_keys);
        final Uint8List iv_2 = decrypted_keys.sublist(0, 16);
        _log('IV_2', iv_2);
        final Uint8List enc_key_2 = decrypted_keys.sublist(16);
        _log('ENCRYPTION KEY 2', enc_key_2);

        _validateHMAC(enc_key_2, encrypted_data, hmac_2, 'HMAC 2');

        // All keys were correct, we can be sure that the decrypted data will be correct
        decrypted_data_full = decryptData(encrypted_data, iv_2, enc_key_2);
        break;
      default:
        f.closeSync();
        throw AESCryptException('Invalid version chunk: $version_chunk');
    }

    f.closeSync();

    _log('WRITE', 'Started');
    dest_file = _makeDestFilenameFromSource(source_file, dest_file, _Action.decripting);
    File outFile = File(dest_file);
    RandomAccessFile raf;
    try {
      raf = outFile.openSync(mode: FileMode.writeOnly);
      raf.writeFromSync(decrypted_data_full, 0, decrypted_data_full.length - (16 - file_size_modulo));
    } on FileSystemException {
      throw AESCryptException('Cannot write to file: $source_file');
    } finally {
      raf.closeSync();
    }

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
      throw AESCryptException('Invalid key length for AES. Provided ${key.length} bytes, expected 32 bytes.');
    }
    if (iv.length != 16) {
      throw AESCryptException('Invalid IV length for AES. Provided ${iv.length} bytes, expected 16 bytes.');
    }
    if (data.length % 16 != 0) {
      throw AESCryptException('Invalid data length ${data.length} for AES');
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
    if (source_file.isNullOrEmpty) {
      throw AESCryptException('Empty source file path');
    }
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
          throw AESCryptException('Destination file $dest_file already exists');
        }
        break;
      case AESCryptFnMode.overwrite:
        if (FileSystemEntity.typeSync(dest_file) != FileSystemEntityType.file) {
          throw AESCryptException('Destination path $dest_file is not a file and can not be overwriten');
        }
        File(dest_file).deleteSync();
        break;
    }

    return dest_file;
  }
  
  
  int _readChunkIntSync(RandomAccessFile f, int num_bytes, String chunk_name, [int expected_value]) {
    int result;
    Uint8List data;

    try { data = f.readSync(num_bytes); } on FileSystemException {
      throw AESCryptException('Could not read chunk `$chunk_name` of $num_bytes bytes');
    }
    if (data.length != num_bytes) {
      throw AESCryptException('Could not read chunk `$chunk_name` of $num_bytes bytes, only found ${data.length} bytes');
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
      throw AESCryptException('The chunk `$chunk_name` was expected to be 0x${expected_value.toRadixString(16).toUpperCase()} but found 0x${data.toHexString()}');
    }

    return result;
  }

  Uint8List _readChunkBytesSync(RandomAccessFile f, int num_bytes, String chunk_name) {
    Uint8List data;
    try { data = f.readSync(num_bytes); } on FileSystemException {
      throw AESCryptException('Could not read chunk `$chunk_name` of $num_bytes bytes');
    }
    if (data.length != num_bytes) {
      throw AESCryptException('Could not read chunk `$chunk_name` of $num_bytes bytes, only found ${data.length} bytes');
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

  void _validateHMAC(Uint8List key, Uint8List data, Uint8List hash, String name) {
    Uint8List calculated = _hmacSha256(key, data);
    if (hash.isNotEqual(calculated)) {
      _log('CALCULATED HMAC', calculated);
      _log('ACTUAL HMAC', hash);
      if (name == 'HMAC 1') {
        throw AESCryptException('$name failed to validate integrity of encryption keys. Incorrect password or file corrupted.');
      } else {
        throw AESCryptException('$name failed to validate integrity of encrypted data. The file is corrupted and should not be trusted.');
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


class AESCryptException implements Exception {
  String msg; 
  AESCryptException(this.msg);
  @override
  String toString() => msg;
}
