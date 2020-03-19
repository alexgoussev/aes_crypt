part of aes_crypt;

extension _Uint8ListExtension on Uint8List {
  bool get isNullOrEmpty => this == null || this.isEmpty;

  Uint8List addList(Uint8List other) {
    int totalLength = this.length + other.length;
    Uint8List newList = Uint8List(totalLength);
    newList.setAll(0, this);
    newList.setRange(this.length, totalLength, other);
    return newList;
  }

  bool isNotEqual(Uint8List other) {
    if (identical(this, other)) return false;
    if (this != null && other == null) return true;
    int length = this.length;
    if (length != other.length) return true;
    for (int i = 0; i < length; i++) {
      if (this[i] != other[i]) return true;
    }
    return false;
  }

  /// Converts bytes to UTF-16 string (Big Endian order)
  ///
  /// From https://stackoverflow.com/questions/28565242/convert-uint8list-to-string-with-dart
  String toUTF16StringBE() {
    StringBuffer buffer = StringBuffer();
    for (int i = 0; i < this.length;) {
      int firstWord = (this[i] << 8) + this[i + 1];
      if (0xD800 <= firstWord && firstWord <= 0xDBFF) {
        int secondWord = (this[i + 2] << 8) + this[i + 3];
        buffer.writeCharCode(((firstWord - 0xD800) << 10) + (secondWord - 0xDC00) + 0x10000);
        i += 4;
      }
      else {
        buffer.writeCharCode(firstWord);
        i += 2;
      }
    }

    return buffer.toString();
  }

  String toHexString() {
    StringBuffer str = StringBuffer();
    this.forEach((item) { str.write(item.toRadixString(16).toUpperCase().padLeft(2, '0')); });
    return str.toString();
  }

  void fillByZero() => this.fillRange(0, this.length, 0);
}


extension _StringExtension on String {
  /// Returns true if string is: null or empty
  bool get isNullOrEmpty => this == null || this.isEmpty;

  /// Converts UTF-16 string to bytes (Big Endian order)
  ///
  /// From https://stackoverflow.com/questions/28565242/convert-uint8list-to-string-with-dart
  /// https://unicode.org/faq/utf_bom.html#utf16-4
  Uint8List toUTF16BytesBE() {
    List<int> list = [];
    this.runes.forEach((rune) {
      if (rune >= 0x10000) {
        rune -= 0x10000;
        int firstWord = (rune >> 10) + 0xD800;
        list.add(firstWord >> 8);
        list.add(firstWord & 0xFF);
        int secondWord = (rune & 0x3FF) + 0xDC00;
        list.add(secondWord >> 8);
        list.add(secondWord & 0xFF);
      }
      else {
        list.add(rune >> 8);
        list.add(rune & 0xFF);
      }
    });
    return Uint8List.fromList(list);
  }

  /// Converts UTF-16 string to bytes (Low Endian order)
  ///
  /// https://stackoverflow.com/questions/28565242/convert-uint8list-to-string-with-dart
  /// https://unicode.org/faq/utf_bom.html#utf16-4
  Uint8List toUTF16BytesLE() {
    List<int> list = [];
    this.runes.forEach((rune) {
      if (rune >= 0x10000) {
        int firstWord = (rune >> 10) + 0xD800 - (0x10000 >> 10);
        int secondWord = (rune & 0x3FF) + 0xDC00;
        list.add(firstWord & 0xFF);
        list.add(firstWord >> 8);
        list.add(secondWord & 0xFF);
        list.add(secondWord >> 8);
      }
      else {
        list.add(rune & 0xFF);
        list.add(rune >> 8);
      }
    });
    return Uint8List.fromList(list);
  }

  List<int> toUTF8Bytes() {
    return utf8.encode(this);
  }
}


extension _FileExtension on File {
  bool isReadable() {
    RandomAccessFile f;

    try { f = this.openSync(mode: FileMode.read); }
    on FileSystemException { return false; }

    try { f.lockSync(FileLock.shared); }
    on FileSystemException { f.closeSync(); return false; }

    f.unlockSync();
    f.closeSync();
    return true;
  }
}
