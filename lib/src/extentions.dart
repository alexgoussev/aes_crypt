part of aes_crypt;

extension _Uint8ListExtension on Uint8List {
  Uint8List addList(Uint8List other) {
    int totalLength = this.length + other.length;
    Uint8List newList = Uint8List(totalLength);
    newList.setAll(0, this);
    newList.setRange(this.length, totalLength, other);
    return newList;
  }

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

  // https://stackoverflow.com/questions/28565242/convert-uint8list-to-string-with-dart
  // https://unicode.org/faq/utf_bom.html#utf16-4
  /// Converts UTF-16 string to bytes (Low Endian order)
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
