part of aes_crypt;

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
