part of aes_crypt;

/// Error thrown when a function is passed an unacceptable argument.
class AesCryptArgumentError extends ArgumentError {
  /// Creates a new AesCryptArgumentError with an error message `message`
  /// describing the erroneous argument.
  AesCryptArgumentError(String message) : super(message);

  /// Throws [AesCryptArgumentError] if [argument] is: null [Object], empty [String] or empty [Iterable]
  static void checkNullOrEmpty(Object argument, String message) {
    if (argument == null ||
        ((argument is String)? argument.isEmpty : false) ||
        ((argument is Iterable)? argument.isEmpty : false)
    ) throw AesCryptArgumentError(message);
  }
}


/// Exception thrown when the file system operation fails.
class AesCryptFsException extends FileSystemException {
  /// Creates a new AesCryptFsException with an error message [message],
  /// optional file system path [path] and optional OS error [osError].
  const AesCryptFsException(String message, [String path = '', OSError osError]) : super(message, path, osError);
}


/// Exception thrown when an integrity of encrypted data is compromised.
class AesCryptDataException implements Exception {
  /// Message describing the problem.
  final String message;

  /// Creates a new AesCryptDataException with an error message `message`.
  const AesCryptDataException(this.message);

  /// Returns a string representation of this object.
  @override
  String toString() => message;
}


/// Exception thrown when ...
class AesCryptException implements Exception {
  /// Message describing the problem.
  final String message;

  /// Type of an exeption.
  final AesCryptExceptionType type;

  /// Creates a new AesCryptException with an error message `message` and type `type`.
  const AesCryptException(this.message, this.type);

  /// Returns a string representation of this object.
  @override
  String toString() => message;
}
