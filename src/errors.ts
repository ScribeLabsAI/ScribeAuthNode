/**
Exception raised when a user cannot perform an action.
Possible reasons:
Username and/or Password are incorrect.
Refresh token is incorrect.
MFA code is incorrect or expired.
*/
export class UnauthorizedError extends Error {
  constructor(message: string, cause?: Error) {
    super(message);
    this.name = 'UnauthorizedError';
    this.cause = cause;
  }
}

/**
Exception raised when an action is performed by a user too many times in a short period.
Actions that could raise this exception:
Changing a password.
Revoking a refresh token.
*/
export class TooManyRequestsError extends Error {
  constructor(message: string, cause?: Error) {
    super(message);
    this.name = 'TooManyRequestsError';
    this.cause = cause;
  }
}

export class UnknownError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UnknownError';
  }
}

export class MissingIdError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MissingIdError';
  }
}

export class MissingFieldError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MissingFieldError';
  }
}

/**
 * Exception raised when MFA fails.
 * Actions that could raise this exception:
 * A code has expired.
 * The provided code doesn't match what the server was expecting.
 *
 */
export class MFAError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'MFAError';
  }
}
