export class TextIntegrityError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = "TextIntegrityError";
    this.code = code;
    this.details = details;
  }
}

export function errorPayload(error) {
  if (error instanceof TextIntegrityError) {
    return {
      status: "error",
      error: {
        code: error.code,
        message: error.message,
        ...(error.details === undefined ? {} : { details: error.details })
      }
    };
  }

  return {
    status: "error",
    error: {
      code: "INTERNAL_ERROR",
      message: "The operation failed unexpectedly."
    }
  };
}
