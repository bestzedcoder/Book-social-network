package com.zed.book_social_network.handler;

import jakarta.mail.MessagingException;
import java.util.HashSet;
import java.util.Set;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {


  @ExceptionHandler(LockedException.class)
  public ResponseEntity<ExceptionResponse> handleException(LockedException exp) {
      return ResponseEntity
          .status(HttpStatus.UNAUTHORIZED)
          .body(
              ExceptionResponse.builder()
                  .businessErrorCode(BusinessErrorCodes.ACCOUNT_LOCKED.getCode())
                  .businessExceptionDescription(BusinessErrorCodes.ACCOUNT_LOCKED.getDescription())
                  .error(exp.getMessage())
                  .build()
          );
  }

  @ExceptionHandler(DisabledException.class)
  public ResponseEntity<ExceptionResponse> handleException(DisabledException exp) {
    return ResponseEntity
        .status(HttpStatus.UNAUTHORIZED)
        .body(
            ExceptionResponse.builder()
                .businessErrorCode(BusinessErrorCodes.ACCOUNT_DISABLE.getCode())
                .businessExceptionDescription(BusinessErrorCodes.ACCOUNT_DISABLE.getDescription())
                .error(exp.getMessage())
                .build()
        );
  }

  @ExceptionHandler(MessagingException.class)
  public ResponseEntity<ExceptionResponse> handleException(MessagingException exp) {
    return ResponseEntity
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .body(
            ExceptionResponse.builder()
                .error(exp.getMessage())
                .build()
        );
  }

  @ExceptionHandler(MethodArgumentNotValidException.class)
  public ResponseEntity<ExceptionResponse> handleException(MethodArgumentNotValidException exp) {
    Set<String> errors = new HashSet<>();
    exp.getBindingResult().getAllErrors().forEach(error -> {
      var errorMessage = error.getDefaultMessage();
      errors.add(errorMessage);
    });
    return ResponseEntity
        .status(HttpStatus.BAD_REQUEST)
        .body(
            ExceptionResponse.builder()
                .validationErrors(errors)
                .build()
        );
  }

  @ExceptionHandler(Exception.class)
  public ResponseEntity<ExceptionResponse> handleException(Exception exp) {
    exp.printStackTrace();
    return ResponseEntity
        .status(HttpStatus.INTERNAL_SERVER_ERROR)
        .body(
            ExceptionResponse.builder()
                .businessExceptionDescription("Internal error, please contact the admin")
                .error(exp.getMessage())
                .build()
        );
  }
}
