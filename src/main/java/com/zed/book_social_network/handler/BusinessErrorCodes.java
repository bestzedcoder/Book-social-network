package com.zed.book_social_network.handler;

import lombok.Getter;
import org.springframework.http.HttpStatus;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.NOT_IMPLEMENTED;

@Getter
public enum BusinessErrorCodes {

  NO_CODE(0, NOT_IMPLEMENTED , "No code" ),

  INCORRECT_CURRENT_PASSWORD(300 , BAD_REQUEST , "Current password is incorrect"),

  NEW_PASSWORD_DOES_NOT_MATCH(301 ,BAD_REQUEST , "The new password does not match" ),

  ACCOUNT_LOCKED(302 , FORBIDDEN , "User account is locked"),

  ACCOUNT_DISABLE(303 , FORBIDDEN , "User account is disabled"),

  BAD_CREDENTIALS(304 , FORBIDDEN , "Login and / or password is incorrect"),


  ;


  private final int code;

  private final String description;

  private final HttpStatus httpStatus;

  BusinessErrorCodes(int code, HttpStatus httpStatus , String description) {
    this.code = code;
    this.description = description;
    this.httpStatus = httpStatus;
  }
}
