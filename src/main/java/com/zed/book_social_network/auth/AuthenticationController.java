package com.zed.book_social_network.auth;

import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.mail.MessagingException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("auth")
@RequiredArgsConstructor
@Tag(name = "Authentication")
public class AuthenticationController {

  private final AuthenticationService authenticationService;

  @PostMapping("/register")
  @ResponseStatus(HttpStatus.ACCEPTED)
  public ResponseEntity<?> register(
      @RequestBody @Valid RegistrationRequest request
  ) throws MessagingException {
    this.authenticationService.register(request);
    return  ResponseEntity.accepted().build();
  }

  @PostMapping("/authenticate")
  public ResponseEntity<AuthenticationResponse> authenticate(
      @RequestBody @Valid AuthenticationRequest request
  ) throws MessagingException {
    return ResponseEntity.ok(this.authenticationService.authenticate(request));
  }

  @GetMapping("/activate-account")
  public void confirm(
      @RequestParam String token
  ) throws MessagingException {
    this.authenticationService.activateAccount(token);
  }
}
