package com.zed.book_social_network.auth;

import com.zed.book_social_network.email.EmailTemplateName;
import com.zed.book_social_network.role.RoleRepository;
import com.zed.book_social_network.security.JwtService;
import com.zed.book_social_network.user.Token;
import com.zed.book_social_network.user.TokenRepository;
import com.zed.book_social_network.user.User;
import com.zed.book_social_network.user.UserRepository;
import com.zed.book_social_network.email.EmailService;
import jakarta.mail.MessagingException;
import jakarta.transaction.Transactional;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

  private final RoleRepository roleRepository;
  private final PasswordEncoder passwordEncoder;
  private final UserRepository userRepository;
  private final TokenRepository tokenRepository;
  private final EmailService emailService;
  private final AuthenticationManager authenticationManager;
  private final JwtService jwtService;

  @Value("${application.mailing.frontend.activation-url}")
  private String activationUrl;

  public void register(RegistrationRequest request) throws MessagingException {
    var userRole = this.roleRepository.findByName("USER")
        .orElseThrow(() -> new IllegalStateException("ROLE USER was not initialized"));
    var user = User.builder()
        .firstName(request.getFirstName())
        .lastName(request.getLastName())
        .email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword()))
        .roles(List.of(userRole))
        .enabled(false)
        .accountLocked(false)
        .build();
    this.userRepository.save(user);
    this.sendValidationEmail(user);
  }

  public AuthenticationResponse authenticate(AuthenticationRequest request) throws MessagingException {


    var auth = this.authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.getEmail(),
            request.getPassword()
        )
    );
    var claims = new HashMap<String , Object>();
    var user = (User) auth.getPrincipal();
    claims.put("fullName" , user.fullName());
    var jwtToken = this.jwtService.generateToken(claims , user);
    return AuthenticationResponse.builder().token(jwtToken).build();
  }

//  @Transactional
  public void activateAccount(String token) throws MessagingException {
    Token savedToken = this.tokenRepository.findByToken(token)
        .orElseThrow(() -> new RuntimeException("Invalid token"));
    if(LocalDateTime.now().isAfter(savedToken.getExpiresAt())) {
      sendValidationEmail(savedToken.getUser());
      throw new RuntimeException("Activation token has expired. A new token has been sent to the same email address.");
    }
    var user = this.userRepository.findById(savedToken.getUser().getId())
        .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    user.setEnabled(true);
    this.userRepository.save(user);
    savedToken.setValidatedAt(LocalDateTime.now());
    this.tokenRepository.save(savedToken);
  }

  private void sendValidationEmail(User user) throws MessagingException {
    var newToken = this.generateAndSaveActivationToken(user);
    // send email
    this.emailService.sendEmail(
        user.getEmail(),
        user.fullName(),
        EmailTemplateName.ACTIVATE_ACCOUNT,
        activationUrl,
        newToken,
        "Account activation"

    );
  }

  private String generateAndSaveActivationToken(User user) {
    // generate a token
    String generatedToken = this.generateActivationCode(6);
    var token = Token.builder()
        .token(generatedToken)
        .createdAt(LocalDateTime.now())
        .expiresAt(LocalDateTime.now().plusMinutes(15))
        .user(user)
        .build();
    this.tokenRepository.save(token);
    return generatedToken;
  }

  private String generateActivationCode(int length) {
    String characters = "0123456789";
    StringBuilder codeBuilder = new StringBuilder();
    SecureRandom secureRandom = new SecureRandom();
    for(int i = 0 ; i < length ; i++) {
      int randomIndex = secureRandom.nextInt(characters.length());
      codeBuilder.append(characters.charAt(randomIndex));
    }
    return codeBuilder.toString();
  }
}
