package com.zed.book_social_network.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
  @Value("${application.security.jwt.expiration}")
  private  Long jwtExpiration ;

  @Value("${application.security.jwt.secretKey}")
  private  String secretKey ;

  public String generateToken(UserDetails userDetails) {

    return this.generateToken(new HashMap<>(), userDetails);
  }

  public String generateToken(Map<String , Object> claims,UserDetails userDetails) {
    return this.buildToken(claims , userDetails , this.jwtExpiration);
  }

  private String buildToken(
      Map<String, Object> claims,
      UserDetails userDetails,
      Long jwtExpiration
  ) {
    var authorities = userDetails.getAuthorities()
        .stream()
        .map(GrantedAuthority::getAuthority)
        .toList();
    return Jwts
        .builder()
        .setClaims(claims)
        .setSubject(userDetails.getUsername())
        .setIssuedAt(new Date(System.currentTimeMillis()))
        .setExpiration(new Date(System.currentTimeMillis() + jwtExpiration))
        .claim("authorities" , authorities)
        .signWith(getSignInKey())
        .compact();
  }

  private Key getSignInKey() {
    byte[] keyBytes = Decoders.BASE64.decode(this.secretKey);
    return Keys.hmacShaKeyFor(keyBytes);
  }

  public boolean isTokenValid(String token, UserDetails userDetails) {
    final String username = this.extractUsername(token);

    return (username.equals(userDetails.getUsername())) && !this.isTokenExpired(token);
  }

  private boolean isTokenExpired(String token) {
    return this.extractExpiration(token).before(new Date());
  }

  private Date extractExpiration(String token) {
    return this.extractClaim(token , Claims::getExpiration);
  }

  public String extractUsername(String token) {
    return this.extractClaim(token , Claims::getSubject);
  }

  public <T> T extractClaim(String token , Function<Claims,T> claimsResolver) {
    final Claims claims = this.extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  public Claims extractAllClaims(String token) {
    return Jwts
        .parserBuilder()
        .setSigningKey(this.getSignInKey())
        .build()
        .parseClaimsJwt(token)
        .getBody();
  }
}
