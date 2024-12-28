package com.jwt.practice_jwt.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY = "c21084f1518851cebbf21b7e08a214b51fcd0ee467b0dc0a2aa842ddcd5ac052cdf505469a35e01908b730dc82d3246acbe5547b62d5aac299997998c72fe98698b5181a7f11b22482fa0f81c36db100663fc49dd79a28708e67dcc08f5f9c5e19436f18ad3d5fa7e977753d6f91bade3c5b78966010fc9d4c1ba87ef24ef18fe72614acf517192e544675627e992ce65dac348a82a7dad3c8eb99d8f936b27c6d67ab7a64967d75819cdd59c25651c6d949f185dacf4869b4133f0964f7965e7810539f17d5a750ba6621000d2efd77bfa1bd420265bb5b411ccfcd8968b3e753320d872ea0b732dd1ce828b31eb75a11acf7358adb6ddda71126f88d14bff3";

    public String extractUsername(String token){
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimResolver){
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(Map<String, Objects> extractClaims, UserDetails userDetails){
       return Jwts.builder()
               .setClaims(extractClaims)
               .setSubject(userDetails.getUsername())
               .setIssuedAt(new Date(System.currentTimeMillis()))
               .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
               .signWith(getSignInKey(), SignatureAlgorithm.HS256)
               .compact();
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }
    public Date extractExpiration(String token){
        return extractClaim(token, Claims::getExpiration);
    }
   private Claims extractAllClaims(String token){

        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

   }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
