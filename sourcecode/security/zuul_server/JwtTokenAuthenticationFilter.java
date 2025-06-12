package com.example.gateway;

import java.io.IOException;
import java.security.Key;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtTokenAuthenticationFilter extends OncePerRequestFilter {

    private String _header = "Authorization";
    private String _prefix = "Bearer ";
    private String _secret = "5367566859703373367639792F423F452848284D6251655468576D5A71347437";

    @SuppressWarnings("null")
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        // 1. get the authentication header. Tokens are supposed to be passed in the
        // authentication header
        String header = request.getHeader(_header);

        // 2. validate the header and check the prefix
        if (header == null || !header.startsWith(_prefix)) {
            chain.doFilter(request, response); // If not valid, go to the next filter.
            return;
        }

        // If there is no token provided and hence the user won't be authenticated.
        // It's Ok. Maybe the user accessing a public path or asking for a token.

        // All secured paths that needs a token are already defined and secured in
        // config class.
        // And If user tried to access without access token, then he won't be
        // authenticated and an exception will be thrown.

        // 3. Get the token
        String token = header.replace(_prefix, "");

        try { // exceptions might be thrown in creating the claims if for example the token is
              // expired

            // 4. Validate the token
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(getSignKey())
                    .build()
                    .parseClaimsJws(token)
                    .getBody();

            String username = claims.getSubject();
            System.out.println(username);
            if (username != null) {
                @SuppressWarnings("unchecked")
                List<String> authorities = (List<String>) claims.get("authorities");

                // 5. Create auth object
                // UsernamePasswordAuthenticationToken: A built-in object, used by spring to
                // represent the current authenticated / being authenticated user.
                // It needs a list of authorities, which has type of GrantedAuthority interface,
                // where SimpleGrantedAuthority is an implementation of that interface
                UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(
                        username, null,
                        authorities.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));

                // 6. Authenticate the user
                // Now, user is authenticated
                SecurityContextHolder.getContext().setAuthentication(auth);
            }

        } catch (Exception e) {
            // In case of failure. Make sure it's clear; so guarantee user won't be
            // authenticated
            e.printStackTrace();
            SecurityContextHolder.clearContext();
        }

        // go to the next filter in the filter chain
        chain.doFilter(request, response);
    }

    private Key getSignKey() {
        byte[] keyBytes = Decoders.BASE64.decode(_secret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

}
