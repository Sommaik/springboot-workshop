package com.business.zuul.security;

import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@EnableWebSecurity
public class SecurityTokenConfig extends WebSecurityConfigurerAdapter {

    final String _uri = "/auth/**";

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
     .csrf().disable()
         // make sure we use stateless session; session won't be used to store user's state.
          .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) 	
     .and()
         // handle an authorized attempts 
         .exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED)) 	
     .and()
        // Add a filter to validate the tokens with every request
        .addFilterAfter(new JwtTokenAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
     // authorization requests config
     .authorizeRequests()
        .antMatchers(HttpMethod.POST, _uri).permitAll()
        .antMatchers("/admin/**").hasRole("ADMIN")
        .anyRequest().authenticated(); 
 }
}