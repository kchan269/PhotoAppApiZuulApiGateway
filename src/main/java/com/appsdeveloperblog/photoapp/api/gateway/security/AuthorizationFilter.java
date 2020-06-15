package com.appsdeveloperblog.photoapp.api.gateway.security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Jwts;

public class AuthorizationFilter extends BasicAuthenticationFilter {

	
	private Environment env;
	
	@Autowired
	public AuthorizationFilter(AuthenticationManager authenticationManager, Environment env) {
		super(authenticationManager);
		this.env = env;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		
		String authorizationHeader = request.getHeader(env.getProperty("authorization.token.header.name"));
		
		if (authorizationHeader == null || !authorizationHeader.startsWith(env.getProperty("authorization.token.header.prefix"))) {
				chain.doFilter(request, response);
		        return;
		}
		
		UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
		
		SecurityContextHolder.getContext().setAuthentication(authentication);
		chain.doFilter(request, response);
	}


	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		
		String authorizationHeader = request.getHeader(env.getProperty("authorization.token.header.name"));
		
		if (authorizationHeader == null) 
			return null;
		
		
		// Strip out the "Bearer" prefix so that we can have clean value of authorization token 
		String token = authorizationHeader.replace(env.getProperty("authorization.token.header.prefix"), "");
		
		// using JWT to validate this token and to pass out that token.  User id was encoded
		// in that token.
		// set signing key which was used to sign this token when it was initially created 
		// getSubject - the subject that we used when we were creating this token and was a public user ID when user 
		// logged 
		String userId = Jwts.parser()
				.setSigningKey(env.getProperty("token.secret"))
				.parseClaimsJws(token)
				.getBody()
				.getSubject();
		System.out.println("user id = " + userId);
		if (userId == null)
			return null;
				
		return new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>());
	}
}
