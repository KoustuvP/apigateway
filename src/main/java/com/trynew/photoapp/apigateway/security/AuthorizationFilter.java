package com.trynew.photoapp.apigateway.security;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import io.jsonwebtoken.Jwts;

public class AuthorizationFilter extends BasicAuthenticationFilter {

	public AuthorizationFilter(AuthenticationManager authenticationManager) {
		super(authenticationManager);
		// TODO Auto-generated constructor stub
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		String authorizationHeader= request.getHeader("Authorization");
		if(authorizationHeader==null||!authorizationHeader.startsWith("Bearer")) {
			chain.doFilter(request, response);
			return;
		}
		
		UsernamePasswordAuthenticationToken authToken = getAuthenticationManager(request);
		SecurityContextHolder.getContext().setAuthentication(authToken);
		chain.doFilter(request, response);
	}

	private UsernamePasswordAuthenticationToken getAuthenticationManager(HttpServletRequest request) {
		// TODO Auto-generated method stub
		String authorizationHeader=request.getHeader("Authorization");
		if(authorizationHeader==null)
			return null;
		String token=authorizationHeader.replace("Bearer ", "");
		String userId=Jwts.parser()
				.setSigningKey("Koustuv@piku1")
				.parseClaimsJws(token)
				.getBody()
				.getSubject();
		if(userId==null)
			return null;
		return new UsernamePasswordAuthenticationToken(userId, null,new ArrayList<>());
	}

}
