package com.appsdeveloperblog.photoapp.api.gateway.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableWebSecurity
public class Websecurity extends WebSecurityConfigurerAdapter {

	private Environment env;
	
	@Autowired
	public Websecurity(Environment env) {
		this.env = env;		
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.csrf().disable();
		http.headers().frameOptions().disable();
		http.authorizeRequests()
		.antMatchers(env.getProperty("api.zuul.actuator.url.path")).permitAll()	
		.antMatchers(env.getProperty("api.users.actuator.url.path")).permitAll()		
		.antMatchers(env.getProperty("h2.console.url")).permitAll()
		.antMatchers(HttpMethod.POST, env.getProperty("api.registration.url")).permitAll()
		.antMatchers(HttpMethod.POST, env.getProperty("api.login.url")).permitAll()
		.anyRequest().authenticated()
		.and()
		.addFilter(new AuthorizationFilter(authenticationManager(), env));
		// SessionCreationPolicy.Sateless make the API stateless
		// When client application starts communicating with the sever side application, there will
		// be http session will be created and this session will uniquely identify the client application 
		// while this client application is communicating with the service.
		// SO if you have multiple different client applications communicating with your API then you 
		// will have multiple different HTTP sessions created.  So this session and the cookies
		// that will be created can cache some information about the request and 
		// this can make our authorization header which contains the authorization header or JTW token in that 
		// header also cached and then even if we do not provide the authorization header in 
		// the following http request, the request will still be authorized and we do not want 
		// that to be happened.  In fact, we want most of the requests that contain that authorization
		// had to be reauthorized.  Why said MOST,  because there are http requests 
		// we do not need that authorization.  For example, users sign up does not need to contain
		// authorization header.  To avoid cache and we can configure our web security to tell
		// spring not to create the http session and thus making our rest API stateless.
		
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}
	

}
