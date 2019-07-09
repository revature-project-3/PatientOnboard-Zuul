package com.patientonboarding.filters;

import java.net.URI;
import java.util.Collections;

import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.netflix.zuul.filters.Route;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.CrossOrigin;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class JwtFilter extends ZuulFilter{
	private static String SECRET_KEY = "t9nHY9pKwVikBibqgHu7OKic5CCQcM5qREDdJfrZ2niMcayrxwD2eo5yOMt104F_MwXJApjfwZgYTFOodCtMJFLEwtzQWVdPbbxT4SPSFvnp77JJLIttKZOheZkvOGM";

	@Override
	public boolean shouldFilter() {
		return true;
	}

	@Override
	@CrossOrigin
	public Object run() throws ZuulException {
		
		RequestContext cont = RequestContext.getCurrentContext();
		HttpServletRequest myreq = cont.getRequest();
		String requestUrl = URI.create(myreq.getRequestURI()).getPath();
		String requestPrefix = requestUrl;
		System.out.println("In zuul filter");
		if(requestPrefix.equalsIgnoreCase("/auth/authenticate")) {
			// login function called dont do anything
		} else {
			String jwt = myreq.getHeader("authorization");

				Claims claim = decodeJWT(jwt);
				if (claim == null) {
					
					//claim invalid
					System.out.println("*************invalid claim**************");
					//Object e = cont.get("error.exception");
					//if (e != null && e instanceof ZuulException) {
		                //ZuulException zuulException = (ZuulException)e;
		                //cont.remove("error.status_code");
		                cont.setSendZuulResponse(false);

		                // response to client
		                cont.setResponseBody("API key not authorized");
		                cont.getResponse().setHeader("Content-Type", "text/plain;charset=UTF-8");
		                cont.setResponseStatusCode(HttpStatus.UNAUTHORIZED.value());
		                // Remove error code to prevent further error handling in follow up filters


		           }

			

		}
		return null;
	}

	@Override
	public String filterType() {
		return "pre";
	}

	@Override
	public int filterOrder() {
		return 0;
	}

    public static Claims decodeJWT(String jwt) {
    	System.out.println("*****************JWT********************");
    	System.out.println("*****************JWT********************");
    	System.out.println(jwt);
    	System.out.println("*****************JWT********************");
    	System.out.println("*****************JWT********************");
        //This line will throw an exception if it is not a signed JWS (as expected)
    	try {
        Claims claims = Jwts.parser()
                .setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY))
                .parseClaimsJws(jwt).getBody();
        return claims;
    	} catch (Exception e) {
    		System.out.println("************INVALID JWT*************");
    		return null;
    	}
    }
}
