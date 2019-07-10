package com.patientonboarding.filters;

import java.net.URI;

import javax.servlet.http.HttpServletRequest;
import javax.xml.bind.DatatypeConverter;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.CrossOrigin;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.netflix.zuul.exception.ZuulException;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class JwtFilter extends ZuulFilter {
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
		System.out.println(requestPrefix);
		if (requestPrefix.equalsIgnoreCase("/auth/authenticate") || requestPrefix.equalsIgnoreCase("/auth/registerUser")) {
			System.out.println("auth or register");
		} else {
			System.out.println(requestPrefix);
			String jwt = myreq.getHeader("authorization");
			Claims claim = decodeJWT(jwt);
			if (claim == null) {
				// claim invalid
				cont.setSendZuulResponse(false); // disable forwarding
				cont.setResponseBody("API key not authorized"); // response to client
				cont.getResponse().setHeader("Content-Type", "text/plain;charset=UTF-8");
				cont.setResponseStatusCode(HttpStatus.UNAUTHORIZED.value());
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
		try {
			Claims claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY))
					.parseClaimsJws(jwt).getBody();
			return claims;
		} catch (Exception e) {
			return null; // we handle this after the function call
		}
	}
}
