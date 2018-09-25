package com.amazonaws.lambda.domain;

public class JwtRequest {

	private String jwt;

	public JwtRequest() {

	}

	/**
	 * @param jwt
	 */
	public JwtRequest(String jwt) {
		this.jwt = jwt;
	}

	public String getJwt() {
		return jwt;
	}

	public void setJwt(String jwt) {
		this.jwt = jwt;
	}

}
