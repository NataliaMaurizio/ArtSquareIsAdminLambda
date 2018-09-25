package com.amazonaws.lambda.core;

import java.util.List;

import com.amazonaws.lambda.domain.JwtRequest;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.RSAKeyProvider;

public class LambdaFunctionHandler implements RequestHandler<JwtRequest, Boolean> {

	/** cognito region **/
	static final private String AWS_REGION = "eu-west-2";

	/** cognito user pools id **/
	static final private String AWS_USER_POOLS_ID = "eu-west-2_DV2qf0sqZ";

	/** the key name of the access token's roles claim **/
	static final private String AWS_ROLES_CLAIM = "cognito:roles";

	/** the key for the admin user in the pool **/
	static final private String AWS_ADMIN_ROLE_ARN = "arn:aws:iam::663403055898:role/artsquare-role";

	@Override
	public Boolean handleRequest(JwtRequest input, Context context) {
		context.getLogger().log("Input: " + input);

		if (input.getJwt() != null && !input.getJwt().isEmpty()) {

			List<String> roles = getUserRoles(input.getJwt());

			/* The user requiring this operation has an admin role */
			if (roles != null && roles.contains(AWS_ADMIN_ROLE_ARN)) {
				return true;
			} else {
				return false;
			}

		} else {
			return false;
		}
	}

	/**
	 * @param accessToken
	 *            cognito access token
	 * @return the cognito user roles extracted from the provided access token
	 */
	private List<String> getUserRoles(String accessToken) {

		RSAKeyProvider keyProvider = new AwsCognitoRSAKeyProvider(AWS_REGION, AWS_USER_POOLS_ID);
		JWTVerifier jwtVerifier = JWT.require(Algorithm.RSA256(keyProvider)).build();

		Claim rolesClaim = null;

		try {
			rolesClaim = jwtVerifier.verify(accessToken).getClaim(AWS_ROLES_CLAIM);
		} catch (JWTVerificationException e) {
			e.printStackTrace();
		}

		if (rolesClaim != null)
			return rolesClaim.asList(String.class);
		return null;
	}

}
