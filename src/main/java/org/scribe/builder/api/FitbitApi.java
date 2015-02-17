package org.scribe.builder.api;

import org.scribe.model.Token;

public class FitbitApi extends DefaultApi10a {

	@Override
	public String getRequestTokenEndpoint() {
		return "https://api.fitbit.com/oauth/request_token";
	}

	@Override
	public String getAccessTokenEndpoint() {
		return "https://api.fitbit.com/oauth/access_token";
	}

	@Override
	public String getAuthorizationUrl(Token requestToken) {
		return String.format("https://fitbit.com/oauth/authorize?oauth_token=%s", requestToken.getToken());
	}
}
