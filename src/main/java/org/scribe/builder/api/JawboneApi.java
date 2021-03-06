package org.scribe.builder.api;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.scribe.exceptions.OAuthException;
import org.scribe.extractors.AccessTokenExtractor;
import org.scribe.extractors.TokenExtractor20Impl;
import org.scribe.model.OAuthConfig;
import org.scribe.model.Request;
import org.scribe.model.Token;
import org.scribe.utils.OAuthEncoder;
import org.scribe.utils.Preconditions;

public class JawboneApi extends DefaultApi20 {

	@Override
	public String getAccessTokenEndpoint() {
		return "https://jawbone.com/auth/oauth2/token?grant_type=authorization_code";
	}
	
	private String urlEncode(String text) {
		try {
			return URLEncoder.encode(text, "UTF-8");
		} catch (UnsupportedEncodingException e) {
			throw new RuntimeException(e.getMessage());
		}
	}

	@Override
	public String getAuthorizationUrl(OAuthConfig config) {
		return String.format("https://jawbone.com/auth/oauth2/auth?response_type=code&client_id=%s&scope=%s&redirect_uri=%s&state=%s", urlEncode(config.getApiKey()), urlEncode(config.getScope()), urlEncode(config.getCallback()), urlEncode(config.getState()));
	}
	
	@Override
	public AccessTokenExtractor getAccessTokenExtractor() {
		return new AccessTokenExtractor() {
			  private static final String TOKEN_REGEX = "\"access_token\"\\s*:\\s*\"([^\"]+)";
			  private static final String EMPTY_SECRET = "";

			  public Token extract(String response)
			  {
			    Preconditions.checkEmptyString(response, "Response body is incorrect. Can't extract a token from an empty string");

			    Matcher matcher = Pattern.compile(TOKEN_REGEX).matcher(response);
			    if (matcher.find())
			    {
			      String token = OAuthEncoder.decode(matcher.group(1));
			      return new Token(token, EMPTY_SECRET, response);
			    } 
			    else
			    {
			      throw new OAuthException("Response body is incorrect. Can't extract a token from this: '" + response + "'", null);
			    }
			  }
		};
	}
	
	@Override
	public void signRequest(Token accessToken, Request request)
	{
		request.addHeader("Authorization", "Bearer " + accessToken.getToken());
	}

}