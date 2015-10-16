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

public class IHealthApi extends DefaultApi20 {
	
	private static final String URL_USERAUTHORIZATION_SANDBOX = "http://sandboxapi.ihealthlabs.com/OpenApiV2/OAuthv2/userauthorization/";
	private static final String URL_USERAUTHORIZATION_PRODUCTION = "https://api.ihealthlabs.com:8443/OpenApiV2/OAuthv2/userauthorization/";

	@Override
	public String getAccessTokenEndpoint() {
		//TODO doesn't work with sandbox
		return "https://api.ihealthlabs.com:8443/OpenApiV2/OAuthv2/userauthorization/?grant_type=authorization_code";
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
		String url = config.isSandbox() ? URL_USERAUTHORIZATION_SANDBOX : URL_USERAUTHORIZATION_PRODUCTION;
		
		return String.format(url + "?response_type=code&client_id=%s&APIName=%s&redirect_uri=%s",
					urlEncode(config.getApiKey()),
					urlEncode(config.getScope()),
					urlEncode(config.getCallback()));
	}
	
	@Override
	public AccessTokenExtractor getAccessTokenExtractor() {
		return new AccessTokenExtractor() {
			  private static final String TOKEN_REGEX = "\"AccessToken\"\\s*:\\s*\"([^\"]+)";
			  private static final String EMPTY_SECRET = "";
			  private static final String REFRESH_TOKEN_REGEX = "\"RefreshToken\"\\s*:\\s*\"([^\"]+)";

			  public Token extract(String response)
			  {
			    Preconditions.checkEmptyString(response, "Response body is incorrect. Can't extract a token from an empty string");

			    Matcher matcher = Pattern.compile(TOKEN_REGEX).matcher(response);
			    Matcher matcherRefresh = Pattern.compile(REFRESH_TOKEN_REGEX).matcher(response);
			    if (matcher.find() && matcherRefresh.find())
			    {
			      String token = OAuthEncoder.decode(matcher.group(1));
			      String refreshToken = OAuthEncoder.decode(matcherRefresh.group(1));
			      return new Token(token, EMPTY_SECRET, response, refreshToken);
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