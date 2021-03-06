package org.scribe.model;

import java.io.*;

/**
 * Parameter object that groups OAuth config values
 * 
 * @author Pablo Fernandez
 */
public class OAuthConfig
{
  private final String apiKey;
  private final String apiSecret;
  private final String callback;
  private final SignatureType signatureType;
  private final String scope;
  private final String state;
  private final boolean sandbox;
  private final OutputStream debugStream;
  
  public OAuthConfig(String key, String secret)
  {
    this(key, secret, null, null, null, null, false, null);
  }

  public OAuthConfig(String key, String secret, String callback, SignatureType type, String scope, String state, boolean sandbox, OutputStream stream)
  {
    this.apiKey = key;
    this.apiSecret = secret;
    this.callback = callback;
    this.signatureType = type;
    this.scope = scope;
    this.state = state;
    this.sandbox = sandbox;
    this.debugStream = stream;
  }

  public String getApiKey()
  {
    return apiKey;
  }

  public String getApiSecret()
  {
    return apiSecret;
  }

  public String getCallback()
  {
    return callback;
  }

  public SignatureType getSignatureType()
  {
    return signatureType;
  }

  public String getScope()
  {
    return scope;
  }
  

  public boolean hasScope()
  {
    return scope != null;
  }
  
public String getState()
{
	return state;
}

public boolean hasState()
{
	return state != null;
}

  public void log(String message)
  {
    if (debugStream != null)
    {
      message = message + "\n";
      try
      {
        debugStream.write(message.getBytes("UTF8"));
      }
      catch (Exception e)
      {
        throw new RuntimeException("there were problems while writing to the debug stream", e);
      }
    }
  }

public boolean isSandbox() {
	return sandbox;
}

}
