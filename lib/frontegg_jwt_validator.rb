require 'jwt'
require 'httparty'
require 'json'
require 'dotenv'

class FronteggJWTValidator
  def initialize(domain)
    @domain = domain
    @config_uri = "https://#{domain}/.well-known/openid-configuration"
    @jwks_uri = nil
    @jwks = nil

    # Fetch JWKS during initialization
    fetch_jwks
  end

  def fetch_configuration
    response = HTTParty.get(@config_uri)
    if response.success?
      config = JSON.parse(response.body)
      @jwks_uri = config['jwks_uri']
      raise "No jwks_uri found in OpenID configuration" unless @jwks_uri
    else
      raise "Failed to fetch OpenID configuration from #{@config_uri}"
    end
  end

  def fetch_jwks
    # Ensure we have the jwks_uri from the configuration
    fetch_configuration unless @jwks_uri

    response = HTTParty.get(@jwks_uri)
    if response.success?
      @jwks = JSON.parse(response.body)
    else
      raise "Failed to fetch JWKS from #{@jwks_uri}"
    end
  end

  def get_signing_key(kid)
    return nil unless @jwks

    key = @jwks['keys'].find { |k| k['kid'] == kid }
    return nil unless key

    # Convert JWK to RSA public key
    JWT::JWK.import(key).public_key
  end

  def validate_token(token)
    # Decode the token header to get the kid
    header = JWT.decode(token, nil, false).last
    kid = header['kid']

    # Get the appropriate signing key
    key = get_signing_key(kid)
    raise "No key found for kid: #{kid}" unless key

    # Validate the token
    decoded_token = JWT.decode(token, key, true, { algorithm: 'RS256' })
    decoded_token.first
  rescue JWT::DecodeError => e
    raise "Invalid token: #{e.message}"
  end
end 