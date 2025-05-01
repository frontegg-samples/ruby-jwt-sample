require 'jwt'
require 'httparty'
require 'json'
require 'dotenv'
require 'base64'

class FronteggJWTValidator
  def initialize(domain)
    @domain = domain
    @config_uri = "https://#{domain}/.well-known/openid-configuration"
    @jwks_uri = nil
    @jwks = nil
  end

  def fetch_jwks
    # First fetch the OpenID Configuration to get the JWKS URI
    config_response = HTTParty.get(@config_uri)
    unless config_response.success?
      raise "Failed to fetch OpenID Configuration from #{@config_uri}"
    end

    config = JSON.parse(config_response.body)
    @jwks_uri = config['jwks_uri']

    # Now fetch the JWKS
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

    # Convert JWK to PEM format
    n = Base64.urlsafe_decode64(key['n'])
    e = Base64.urlsafe_decode64(key['e'])
    
    # Create RSA key from components
    rsa_key = OpenSSL::PKey::RSA.new
    rsa_key.set_key(OpenSSL::BN.new(n, 2), OpenSSL::BN.new(e, 2), nil)
    rsa_key
  end

  def validate_token(token)
    # Decode the token header to get the kid
    begin
      header = JWT.decode(token, nil, false).last
      kid = header['kid']

      # Get the appropriate signing key
      key = get_signing_key(kid)
      raise JWT::DecodeError, "No key found for kid: #{kid}" unless key

      # Validate the token
      decoded_token = JWT.decode(token, key, true, { algorithm: 'RS256' })
      decoded_token.first
    rescue JWT::DecodeError => e
      raise JWT::DecodeError, e.message
    rescue JWT::VerificationError => e
      raise JWT::DecodeError, "Signature verification failed"
    rescue StandardError => e
      raise JWT::DecodeError, e.message
    end
  end
end

# Example usage:
if __FILE__ == $0
  # Load environment variables
  Dotenv.load

  # Get domain from environment variable or use default
  domain = ENV['FRONTEGG_DOMAIN'] || 'auth.loudapi.com'

  # Initialize validator
  validator = FronteggJWTValidator.new(domain)

  # Fetch JWKS
  validator.fetch_jwks

  # Example token (replace with actual token)
  token = ENV['FRONTEGG_TOKEN']
  
  if token
    begin
      # Validate token
      payload = validator.validate_token(token)
      puts "Token is valid!"
      puts "Payload: #{JSON.pretty_generate(payload)}"
    rescue JWT::DecodeError => e
      puts "Error: #{e.message}"
    end
  else
    puts "No token provided. Set FRONTEGG_TOKEN environment variable."
  end
end 