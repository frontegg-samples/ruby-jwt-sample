require 'jwt'
require 'httparty'
require 'json'
require 'dotenv'

class FronteggJWTValidator
  def initialize(domain)
    @domain = domain
    @jwks_uri = "https://#{domain}/.well-known/openid-configuration/jwks"
    @jwks = nil
  end

  def fetch_jwks
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
    rescue => e
      puts "Error: #{e.message}"
    end
  else
    puts "No token provided. Set FRONTEGG_TOKEN environment variable."
  end
end 