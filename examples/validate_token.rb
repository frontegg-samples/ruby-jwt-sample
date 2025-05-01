require_relative '../lib/frontegg_jwt_validator'
require 'dotenv'

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