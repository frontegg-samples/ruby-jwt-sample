# Frontegg JWT Token Validator

A Ruby library for validating Frontegg JWT tokens. This library fetches the JSON Web Key Set (JWKS) from Frontegg's well-known OIDC endpoint and uses it to validate JWT tokens.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'frontegg_jwt_validator'
```

And then execute:

```bash
bundle install
```

Or install it yourself as:

```bash
gem install frontegg_jwt_validator
```

## Usage

### Basic Usage

```ruby
require 'frontegg_jwt_validator'

# Initialize the validator with your Frontegg domain
validator = FronteggJWTValidator.new('acme.frontegg.com')

# Fetch the JWKS
validator.fetch_jwks

# Validate a token
begin
  payload = validator.validate_token('your.jwt.token')
  puts "Token is valid!"
  puts "Payload: #{payload}"
rescue => e
  puts "Error: #{e.message}"
end
```

### Using Environment Variables

Create a `.env` file in your project root:

```
FRONTEGG_DOMAIN=your-frontegg-domain
FRONTEGG_TOKEN=your-jwt-token
```

Then use the example script:

```bash
ruby examples/validate_token.rb
```

## Development

After checking out the repo, run `bundle install` to install dependencies.

### Running Tests

Run the test suite:

```bash
bundle exec rspec
```

## How it Works

1. The validator fetches the JSON Web Key Set (JWKS) from Frontegg's well-known OIDC endpoint
2. It extracts the appropriate signing key based on the token's `kid` (Key ID)
3. The token is validated using the public key
4. If valid, the token payload is returned

## Error Handling

The validator will raise exceptions for:

- Invalid tokens
- Missing or invalid JWKS
- Missing or invalid signing keys
- Network errors when fetching JWKS

## Security Notes

- Always validate tokens in a secure environment
- Keep your tokens secure and never expose them in logs or error messages
- Use HTTPS for all communications
- Regularly update the JWKS as keys may rotate

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/yourusername/frontegg_jwt_validator.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
