require 'spec_helper'
require 'jwt'
require 'webmock/rspec'
require 'base64'

# Generate a single RSA key pair for all tests
TEST_RSA_KEY = OpenSSL::PKey::RSA.new(2048)

RSpec.describe FronteggJWTValidator do
  let(:domain) { 'auth.loudapi.com' }
  let(:validator) { described_class.new(domain) }
  let(:jwks_uri) { "https://#{domain}/.well-known/openid-configuration/jwks" }
  let(:config_uri) { "https://#{domain}/.well-known/openid-configuration" }

  # Create a proper JWK from our RSA key
  let(:jwk) do
    JWT::JWK.new(TEST_RSA_KEY, 'test-key-1').export
  end

  # Sample JWKS response with our actual public key
  let(:sample_jwks) do
    {
      "keys" => [jwk]
    }
  end

  # Sample OpenID Configuration
  let(:sample_config) do
    {
      "issuer" => "https://#{domain}",
      "jwks_uri" => jwks_uri,
      "authorization_endpoint" => "https://#{domain}/oauth/authorize",
      "token_endpoint" => "https://#{domain}/oauth/token"
    }
  end

  # Generate tokens using our RSA key
  let(:valid_token) do
    JWT.encode(
      { sub: 'user123', exp: Time.now.to_i + 3600 },
      TEST_RSA_KEY,
      'RS256',
      { kid: 'test-key-1' }
    )
  end

  let(:invalid_token) { "invalid.token.here" }
  
  let(:unknown_kid_token) do
    JWT.encode(
      { sub: 'user123', exp: Time.now.to_i + 3600 },
      OpenSSL::PKey::RSA.new(2048),
      'RS256',
      { kid: 'unknown-key' }
    )
  end

  before do
    # Stub the OpenID Configuration endpoint
    stub_request(:get, config_uri)
      .to_return(
        status: 200,
        body: sample_config.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )

    # Stub the JWKS endpoint
    stub_request(:get, jwks_uri)
      .to_return(
        status: 200,
        body: sample_jwks.to_json,
        headers: { 'Content-Type' => 'application/json' }
      )
  end

  describe '#initialize' do
    it 'sets the domain and constructs the config URI' do
      expect(validator.instance_variable_get(:@domain)).to eq(domain)
      expect(validator.instance_variable_get(:@config_uri)).to eq(config_uri)
    end
  end

  describe '#fetch_jwks' do
    it 'fetches and parses the JWKS' do
      validator.fetch_jwks
      expect(validator.instance_variable_get(:@jwks)).to eq(sample_jwks)
    end

    context 'when the request fails' do
      before do
        stub_request(:get, jwks_uri)
          .to_return(status: 500)
      end

      it 'raises an error' do
        expect { validator.fetch_jwks }.to raise_error(/Failed to fetch JWKS/)
      end
    end
  end

  describe '#get_signing_key' do
    before do
      validator.fetch_jwks
    end

    it 'returns nil for unknown key ID' do
      expect(validator.get_signing_key('unknown-key')).to be_nil
    end

    it 'returns a public key for known key ID' do
      key = validator.get_signing_key('test-key-1')
      expect(key).to be_a(OpenSSL::PKey::RSA)
      expect(key.public?).to be true
    end
  end

  describe '#validate_token' do
    before do
      validator.fetch_jwks
    end

    it 'validates a valid token' do
      payload = validator.validate_token(valid_token)
      expect(payload).to include('sub' => 'user123')
    end

    it 'raises an error for an invalid token' do
      expect { validator.validate_token(invalid_token) }
        .to raise_error(JWT::DecodeError, /Invalid segment encoding/)
    end

    it 'raises an error for a token with unknown kid' do
      expect { validator.validate_token(unknown_kid_token) }
        .to raise_error(JWT::DecodeError, /No key found for kid/)
    end
  end
end 