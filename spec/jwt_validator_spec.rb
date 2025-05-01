require 'spec_helper'
require 'jwt'
require 'webmock/rspec'

RSpec.describe FronteggJWTValidator do
  let(:domain) { 'auth.loudapi.com' }
  let(:validator) { described_class.new(domain) }
  let(:jwks_uri) { "https://#{domain}/.well-known/openid-configuration/jwks" }
  let(:config_uri) { "https://#{domain}/.well-known/openid-configuration" }

  # Generate a key pair for testing
  let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:jwk) { JWT::JWK.new(rsa_key) }

  # Sample JWKS response
  let(:sample_jwks) do
    {
      "keys" => [
        {
          "kty" => "RSA",
          "kid" => "test-key-1",
          "n" => Base64.urlsafe_encode64(rsa_key.n.to_s(2)),
          "e" => Base64.urlsafe_encode64(rsa_key.e.to_s(2)),
          "use" => "sig",
          "alg" => "RS256"
        }
      ]
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

  # Sample valid token
  let(:valid_token) do
    JWT.encode(
      { sub: 'user123', exp: Time.now.to_i + 3600 },
      rsa_key,
      'RS256',
      { kid: 'test-key-1' }
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
      invalid_token = 'invalid.token.here'
      expect { validator.validate_token(invalid_token) }.to raise_error(JWT::DecodeError)
    end

    it 'raises an error for a token with unknown kid' do
      token_with_unknown_kid = JWT.encode(
        { sub: 'user123' },
        OpenSSL::PKey::RSA.new(2048),
        'RS256',
        { kid: 'unknown-key' }
      )
      expect { validator.validate_token(token_with_unknown_kid) }.to raise_error(/No key found for kid/)
    end
  end
end 