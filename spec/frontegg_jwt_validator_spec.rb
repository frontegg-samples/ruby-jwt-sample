require 'spec_helper'
require 'jwt'
require 'webmock/rspec'

RSpec.describe FronteggJWTValidator do
  let(:domain) { 'auth.loudapi.com' }
  let(:config_uri) { "https://#{domain}/.well-known/openid-configuration" }
  let(:jwks_uri) { "https://#{domain}/.well-known/jwks.json" }

  # Sample OpenID Configuration response
  let(:sample_config) do
    {
      "issuer" => "https://#{domain}",
      "authorization_endpoint" => "https://#{domain}/oauth/authorize",
      "token_endpoint" => "https://#{domain}/oauth/token",
      "userinfo_endpoint" => "https://#{domain}/identity/resources/users/v2/me",
      "jwks_uri" => jwks_uri,
      "scopes_supported" => ["openid", "profile", "email"],
      "response_types_supported" => ["code"],
      "response_modes_supported" => ["query"],
      "grant_types_supported" => ["authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"],
      "subject_types_supported" => ["public"],
      "id_token_signing_alg_values_supported" => ["RS256", "ES256"],
      "token_endpoint_auth_methods_supported" => ["client_secret_basic", "client_secret_post"],
      "token_endpoint_auth_signing_alg_values_supported" => ["RS256", "ES256"],
      "end_session_endpoint" => "https://#{domain}/oauth/logout"
    }
  end

  # Sample JWKS response
  let(:sample_jwks) do
    {
      "keys" => [
        {
          "kty" => "RSA",
          "kid" => "test-key-1",
          "n" => "sample-modulus",
          "e" => "AQAB",
          "use" => "sig",
          "alg" => "RS256"
        }
      ]
    }
  end

  # Sample valid token
  let(:valid_token) do
    JWT.encode(
      { sub: 'user123', exp: Time.now.to_i + 3600 },
      OpenSSL::PKey::RSA.new(2048),
      'RS256',
      { kid: 'test-key-1' }
    )
  end

  before do
    # Stub the OpenID configuration endpoint
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
    it 'sets the domain and fetches JWKS' do
      validator = described_class.new(domain)
      expect(validator.instance_variable_get(:@domain)).to eq(domain)
      expect(validator.instance_variable_get(:@config_uri)).to eq(config_uri)
      expect(validator.instance_variable_get(:@jwks_uri)).to eq(jwks_uri)
      expect(validator.instance_variable_get(:@jwks)).to eq(sample_jwks)
    end

    context 'when configuration fetch fails' do
      before do
        stub_request(:get, config_uri)
          .to_return(status: 500)
      end

      it 'raises an error' do
        expect { described_class.new(domain) }.to raise_error(/Failed to fetch OpenID configuration/)
      end
    end

    context 'when JWKS fetch fails' do
      before do
        stub_request(:get, jwks_uri)
          .to_return(status: 500)
      end

      it 'raises an error' do
        expect { described_class.new(domain) }.to raise_error(/Failed to fetch JWKS/)
      end
    end
  end

  describe '#get_signing_key' do
    let(:validator) { described_class.new(domain) }

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
    let(:validator) { described_class.new(domain) }

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