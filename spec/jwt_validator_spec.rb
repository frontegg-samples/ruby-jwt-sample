require 'spec_helper'
require 'jwt'
require 'webmock/rspec'
require 'base64'

RSpec.describe FronteggJWTValidator do
  let(:domain) { 'auth.loudapi.com' }
  let(:validator) { described_class.new(domain) }
  let(:jwks_uri) { "https://#{domain}/.well-known/openid-configuration/jwks" }
  let(:config_uri) { "https://#{domain}/.well-known/openid-configuration" }

  # Mock RSA key
  let(:mock_public_key) { instance_double(OpenSSL::PKey::RSA, public?: true) }

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

  # Sample OpenID Configuration
  let(:sample_config) do
    {
      "issuer" => "https://#{domain}",
      "jwks_uri" => jwks_uri,
      "authorization_endpoint" => "https://#{domain}/oauth/authorize",
      "token_endpoint" => "https://#{domain}/oauth/token"
    }
  end

  let(:valid_token) { "valid.jwt.token" }
  let(:invalid_token) { "invalid.token" }
  let(:unknown_kid_token) { "unknown.kid.token" }

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

    # Mock RSA key creation
    allow(OpenSSL::PKey::RSA).to receive(:new).and_return(mock_public_key)
    allow(OpenSSL::BN).to receive(:new).and_return(double('BN'))

    # Mock JWT decode
    allow(JWT).to receive(:decode) do |token, key, verify, options|
      case token
      when valid_token
        if verify
          if key == mock_public_key
            [{"sub" => "user123"}, {"kid" => "test-key-1"}]
          else
            raise JWT::VerificationError, "Signature verification failed"
          end
        else
          [{}, {"kid" => "test-key-1"}]
        end
      when invalid_token
        raise JWT::DecodeError, "Invalid segment encoding"
      when unknown_kid_token
        if verify
          raise JWT::DecodeError, "No key found for kid: unknown-key"
        else
          [{}, {"kid" => "unknown-key"}]
        end
      else
        raise JWT::DecodeError, "Unknown token"
      end
    end
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