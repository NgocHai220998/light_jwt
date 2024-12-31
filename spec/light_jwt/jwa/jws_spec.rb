# frozen_string_literal: true

require 'spec_helper'

RSpec.describe LightJWT::JWA::JWS do
  let(:data) { 'header.payload' }
  let(:supported_algorithms) { %w[HS256 HS384 HS512 RS256 RS384 RS512 ES256 ES384 ES512 none] }

  describe 'HMAC algorithms' do
    hmac_keys = {
      'HS256' => OpenSSL::Random.random_bytes(32),
      'HS384' => OpenSSL::Random.random_bytes(48),
      'HS512' => OpenSSL::Random.random_bytes(64)
    }

    hmac_keys.each do |alg, key|
      context "with algorithm #{alg}" do
        it 'successfully signs and verifies' do
          signature = described_class.sign(alg, key, data)
          expect(described_class.verify(alg, key, data, signature)).to be true
        end

        it 'fails to sign with a key that is too short' do
          short_key = OpenSSL::Random.random_bytes(key.bytesize - 1)

          expect do
            described_class.sign(alg, short_key, data)
          end.to raise_error(/Signing key must be/)
        end

        it 'fails verification with an incorrect key' do
          signature = described_class.sign(alg, key, data)
          wrong_key = OpenSSL::Random.random_bytes(key.bytesize)
          expect(described_class.verify(alg, wrong_key, data, signature)).to be false
        end

        it 'fails verification with altered data' do
          signature = described_class.sign(alg, key, data)
          altered_data = 'header.altered_payload'
          expect(described_class.verify(alg, key, altered_data, signature)).to be false
        end
      end
    end
  end

  describe 'ECDSA algorithms' do
    private_key_256 = <<~KEY
      -----BEGIN EC PRIVATE KEY-----
      MHcCAQEEIDs7fqgSt///OdhhAmzbbIk95Ejxl7MrEkT4LxZbeYftoAoGCCqGSM49
      AwEHoUQDQgAEIzZCaGIcno1dXioF/NxZeyQpw3ya7sAADZ5CNl1d9lGQo7lmDTr3
      fxKGYwTWllka/zolL+LRsvhhqPD2QfGAyQ==
      -----END EC PRIVATE KEY-----
    KEY

    public_key_256 = <<~KEY
      -----BEGIN PUBLIC KEY-----
      MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIzZCaGIcno1dXioF/NxZeyQpw3ya
      7sAADZ5CNl1d9lGQo7lmDTr3fxKGYwTWllka/zolL+LRsvhhqPD2QfGAyQ==
      -----END PUBLIC KEY-----
    KEY

    curves = {
      'ES256' => 'prime256v1'
      # 'ES384' => 'secp384r1',
      # 'ES512' => 'secp521r1'
    }

    curves.each do |alg, curve|
      context "with algorithm #{alg}" do
        let(:private_key) do
          OpenSSL::PKey::EC.new(private_key_256)
        end

        let(:public_key) { OpenSSL::PKey::EC.new(public_key_256) }

        it 'successfully signs and verifies' do
          signature = described_class.sign(alg, private_key, data)
          expect(described_class.verify(alg, public_key, data, signature)).to be true
        end

        it 'fails verification with an incorrect public key' do
          signature = described_class.sign(alg, private_key, data)
          wrong_public_key = OpenSSL::PKey::EC.generate(curve)
          expect(described_class.verify(alg, wrong_public_key, data, signature)).to be false
        end

        it 'fails verification with altered data' do
          signature = described_class.sign(alg, private_key, data)
          altered_data = 'header.altered_payload'
          expect(described_class.verify(alg, public_key, altered_data, signature)).to be false
        end
      end
    end
  end

  describe '#supported_algorithms' do
    it 'returns a list of supported algorithms' do
      expect(described_class.supported_algorithms).to match_array(supported_algorithms)
    end
  end

  describe 'unsupported algorithms' do
    let(:unsupported_algorithm) { 'RSA1000' }

    it 'raises an error when signing with an unsupported algorithm' do
      expect do
        described_class.sign(unsupported_algorithm, 'key', data)
      end.to raise_error(LightJWT::Error::UnsupportedAlgorithm,
                         "Unsupported JWS algorithm: #{unsupported_algorithm}. Supported algorithms are: #{supported_algorithms.join(', ')}")
    end

    it 'raises an error when verifying with an unsupported algorithm' do
      expect do
        described_class.verify(unsupported_algorithm, 'key', data, 'signature')
      end.to raise_error(LightJWT::Error::UnsupportedAlgorithm,
                         "Unsupported JWS algorithm: #{unsupported_algorithm}. Supported algorithms are: #{supported_algorithms.join(', ')}")
    end
  end
end
