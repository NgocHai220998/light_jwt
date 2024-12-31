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
          end.to raise_error(LightJWT::Error::InvalidKey)
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

  describe 'RSA algorithms' do
    rsa_keys = {
      'RS256' => OpenSSL::PKey::RSA.generate(2048),
      'RS384' => OpenSSL::PKey::RSA.generate(2048),
      'RS512' => OpenSSL::PKey::RSA.generate(2048)
    }

    rsa_keys.each do |alg, key|
      context "with algorithm #{alg}" do
        it 'successfully signs and verifies' do
          signature = described_class.sign(alg, key, data)
          expect(described_class.verify(alg, key.public_key, data, signature)).to be true
        end

        it 'fails to sign with an short key' do
          short_key = OpenSSL::PKey::RSA.generate(1024)

          expect do
            described_class.sign(alg, short_key, data)
          end.to raise_error(LightJWT::Error::InvalidKey)
        end

        it 'fails verification with an incorrect key' do
          signature = described_class.sign(alg, key, data)
          wrong_key = OpenSSL::PKey::RSA.generate(2048)
          expect(described_class.verify(alg, wrong_key, data, signature)).to be false
        end

        it 'fails verification with altered data' do
          signature = described_class.sign(alg, key, data)
          altered_data = 'header.altered_payload'
          expect(described_class.verify(alg, key.public_key, altered_data, signature)).to be false
        end
      end
    end
  end

  describe 'ECDSA algorithms' do
    context 'with algorithm ES256' do
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

      let(:private_key) { OpenSSL::PKey::EC.new(private_key_256) }
      let(:public_key) { OpenSSL::PKey::EC.new(public_key_256) }
      let(:alg) { 'ES256' }

      it 'successfully signs and verifies' do
        signature = described_class.sign(alg, private_key, data)
        expect(described_class.verify(alg, public_key, data, signature)).to be true
      end

      context 'fails signing with an invalid private key' do
        invalid_private_key_256 = <<~KEY
          -----BEGIN EC PRIVATE KEY-----
          Invalid
          -----END EC PRIVATE KEY-----
        KEY
        let(:invalid_private_key) { OpenSSL::PKey::EC.new(invalid_private_key_256) }

        it do
          expect do
            described_class.sign(alg, invalid_private_key, data)
          end.to raise_error(OpenSSL::PKey::ECError)
        end
      end

      it 'fails verification with an incorrect public key' do
        signature = described_class.sign(alg, private_key, data)
        wrong_public_key = OpenSSL::PKey::EC.generate('prime256v1')
        expect(described_class.verify(alg, wrong_public_key, data, signature)).to be false
      end

      it 'fails verification with altered data' do
        signature = described_class.sign(alg, private_key, data)
        altered_data = 'header.altered_payload'
        expect(described_class.verify(alg, public_key, altered_data, signature)).to be false
      end
    end

    context 'with algorithm ES384' do
      private_key_384 = <<~KEY
        -----BEGIN EC PRIVATE KEY-----
        MIGkAgEBBDCGc5IaEoxXVFDgc5IwJax4AogQhhsfeVrhMoS6ts6CKwY0ma/77vB+
        iqOBAnxDMpmgBwYFK4EEACKhZANiAASCflY+qAmpLp7gw7aO56fMZBeQ2K241Xhk
        U2K+upaUrIR3VK9uiE7fcCzMwQNSS33vcJexjdaOnz015ZscPbSluzaLSf7+d7Gl
        hgRX9vCU7ER3kLh9oBUc5WMo4B8qejg=
        -----END EC PRIVATE KEY-----
      KEY

      public_key_384 = <<~KEY
        -----BEGIN PUBLIC KEY-----
        MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgn5WPqgJqS6e4MO2juenzGQXkNituNV4
        ZFNivrqWlKyEd1SvbohO33AszMEDUkt973CXsY3Wjp89NeWbHD20pbs2i0n+/nex
        pYYEV/bwlOxEd5C4faAVHOVjKOAfKno4
        -----END PUBLIC KEY-----
      KEY

      let(:private_key) { OpenSSL::PKey::EC.new(private_key_384) }
      let(:public_key) { OpenSSL::PKey::EC.new(public_key_384) }
      let(:alg) { 'ES384' }

      it 'successfully signs and verifies' do
        signature = described_class.sign(alg, private_key, data)
        expect(described_class.verify(alg, public_key, data, signature)).to be true
      end

      context 'fails signing with an invalid private key' do
        invalid_private_key_384 = <<~KEY
          -----BEGIN EC PRIVATE KEY-----
          Invalid
          -----END EC PRIVATE KEY-----
        KEY
        let(:invalid_private_key) { OpenSSL::PKey::EC.new(invalid_private_key_384) }

        it do
          expect do
            described_class.sign(alg, invalid_private_key, data)
          end.to raise_error(OpenSSL::PKey::ECError)
        end
      end

      it 'fails verification with an incorrect public key' do
        signature = described_class.sign(alg, private_key, data)
        wrong_public_key = OpenSSL::PKey::EC.generate('secp384r1')
        expect(described_class.verify(alg, wrong_public_key, data, signature)).to be false
      end

      it 'fails verification with altered data' do
        signature = described_class.sign(alg, private_key, data)
        altered_data = 'header.altered_payload'
        expect(described_class.verify(alg, public_key, altered_data, signature)).to be false
      end
    end

    context 'with algorithm ES512' do
      private_key_512 = <<~KEY
        -----BEGIN EC PRIVATE KEY-----
        MIHcAgEBBEIAoIhwDTajsCVHram127Z5m5EqkC3pTyrwrcrrg/cbzkIfX+GH0VMh
        cjo41SxdjxBVgx7p7qWcj3JoNWbvSPH3KUGgBwYFK4EEACOhgYkDgYYABAGCrzUD
        9c6BbzUSMmwvWzi8qidq8xBVmOKeRT1Ws8R2OIHfnBvuqxxz/VdWJ4/10o8L31RU
        XpCAobq6bRfckCC4EQHW5RggJSL1S6QdGkbtPkWYEV2RhLFMiiMFvVK3CPdCXZZZ
        HZLwWrPwCxf+kLHOvJrmTx5K/3ZtAZfFeeEAuJoJ9w==
        -----END EC PRIVATE KEY-----
      KEY

      public_key_512 = <<~KEY
        -----BEGIN PUBLIC KEY-----
        MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBgq81A/XOgW81EjJsL1s4vKonavMQ
        VZjinkU9VrPEdjiB35wb7qscc/1XVieP9dKPC99UVF6QgKG6um0X3JAguBEB1uUY
        ICUi9UukHRpG7T5FmBFdkYSxTIojBb1Stwj3Ql2WWR2S8Fqz8AsX/pCxzrya5k8e
        Sv92bQGXxXnhALiaCfc=
        -----END PUBLIC KEY-----
      KEY

      let(:private_key) { OpenSSL::PKey::EC.new(private_key_512) }
      let(:public_key) { OpenSSL::PKey::EC.new(public_key_512) }
      let(:alg) { 'ES512' }

      it 'successfully signs and verifies' do
        signature = described_class.sign(alg, private_key, data)
        expect(described_class.verify(alg, public_key, data, signature)).to be true
      end

      context 'fails signing with an invalid private key' do
        invalid_private_key_512 = <<~KEY
          -----BEGIN EC PRIVATE KEY-----
          Invalid
          -----END EC PRIVATE KEY-----
        KEY
        let(:invalid_private_key) { OpenSSL::PKey::EC.new(invalid_private_key_512) }

        it do
          expect do
            described_class.sign(alg, invalid_private_key, data)
          end.to raise_error(OpenSSL::PKey::ECError)
        end
      end

      it 'fails verification with an incorrect public key' do
        signature = described_class.sign(alg, private_key, data)
        wrong_public_key = OpenSSL::PKey::EC.generate('secp521r1')
        expect(described_class.verify(alg, wrong_public_key, data, signature)).to be false
      end

      it 'fails verification with altered data' do
        signature = described_class.sign(alg, private_key, data)
        altered_data = 'header.altered_payload'
        expect(described_class.verify(alg, public_key, altered_data, signature)).to be false
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
