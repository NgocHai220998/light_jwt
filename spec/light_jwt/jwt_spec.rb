# frozen_string_literal: true

require 'spec_helper'

RSpec.describe LightJWT::JWT do
  let(:claims) { { sub: '1234567890', name: 'John Doe' } }

  describe '#sign' do
    let(:jws) { described_class.new(claims).sign(alg, signing_key) }

    context 'with HMAC algorithm' do
      let(:header) { { alg:, typ: 'JWT' } }

      context 'with SHA-256' do
        let(:alg) { 'HS256' }
        let(:signing_key) { OpenSSL::Random.random_bytes(32) }

        it 'successfully signs the claims' do
          expect(jws.to_s.split('.').size).to eq(3)

          header_, payload_, signature = jws.to_s.split('.')
          expect(Base64.urlsafe_decode64(header_)).to eq(header.to_json)
          expect(Base64.urlsafe_decode64(payload_)).to eq(claims.to_json)
          expect(signature).not_to be_nil
        end
      end

      context 'with SHA-384' do
        let(:alg) { 'HS384' }
        let(:signing_key) { OpenSSL::Random.random_bytes(48) }

        it 'successfully signs the claims' do
          expect(jws.to_s.split('.').size).to eq(3)

          header_, payload_, signature = jws.to_s.split('.')
          expect(Base64.urlsafe_decode64(header_)).to eq(header.to_json)
          expect(Base64.urlsafe_decode64(payload_)).to eq(claims.to_json)
          expect(signature).not_to be_nil
        end
      end

      context 'with SHA-512' do
        let(:alg) { 'HS512' }
        let(:signing_key) { OpenSSL::Random.random_bytes(64) }

        it 'successfully signs the claims' do
          expect(jws.to_s.split('.').size).to eq(3)

          header_, payload_, signature = jws.to_s.split('.')
          expect(Base64.urlsafe_decode64(header_)).to eq(header.to_json)
          expect(Base64.urlsafe_decode64(payload_)).to eq(claims.to_json)
          expect(signature).not_to be_nil
        end
      end

      context 'with invalid algorithm' do
        let(:alg) { 'HS1024' }
        let(:signing_key) { OpenSSL::Random.random_bytes(32) }

        it 'raises an error' do
          expect { jws }.to raise_error(LightJWT::Error::UnsupportedAlgorithm)
        end
      end
    end

    context 'with RSA algorithm' do
      let(:header) { { alg:, typ: 'JWT' } }

      context 'with RSA-256' do
        let(:alg) { 'RS256' }
        let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }
        let(:signing_key) { rsa_key }

        it 'successfully signs the claims' do
          expect(jws.to_s.split('.').size).to eq(3)

          _header, _payload, signature = jws.to_s.split('.')
          expect(Base64.urlsafe_decode64(_header)).to eq(header.to_json)
          expect(Base64.urlsafe_decode64(_payload)).to eq(claims.to_json)
          expect(signature).not_to be_nil
        end
      end

      context 'with RSA-384' do
        let(:alg) { 'RS384' }
        let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }
        let(:signing_key) { rsa_key }

        it 'successfully signs the claims' do
          expect(jws.to_s.split('.').size).to eq(3)

          _header, _payload, signature = jws.to_s.split('.')
          expect(Base64.urlsafe_decode64(_header)).to eq(header.to_json)
          expect(Base64.urlsafe_decode64(_payload)).to eq(claims.to_json)
          expect(signature).not_to be_nil
        end
      end

      context 'with RSA-512' do
        let(:alg) { 'RS512' }
        let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }
        let(:signing_key) { rsa_key }

        it 'successfully signs the claims' do
          expect(jws.to_s.split('.').size).to eq(3)

          _header, _payload, signature = jws.to_s.split('.')
          expect(Base64.urlsafe_decode64(_header)).to eq(header.to_json)
          expect(Base64.urlsafe_decode64(_payload)).to eq(claims.to_json)
          expect(signature).not_to be_nil
        end
      end

      context 'with invalid algorithm' do
        let(:alg) { 'RS1024' }
        let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }
        let(:signing_key) { rsa_key }

        it 'raises an error' do
          expect { jws }.to raise_error(LightJWT::Error::UnsupportedAlgorithm)
        end
      end
    end
  end

  describe '#encrypt' do
    let(:jwe) { described_class.new(claims).encrypt(alg, enc, rsa_key.public_key) }

    context 'with RSA algorithm' do
      context 'with RSA-OAEP and A256GCM' do
        let(:alg) { 'RSA-OAEP' }
        let(:enc) { 'A256GCM' }
        let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }

        it 'successfully encrypts the claims' do
          expect(jwe.to_s.split('.').size).to eq(5)

          header, encrypted_key, iv, ciphertext, auth_tag = jwe.to_s.split('.')
          expect(Base64.urlsafe_decode64(header)).to eq({ alg:, enc: }.to_json)
          expect(encrypted_key).not_to be_nil
          expect(iv).not_to be_nil
          expect(ciphertext).not_to be_nil
          expect(auth_tag).not_to be_nil
        end
      end

      context 'with RSA-OAEP and A128GCM' do
        let(:alg) { 'RSA-OAEP' }
        let(:enc) { 'A128GCM' }
        let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }

        it 'successfully encrypts the claims' do
          expect(jwe.to_s.split('.').size).to eq(5)

          header, encrypted_key, iv, ciphertext, auth_tag = jwe.to_s.split('.')
          expect(Base64.urlsafe_decode64(header)).to eq({ alg:, enc: }.to_json)
          expect(encrypted_key).not_to be_nil
          expect(iv).not_to be_nil
          expect(ciphertext).not_to be_nil
          expect(auth_tag).not_to be_nil
        end
      end

      context 'with RSA1_5 and A128GCM' do
        let(:alg) { 'RSA1_5' }
        let(:enc) { 'A128GCM' }
        let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }

        it 'successfully encrypts the claims' do
          expect(jwe.to_s.split('.').size).to eq(5)

          header, encrypted_key, iv, ciphertext, auth_tag = jwe.to_s.split('.')
          expect(Base64.urlsafe_decode64(header)).to eq({ alg:, enc: }.to_json)
          expect(encrypted_key).not_to be_nil
          expect(iv).not_to be_nil
          expect(ciphertext).not_to be_nil
          expect(auth_tag).not_to be_nil
        end
      end

      context 'with RSA1_5 and A256GCM' do
        let(:alg) { 'RSA1_5' }
        let(:enc) { 'A256GCM' }
        let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }

        it 'successfully encrypts the claims' do
          expect(jwe.to_s.split('.').size).to eq(5)

          header, encrypted_key, iv, ciphertext, auth_tag = jwe.to_s.split('.')
          expect(Base64.urlsafe_decode64(header)).to eq({ alg:, enc: }.to_json)
          expect(encrypted_key).not_to be_nil
          expect(iv).not_to be_nil
          expect(ciphertext).not_to be_nil
          expect(auth_tag).not_to be_nil
        end
      end
    end
  end

  describe '.decode' do
    context 'with a JWS token' do
      let(:jws) { described_class.new(claims).sign(alg, rsa_key) }

      context 'with HMAC algorithm' do
        context 'with SHA-256' do
          let(:alg) { 'HS256' }
          let(:rsa_key) { OpenSSL::Random.random_bytes(32) }

          it 'successfully decodes the token' do
            jws2 = described_class.decode(jws.to_s, rsa_key)
            expect(jws2.header.to_json).to eq(jws.header.to_json)
            expect(jws2.payload.to_json).to eq(jws.payload.to_json)
            expect(jws2.signature).not_to be_nil
          end
        end

        context 'with SHA-384' do
          let(:alg) { 'HS384' }
          let(:rsa_key) { OpenSSL::Random.random_bytes(48) }

          it 'successfully decodes the token' do
            jws2 = described_class.decode(jws.to_s, rsa_key)
            expect(jws2.header.to_json).to eq(jws.header.to_json)
            expect(jws2.payload.to_json).to eq(jws.payload.to_json)
            expect(jws2.signature).not_to be_nil
          end
        end

        context 'with SHA-512' do
          let(:alg) { 'HS512' }
          let(:rsa_key) { OpenSSL::Random.random_bytes(64) }

          it 'successfully decodes the token' do
            jws2 = described_class.decode(jws.to_s, rsa_key)
            expect(jws2.header.to_json).to eq(jws.header.to_json)
            expect(jws2.payload.to_json).to eq(jws.payload.to_json)
            expect(jws2.signature).not_to be_nil
          end
        end

        context 'with invalid algorithm' do
          let(:alg) { 'HS1024' }
          let(:rsa_key) { OpenSSL::Random.random_bytes(32) }

          it 'raises an error' do
            expect do
              described_class.decode(jws.to_s, rsa_key)
            end.to raise_error(LightJWT::Error::UnsupportedAlgorithm)
          end
        end
      end

      context 'with RSA algorithm' do
        context 'with RSA-256' do
          let(:alg) { 'RS256' }
          let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }

          it 'successfully decodes the token' do
            jws2 = described_class.decode(jws.to_s, rsa_key.public_key)
            expect(jws2.header.to_json).to eq(jws.header.to_json)
            expect(jws2.payload.to_json).to eq(jws.payload.to_json)
            expect(jws2.signature).not_to be_nil
          end

          context 'with JWK' do
            let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }
            let(:jwks_uri) { 'https://example.com/.well-known/jwks.json' }
            let(:jwk_response) do
              {
                keys: [
                  {
                    kty: 'RSA',
                    use: 'sig',
                    alg: 'RS256',
                    kid: 'valid-key',
                    n: Base64.urlsafe_encode64(rsa_key.n.to_s(2)),
                    e: Base64.urlsafe_encode64(rsa_key.e.to_s(2))
                  }
                ]
              }.to_json
            end

            before do
              stub_request(:get, jwks_uri)
                .to_return(status: 200, body: jwk_response, headers: { 'Content-Type' => 'application/json' })
            end

            it 'successfully decodes the token' do
              jwk = LightJWT::JWK.new(jwks_uri)
              key = jwk.get('valid-key')

              jws2 = described_class.decode(jws.to_s, key)
              expect(jws2.header).to eq(jws.header)
              expect(jws2.payload).to eq(jws.payload)
              expect(jws2.signature).not_to be_nil

              jws3 = described_class.decode(jws.to_s, key.public_key)
              expect(jws3.header).to eq(jws.header)
              expect(jws3.payload).to eq(jws.payload)
              expect(jws3.signature).not_to be_nil
            end
          end
        end

        context 'with RSA-384' do
          let(:alg) { 'RS384' }
          let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }

          it 'successfully decodes the token' do
            jws2 = described_class.decode(jws.to_s, rsa_key.public_key)
            expect(jws2.header.to_json).to eq(jws.header.to_json)
            expect(jws2.payload.to_json).to eq(jws.payload.to_json)
            expect(jws2.signature).not_to be_nil
          end
        end

        context 'with RSA-512' do
          let(:alg) { 'RS512' }
          let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }

          it 'successfully decodes the token' do
            jws2 = described_class.decode(jws.to_s, rsa_key.public_key)
            expect(jws2.header.to_json).to eq(jws.header.to_json)
            expect(jws2.payload.to_json).to eq(jws.payload.to_json)
            expect(jws2.signature).not_to be_nil
          end
        end

        context 'with invalid algorithm' do
          let(:alg) { 'RS1024' }
          let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }

          it 'raises an error' do
            expect do
              described_class.decode(jws.to_s, rsa_key.public_key)
            end.to raise_error(LightJWT::Error::UnsupportedAlgorithm)
          end
        end

        context 'with a wrong key' do
          let(:alg) { 'RS256' }
          let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }
          let(:wrong_rsa_key) { OpenSSL::PKey::RSA.new(2048) }

          it 'raises an error' do
            expect do
              described_class.decode(jws.to_s, wrong_rsa_key.public_key)
            end.to raise_error(LightJWT::Error::VerificationError)
          end

          it 'not raises an error when passing :skip_verification true' do
            jws2 = described_class.decode(jws.to_s, skip_verification: true)
            expect(jws2.header.to_json).to eq(jws.header.to_json)
            expect(jws2.payload.to_json).to eq(jws.payload.to_json)
            expect(jws2.signature).not_to be_nil
          end
        end
      end
    end

    context 'with a JWE token' do
      let(:jwe) { described_class.new(claims).encrypt(alg, enc, rsa_key.public_key) }

      context 'with RSA algorithm' do
        let(:alg) { 'RSA-OAEP' }
        let(:enc) { 'A256GCM' }
        let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }

        it 'successfully decodes the token' do
          jwe2 = described_class.decode(jwe.to_s, rsa_key)
          expect(jwe2.encrypted_key).to eq(jwe.encrypted_key)
          expect(jwe2.iv).to eq(jwe.iv)
          expect(jwe2.ciphertext).to eq(jwe.ciphertext)
          expect(jwe2.auth_tag).to eq(jwe.auth_tag)
          expect(jwe2.payload).to eq(jwe.payload)
        end

        it 'raises an error when the private key is wrong' do
          wrong_rsa_key = OpenSSL::PKey::RSA.new(2048)
          expect { described_class.decode(jwe.to_s, wrong_rsa_key) }.to raise_error(/decoding/)
        end
      end
    end
  end
end
