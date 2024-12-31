# frozen_string_literal: true

require 'spec_helper'

RSpec.describe LightJWT::JWT do
  let(:claims) { { sub: '1234567890', name: 'John Doe' } }

  describe '#sign' do
    let(:jws) { described_class.new(claims: claims).sign(alg, signing_key) }

    context 'with HMAC algorithm' do
      let(:alg) { 'HS256' }
      let(:signing_key) { OpenSSL::Random.random_bytes(32) }

      it 'successfully signs the claims' do
        expect(jws.to_s.split('.').size).to eq(3)

        header, payload, signature = jws.to_s.split('.')
        expect(Base64.urlsafe_decode64(header)).to eq('{"alg":"HS256","typ":"JWT"}')
        expect(Base64.urlsafe_decode64(payload)).to eq('{"sub":"1234567890","name":"John Doe"}')
        expect(signature).not_to be_nil
      end
    end

    context 'with RSA algorithm' do
      let(:alg) { 'RS256' }
      let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }
      let(:signing_key) { rsa_key }

      it 'successfully signs the claims' do
        expect(jws.to_s.split('.').size).to eq(3)

        header, payload, signature = jws.to_s.split('.')
        expect(Base64.urlsafe_decode64(header)).to eq('{"alg":"RS256","typ":"JWT"}')
        expect(Base64.urlsafe_decode64(payload)).to eq('{"sub":"1234567890","name":"John Doe"}')
        expect(signature).not_to be_nil
      end
    end
  end

  describe '#encrypt' do
    let(:jwe) { described_class.new(claims: claims).encrypt(alg, enc, rsa_key.public_key) }

    context 'with RSA algorithm' do
      let(:alg) { 'RSA-OAEP' }
      let(:enc) { 'A256GCM' }
      let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }

      it 'successfully encrypts the claims' do
        expect(jwe.to_s.split('.').size).to eq(5)

        header, encrypted_key, iv, ciphertext, auth_tag = jwe.to_s.split('.')
        expect(Base64.urlsafe_decode64(header)).to eq({ alg: 'RSA-OAEP', enc: 'A256GCM' }.to_json)
        expect(encrypted_key).not_to be_nil
        expect(iv).not_to be_nil
        expect(ciphertext).not_to be_nil
        expect(auth_tag).not_to be_nil
      end
    end
  end

  describe '.decode' do
    context 'with a JWS token' do
      let(:jws) { described_class.new(claims: claims).sign(alg, rsa_key) }

      context 'with HMAC algorithm' do
        let(:alg) { 'HS256' }
        let(:rsa_key) { OpenSSL::Random.random_bytes(32) }

        it 'successfully decodes the token' do
          jws2 = described_class.decode(jws.to_s, rsa_key)
          expect(jws2.header.to_json).to eq(jws.header.to_json)
          expect(jws2.payload.to_json).to eq(jws.payload.to_json)
          expect(jws2.signature).not_to be_nil
        end
      end

      context 'with RSA algorithm' do
        let(:alg) { 'RS256' }
        let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }

        it 'successfully decodes the token' do
          jws2 = described_class.decode(jws.to_s, rsa_key.public_key)
          expect(jws2.header.to_json).to eq(jws.header.to_json)
          expect(jws2.payload.to_json).to eq(jws.payload.to_json)
          expect(jws2.signature).not_to be_nil
        end

        context 'with a wrong key' do
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
      let(:jwe) { described_class.new(claims: claims).encrypt(alg, enc, rsa_key.public_key) }

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
          expect(jwe2.plain_text).to eq(jwe.plain_text)
        end

        it 'raises an error when the private key is wrong' do
          wrong_rsa_key = OpenSSL::PKey::RSA.new(2048)
          expect { described_class.decode(jwe.to_s, wrong_rsa_key) }.to raise_error(/decoding/)
        end
      end
    end
  end
end