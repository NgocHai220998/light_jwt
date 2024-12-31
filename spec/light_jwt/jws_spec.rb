# frozen_string_literal: true

require 'spec_helper'

RSpec.describe LightJWT::JWS do
  let(:payload) { { sub: '1234567890', name: 'John Doe' } }
  let(:header) { { alg: alg, typ: 'JWT' } }
  let(:jwt_token) do
    [header, payload].collect do |segment|
      Base64.urlsafe_encode64(segment.to_json, padding: false)
    end.join('.')
  end

  context 'with HMAC algorithms' do
    let(:alg) { 'HS256' }
    let(:signing_key) { OpenSSL::Random.random_bytes(32) }
    let(:jws) { described_class.new(jwt_token, alg, signing_key) }

    describe '#sign!' do
      it 'successfully signs the payload' do
        jws.sign!
        expect(jws.to_s.split('.').size).to eq(3)

        header, payload, signature = jws.to_s.split('.')
        expect(Base64.urlsafe_decode64(header)).to eq('{"alg":"HS256","typ":"JWT"}')
        expect(Base64.urlsafe_decode64(payload)).to eq({ sub: '1234567890', name: 'John Doe' }.to_json)
        expect(signature).not_to be_nil
      end

      context 'raises an error when signing key is too short' do
        let(:signing_key) { OpenSSL::Random.random_bytes(16) }

        it do
          expect { jws.sign! }.to raise_error(/must be at least/)
        end
      end
    end

    describe '#verify!' do
      before do
        jws.sign!
      end

      it 'successfully verifies the signature' do
        expect(jws.verify!).to be true
      end
    end

    describe '#decode_compact_serialized' do
      let(:jws2) { described_class.decode_compact_serialized(jws.to_s, signing_key) }

      before { jws.sign! }

      it 'successfully decodes the token' do
        expect(jws2.header.to_json).to eq(header.to_json)
        expect(jws2.payload.to_json).to eq(payload.to_json)
        expect(jws2.signature).not_to be_nil
      end
    end
  end

  # RSA settings
  context 'with RSA algorithms' do
    let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }
    let(:alg) { 'RS256' }
    let(:signing_key) { rsa_key }
    let(:jws) { described_class.new(jwt_token, alg, signing_key) }

    describe '#sign!' do
      it 'successfully signs the payload' do
        jws.sign!
        expect(jws.to_s.split('.').size).to eq(3)

        header, payload, signature = jws.to_s.split('.')
        expect(Base64.urlsafe_decode64(header)).to eq('{"alg":"RS256","typ":"JWT"}')
        expect(Base64.urlsafe_decode64(payload)).to eq({ sub: '1234567890', name: 'John Doe' }.to_json)
        expect(signature).not_to be_nil
      end

      context 'raises an error when private key is too short' do
        let(:rsa_key) { OpenSSL::PKey::RSA.new(1024) }

        it do
          expect { jws.sign! }.to raise_error(/must be at least/)
        end
      end
    end

    describe '#verify!' do
      before do
        jws.sign!
      end

      let(:jws2) { described_class.decode_compact_serialized(jws.to_s, rsa_key.public_key) }

      it 'successfully verifies the signature' do
        expect(jws2.verify!).to be true
      end
    end

    describe '#decode_compact_serialized' do
      let(:jws2) { described_class.decode_compact_serialized(jws.to_s, rsa_key.public_key) }

      before { jws.sign! }

      it 'successfully decodes the token' do
        expect(jws2.header.to_json).to eq(header.to_json)
        expect(jws2.payload.to_json).to eq(payload.to_json)
        expect(jws2.signature).not_to be_nil
      end

      it 'successfully verifies the signature' do
        expect(jws2.verify!).to be true
      end
    end
  end
end
