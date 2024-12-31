# frozen_string_literal: true

require 'spec_helper'

RSpec.describe LightJWT::JWS do
  let(:payload) { { sub: '1234567890', name: 'John Doe' } }
  let(:header) { { alg: alg, typ: 'JWT' } }
  let(:signing_data) do
    [header, payload].collect do |segment|
      Base64.urlsafe_encode64(segment.to_json, padding: false)
    end.join('.')
  end

  context 'with HMAC algorithms' do
    let(:alg) { 'HS256' }
    let(:signing_key) { OpenSSL::Random.random_bytes(32) }
    let(:jws) { described_class.new(signing_data, alg, signing_key) }

    describe '#sign!' do
      it 'successfully signs the payload' do
        jws.sign!
        expect(jws.to_s.split('.').size).to eq(3)

        header_, payload_, signature = jws.to_s.split('.')
        expect(Base64.urlsafe_decode64(header_)).to eq(header.to_json)
        expect(Base64.urlsafe_decode64(payload_)).to eq(payload.to_json)
        expect(signature).not_to be_nil
      end
    end

    describe '#verify!' do
      before do
        jws.sign!
      end

      context 'with valid signature' do
        before { jws.sign! }
        let(:jws2) { described_class.decode_compact_serialized(jws.to_s, signing_key) }

        it 'successfully' do
          expect(jws2.verify!).to be true
        end
      end

      context 'with invalid signing key' do
        let(:jws2) { described_class.decode_compact_serialized(jws.to_s, OpenSSL::Random.random_bytes(32)) }

        it 'raises an error' do
          expect { jws2.verify! }.to raise_error(LightJWT::Error::VerificationError)
        end
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

      context 'with invalid jwt_token' do
        subject { described_class.decode_compact_serialized('invalid.token', signing_key) }

        it 'raises an error' do
          expect { subject }.to raise_error(ArgumentError)
        end
      end
    end
  end

  context 'with RSA algorithms' do
    let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }
    let(:alg) { 'RS256' }
    let(:signing_key) { rsa_key }
    let(:jws) { described_class.new(signing_data, alg, signing_key) }

    describe '#sign!' do
      it 'successfully signs the payload' do
        jws.sign!
        expect(jws.to_s.split('.').size).to eq(3)

        header_, payload_, signature = jws.to_s.split('.')
        expect(Base64.urlsafe_decode64(header_)).to eq(header.to_json)
        expect(Base64.urlsafe_decode64(payload_)).to eq(payload.to_json)
        expect(signature).not_to be_nil
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

      context 'with invalid public key' do
        let(:jws2) { described_class.decode_compact_serialized(jws.to_s, OpenSSL::PKey::RSA.new(2048).public_key) }

        it 'raises an error' do
          expect { jws2.verify! }.to raise_error(LightJWT::Error::VerificationError)
        end
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

      context 'with invalid jwt_token' do
        subject { described_class.decode_compact_serialized('invalid.token', rsa_key.public_key) }

        it 'raises an error' do
          expect { subject }.to raise_error(ArgumentError)
        end
      end
    end
  end
end
