# frozen_string_literal: true

require 'spec_helper'

RSpec.describe LightJWT::JWK do
  context 'When the JWK for :sig' do
    context 'is a RSA key' do
      let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
      let(:public_key) { private_key.public_key }
      let(:jwks_uri) { 'https://example.com/.well-known/jwks.json' }
      let(:jwk_response) do
        {
          keys: [
            {
              kty: 'RSA',
              use: 'sig',
              alg: 'RS256',
              kid: 'valid-key',
              n: Base64.urlsafe_encode64(private_key.n.to_s(2)),
              e: Base64.urlsafe_encode64(private_key.e.to_s(2))
            }
          ]
        }.to_json
      end

      before do
        stub_request(:get, jwks_uri)
          .to_return(status: 200, body: jwk_response, headers: { 'Content-Type' => 'application/json' })
      end

      it 'fetches the JWK and builds the public key' do
        jwk = described_class.new(jwks_uri)
        key = jwk.get('valid-key')

        expect(key.kty).to eq('RSA')
        expect(key.use).to eq('sig')
        expect(key.alg).to eq('RS256')
        expect(key.kid).to eq('valid-key')
        expect(key.n).to eq(Base64.urlsafe_encode64(private_key.n.to_s(2)))
        expect(key.e).to eq(Base64.urlsafe_encode64(private_key.e.to_s(2)))

        expect(key.public_key.to_pem).to eq(public_key.to_pem)
      end

      it 'success verification' do
        jwk = described_class.new(jwks_uri)
        key = jwk.get('valid-key')
        jws = LightJWT::JWT.new(claims: { sub: '1234567890', name: 'John Doe' }).sign('RS256', private_key)
        jws2 = LightJWT::JWT.decode(jws.to_s, key.public_key)

        expect(jws2.header.to_json).to eq('{"alg":"RS256","typ":"JWT"}')
        expect(jws2.payload.to_json).to eq('{"sub":"1234567890","name":"John Doe"}')
        expect(jws2.signature).not_to be_nil

        # Raises an error when the public key is invalid
        expect { LightJWT::JWT.decode(jws.to_s, OpenSSL::PKey::RSA.new(2048).public_key) }.to raise_error(LightJWT::Error::VerificationError)
      end
    end

    context 'is an EC key' do
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

      public_key_ = OpenSSL::PKey::EC.new(public_key_256)
      ec_point_ = public_key_.public_key
      octet_string_ = ec_point_.to_octet_string(:uncompressed)
      x, y = octet_string_[1..].scan(/.{1,32}/).map do |coord|
        Base64.urlsafe_encode64(coord)
      end

      let(:private_key) { OpenSSL::PKey::EC.new(private_key_256) }
      let(:public_key) { OpenSSL::PKey::EC.new(public_key_256) }
      let(:jwks_uri) { 'https://example.com/.well-known/jwks.json' }
      let(:jwk_response) do
        {
          keys: [
            {
              kty: 'EC',
              use: 'sig',
              alg: 'ES256',
              kid: 'valid-key',
              crv: 'P-256',
              x:,
              y:
            }
          ]
        }.to_json
      end

      before do
        stub_request(:get, jwks_uri)
          .to_return(status: 200, body: jwk_response, headers: { 'Content-Type' => 'application/json' })
      end

      it 'fetches the JWK and builds the public key' do
        jwk = described_class.new(jwks_uri)
        key = jwk.get('valid-key')

        expect(key.kty).to eq('EC')
        expect(key.use).to eq('sig')
        expect(key.alg).to eq('ES256')
        expect(key.kid).to eq('valid-key')
        expect(key.crv).to eq('P-256')
        expect(key.x).to eq(x)
        expect(key.y).to eq(y)

        expect(key.public_key.to_pem).to eq(public_key_256)
      end

      it 'success verification' do
        jwk = described_class.new(jwks_uri)
        key = jwk.get('valid-key')
        jws = LightJWT::JWT.new(claims: { sub: '1234567890', name: 'John Doe' }).sign('ES256', private_key)
        jws2 = LightJWT::JWT.decode(jws.to_s, key.public_key)

        expect(jws2.header.to_json).to eq('{"alg":"ES256","typ":"JWT"}')
        expect(jws2.payload.to_json).to eq('{"sub":"1234567890","name":"John Doe"}')
        expect(jws2.signature).not_to be_nil
      end
    end
  end

  context 'When the JWK for :enc' do
    context 'is a RSA key' do
      let(:private_key) { OpenSSL::PKey::RSA.new(2048) }
      let(:public_key) { private_key.public_key }
      let(:jwks_uri) { 'https://example.com/.well-known/jwks.json' }
      let(:jwk_response) do
        {
          keys: [
            {
              kty: 'RSA',
              use: 'enc',
              alg: 'RSA-OAEP',
              kid: 'valid-key',
              n: Base64.urlsafe_encode64(private_key.n.to_s(2)),
              e: Base64.urlsafe_encode64(private_key.e.to_s(2))
            }
          ]
        }.to_json
      end

      before do
        stub_request(:get, jwks_uri)
          .to_return(status: 200, body: jwk_response, headers: { 'Content-Type' => 'application/json' })
      end

      it 'fetches the JWK and builds the public key' do
        jwk = described_class.new(jwks_uri)
        key = jwk.get('valid-key')

        expect(key.kty).to eq('RSA')
        expect(key.use).to eq('enc')
        expect(key.alg).to eq('RSA-OAEP')
        expect(key.kid).to eq('valid-key')
        expect(key.n).to eq(Base64.urlsafe_encode64(private_key.n.to_s(2)))
        expect(key.e).to eq(Base64.urlsafe_encode64(private_key.e.to_s(2)))

        expect(key.public_key.to_pem).to eq(public_key.to_pem)
      end

      it 'success to encrypt' do
        jwk = described_class.new(jwks_uri)
        key = jwk.get('valid-key')
        jwe = LightJWT::JWT.new(claims: { sub: '1234567890', name: 'John Doe' }).encrypt('RSA-OAEP', 'A256GCM', key.public_key)
        expect(jwe.to_s.split('.').size).to eq(5)

        header, encrypted_key, iv, ciphertext, auth_tag = jwe.to_s.split('.')
        expect(Base64.urlsafe_decode64(header)).to eq({ alg: 'RSA-OAEP', enc: 'A256GCM' }.to_json)
        expect(encrypted_key).not_to be_nil
        expect(iv).not_to be_nil
        expect(ciphertext).not_to be_nil
        expect(auth_tag).not_to be_nil

        jwe2 = LightJWT::JWT.decode(jwe.to_s, private_key)
        expect(jwe2.header.to_json).to eq('{"alg":"RSA-OAEP","enc":"A256GCM"}')
        expect(jwe2.plain_text).to eq('{"sub":"1234567890","name":"John Doe"}')
      end
    end
  end
end
