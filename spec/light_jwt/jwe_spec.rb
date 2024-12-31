# frozen_string_literal: true

require 'spec_helper'

RSpec.describe LightJWT::JWE do
  let(:rsa_key) { OpenSSL::PKey::RSA.new(2048) }
  let(:private_key) { rsa_key }
  let(:public_key) { private_key.public_key }
  let(:key) { nil }

  let(:plaintext) { 'This is a secret message.' }
  let(:alg) { 'RSA-OAEP' }
  let(:enc) { 'A256GCM' }

  subject { described_class.new(key) }

  describe '#encrypt!' do
    let(:key) { public_key }

    it 'encrypts the plaintext into JWE components' do
      subject.alg = alg
      subject.enc = enc
      subject.plain_text = plaintext
      subject.encrypt!

      expect(subject.encrypted_key).not_to be_nil
      expect(subject.iv).not_to be_nil
      expect(subject.ciphertext).not_to be_nil
      expect(subject.auth_tag).not_to be_nil
    end
  end

  describe '#decrypt!' do
    let(:jwe) { described_class.new(public_key) }

    before do
      jwe.alg = alg
      jwe.enc = enc
      jwe.plain_text = plaintext
      jwe.encrypt!
    end

    it 'decrypts the encrypted data back to plaintext' do
      decrypted_jwe = described_class.decode_compact_serialized(jwe.to_s, OpenSSL::PKey::RSA.new(private_key))

      decrypted_jwe.decrypt!

      expect(decrypted_jwe.plain_text).to eq(plaintext)
    end
  end

  describe '.decode_compact_serialized' do
    let(:jwe) { described_class.new(public_key) }

    before do
      jwe.alg = alg
      jwe.enc = enc
      jwe.plain_text = plaintext
      jwe.encrypt!
    end

    it 'decodes a compact serialized JWE string' do
      decoded_jwe = described_class.decode_compact_serialized(jwe.to_s, OpenSSL::PKey::RSA.new(private_key))

      expect(decoded_jwe.alg).to eq(alg)
      expect(decoded_jwe.enc).to eq(enc)
      expect(decoded_jwe.encrypted_key).not_to be_nil
      expect(decoded_jwe.iv).not_to be_nil
      expect(decoded_jwe.ciphertext).not_to be_nil
      expect(decoded_jwe.auth_tag).not_to be_nil
    end

    it 'raises an error for invalid compact serialization' do
      expect do
        described_class.decode_compact_serialized('invalid.string',
                                                  OpenSSL::PKey::RSA.new(private_key))
      end.to raise_error(ArgumentError, 'JWT Token must contain exactly 5 segments')
    end
  end

  describe '#to_s' do
    let(:key) { public_key }

    it 'returns a valid compact serialization string' do
      subject.alg = alg
      subject.enc = enc
      subject.plain_text = plaintext
      subject.encrypt!

      compact_serialized = subject.to_s
      segments = compact_serialized.split('.')

      expect(segments.size).to eq(5)
      segments.each do |segment|
        expect { Base64.urlsafe_decode64(segment) }.not_to raise_error
      end
    end
  end
end
