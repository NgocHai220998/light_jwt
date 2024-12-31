# frozen_string_literal: true

require 'spec_helper'

RSpec.describe LightJWT::JWA::JWE do
  let(:plaintext) { 'This is a secret message.' }
  let(:valid_rsa_private_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:valid_rsa_public_key) { valid_rsa_private_key.public_key }
  let(:small_rsa_private_key) { OpenSSL::PKey::RSA.generate(1024) }
  let(:small_rsa_public_key) { small_rsa_private_key.public_key }

  describe 'JWE encryption and decryption' do
    context 'with supported RSA key management algorithms' do
      %w[RSA1_5 RSA-OAEP].each do |alg|
        context "using #{alg}" do
          %w[A128GCM A256GCM].each do |enc|
            it "successfully encrypts and decrypts with #{enc}" do
              result = described_class.encrypt(alg, enc, plaintext, valid_rsa_public_key)

              expect(result).to have_key(:encrypted_key)
              expect(result).to have_key(:iv)
              expect(result).to have_key(:ciphertext)
              expect(result).to have_key(:auth_tag)

              decrypted = described_class.decrypt(
                alg,
                enc,
                result[:encrypted_key],
                result[:iv],
                result[:ciphertext],
                result[:auth_tag],
                valid_rsa_private_key
              )

              expect(decrypted).to eq(plaintext)
            end

            it "fails decryption with an incorrect private key for #{enc}" do
              result = described_class.encrypt(alg, enc, plaintext, valid_rsa_public_key)

              incorrect_private_key = OpenSSL::PKey::RSA.generate(2048)

              expect do
                described_class.decrypt(
                  alg,
                  enc,
                  result[:encrypted_key],
                  result[:iv],
                  result[:ciphertext],
                  result[:auth_tag],
                  incorrect_private_key
                )
              end.to raise_error
            end

            it "fails decryption with an altered ciphertext for #{enc}" do
              result = described_class.encrypt(alg, enc, plaintext, valid_rsa_public_key)

              altered_ciphertext = result[:ciphertext].dup
              altered_ciphertext[0] = 'X'

              expect do
                described_class.decrypt(
                  alg,
                  enc,
                  result[:encrypted_key],
                  result[:iv],
                  altered_ciphertext,
                  result[:auth_tag],
                  valid_rsa_private_key
                )
              end.to raise_error(OpenSSL::Cipher::CipherError)
            end

            it "fails decryption with an altered auth tag for #{enc}" do
              result = described_class.encrypt(alg, enc, plaintext, valid_rsa_public_key)

              altered_auth_tag = result[:auth_tag].dup
              altered_auth_tag[0] = 'X'

              expect do
                described_class.decrypt(
                  alg,
                  enc,
                  result[:encrypted_key],
                  result[:iv],
                  result[:ciphertext],
                  altered_auth_tag,
                  valid_rsa_private_key
                )
              end.to raise_error(OpenSSL::Cipher::CipherError)
            end
          end
        end
      end
    end

    context 'with invalid key sizes' do
      %w[RSA1_5 RSA-OAEP].each do |alg|
        %w[A128GCM A256GCM].each do |enc|
          it "raises an error when using a small RSA key for #{alg} and #{enc}" do
            expect do
              described_class.encrypt(alg, enc, plaintext, small_rsa_public_key)
            end.to raise_error(LightJWT::Error::InvalidKey)
          end
        end
      end
    end

    context 'with unsupported algorithms' do
      let(:unsupported_algorithm) { 'RSA1000' }
      let(:unsupported_encryption) { 'unsupported-enc' }

      it 'raises an error for unsupported key management algorithm' do
        expect do
          described_class.encrypt(unsupported_algorithm, 'A128GCM', plaintext, valid_rsa_public_key)
        end.to raise_error(LightJWT::Error::UnsupportedAlgorithm)
      end

      it 'raises an error for unsupported content encryption algorithm' do
        expect do
          described_class.encrypt('RSA-OAEP', unsupported_encryption, plaintext, valid_rsa_public_key)
        end.to raise_error(LightJWT::Error::UnsupportedAlgorithm)
      end
    end
  end

  describe '#supported_algorithms' do
    let(:supported_algorithms) do
      [
        { alg: 'RSA1_5', enc: 'A128GCM' },
        { alg: 'RSA1_5', enc: 'A256GCM' },
        { alg: 'RSA-OAEP', enc: 'A128GCM' },
        { alg: 'RSA-OAEP', enc: 'A256GCM' }
      ]
    end

    it 'returns a list of supported algorithms' do
      expect(described_class.supported_algorithms).to eq(supported_algorithms)
    end
  end
end
