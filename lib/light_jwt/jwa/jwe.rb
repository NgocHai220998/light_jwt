# frozen_string_literal: true

require 'openssl'

module LightJWT
  module JWA
    class JWE
      RSA_KEY_MANAGEMENT_ALGORITHMS = %w[RSA1_5 RSA-OAEP].freeze
      CONTENT_ENCRYPTION_ALGORITHMS = {
        'A128GCM' => { key_length: 16, cipher: 'aes-128-gcm', iv_length: 12 },
        'A256GCM' => { key_length: 32, cipher: 'aes-256-gcm', iv_length: 12 }
      }.freeze

      SUPPORTED_ALGORITHMS = RSA_KEY_MANAGEMENT_ALGORITHMS.product(CONTENT_ENCRYPTION_ALGORITHMS.keys)

      class << self
        def encrypt(alg, enc, plaintext, public_key)
          validate_algorithms(alg, enc)

          cek = generate_cek(enc)
          encrypted_key = rsa_encrypt_key(alg, cek, public_key)
          iv, ciphertext, auth_tag = aes_gcm_encrypt(enc, cek, plaintext)

          { encrypted_key:, iv:, ciphertext:, auth_tag: }
        end

        def decrypt(alg, enc, encrypted_key, iv, ciphertext, auth_tag, private_key)
          validate_algorithms(alg, enc)

          cek = rsa_decrypt_key(alg, encrypted_key, private_key)
          aes_gcm_decrypt(enc, cek, iv, ciphertext, auth_tag)
        end

        def supported_algorithms
          SUPPORTED_ALGORITHMS.map { |alg, enc| { alg: alg, enc: enc } }
        end

        private

        def validate_algorithms(alg, enc)
          unless SUPPORTED_ALGORITHMS.include?([alg, enc])
            raise LightJWT::Error::UnsupportedAlgorithm,
                  "Unsupported combination: #{alg} + #{enc}"
          end
        end

        def generate_cek(enc)
          OpenSSL::Random.random_bytes(CONTENT_ENCRYPTION_ALGORITHMS[enc][:key_length])
        end

        def rsa_encrypt_key(alg, cek, public_key)
          rsa = OpenSSL::PKey::RSA.new(public_key)
          validate_rsa_key_size(rsa)

          case alg
          when 'RSA1_5'
            rsa.public_encrypt(cek, OpenSSL::PKey::RSA::PKCS1_PADDING)
          when 'RSA-OAEP'
            rsa.public_encrypt(cek, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
          else
            raise LightJWT::Error::UnsupportedAlgorithm, "Unsupported RSA algorithm: #{alg}"
          end
        end

        def rsa_decrypt_key(alg, encrypted_key, private_key)
          rsa = OpenSSL::PKey::RSA.new(private_key)
          validate_rsa_key_size(rsa)

          case alg
          when 'RSA1_5'
            rsa.private_decrypt(encrypted_key, OpenSSL::PKey::RSA::PKCS1_PADDING)
          when 'RSA-OAEP'
            rsa.private_decrypt(encrypted_key, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
          else
            raise LightJWT::Error::UnsupportedAlgorithm, "Unsupported RSA algorithm: #{alg}"
          end
        end

        def validate_rsa_key_size(rsa)
          raise LightJWT::Error::InvalidKey, 'RSA key must be at least 2048 bits' if rsa.n.num_bits < 2048
        end

        def aes_gcm_encrypt(enc, cek, plaintext)
          params = CONTENT_ENCRYPTION_ALGORITHMS[enc]
          cipher = OpenSSL::Cipher.new(params[:cipher])
          cipher.encrypt
          iv = OpenSSL::Random.random_bytes(params[:iv_length])
          cipher.key = cek
          cipher.iv = iv

          ciphertext = cipher.update(plaintext) + cipher.final
          auth_tag = cipher.auth_tag

          [iv, ciphertext, auth_tag]
        end

        def aes_gcm_decrypt(enc, cek, iv, ciphertext, auth_tag)
          params = CONTENT_ENCRYPTION_ALGORITHMS[enc]
          decipher = OpenSSL::Cipher.new(params[:cipher])
          decipher.decrypt
          decipher.key = cek
          decipher.iv = iv
          decipher.auth_tag = auth_tag

          decipher.update(ciphertext) + decipher.final
        end
      end
    end
  end
end
