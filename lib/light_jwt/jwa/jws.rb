# frozen_string_literal: true

module LightJWT
  module JWA
    class JWS
      HMAC_ALGORITHMS = {
        'HS256' => OpenSSL::Digest::SHA256,
        'HS384' => OpenSSL::Digest::SHA384,
        'HS512' => OpenSSL::Digest::SHA512
      }.freeze

      RSA_ALGORITHMS = {
        'RS256' => OpenSSL::Digest::SHA256,
        'RS384' => OpenSSL::Digest::SHA384,
        'RS512' => OpenSSL::Digest::SHA512
      }.freeze

      ECDSA_ALGORITHMS = {
        'ES256' => OpenSSL::Digest::SHA256,
        'ES384' => OpenSSL::Digest::SHA384,
        'ES512' => OpenSSL::Digest::SHA512
      }.freeze

      SUPPORTED_ALGORITHMS = HMAC_ALGORITHMS.keys + RSA_ALGORITHMS.keys + ECDSA_ALGORITHMS.keys + ['none']

      class << self
        def sign(alg, signing_key, token)
          algorithm_handler(alg).sign(signing_key, token)
        end

        def verify(alg, key, token, signature)
          algorithm_handler(alg).verify(key, token, signature)
        end

        def supported_algorithms
          SUPPORTED_ALGORITHMS
        end

        private

        def algorithm_handler(alg)
          case alg
          when *HMAC_ALGORITHMS.keys
            HMACHandler.new(alg)
          when *RSA_ALGORITHMS.keys
            RSAHandler.new(alg)
          when *ECDSA_ALGORITHMS.keys
            ECDSAHandler.new(alg)
          when 'none'
            NoneHandler.new(alg)
          else
            raise LightJWT::Error::UnsupportedAlgorithm,
                  "Unsupported JWS algorithm: #{alg}. Supported algorithms are: #{SUPPORTED_ALGORITHMS.join(', ')}"
          end
        end
      end

      class BaseHandler
        attr_reader :alg, :digest

        def initialize(alg)
          @alg = alg
          @digest = build_digest unless alg == 'none'
        end

        # Constant-time comparison algorithm to prevent timing attacks
        def secure_compare(a, b)
          return false if a.bytesize != b.bytesize

          a.bytes.zip(b.bytes).map { |x, y| x ^ y }.sum.zero?
        end

        private

        def build_digest
          case alg
          when *HMAC_ALGORITHMS.keys
            HMAC_ALGORITHMS[alg].new
          when *RSA_ALGORITHMS.keys
            RSA_ALGORITHMS[alg].new
          when *ECDSA_ALGORITHMS.keys
            ECDSA_ALGORITHMS[alg].new
          else
            raise LightJWT::Error::UnsupportedAlgorithm,
                  "Unsupported JWS algorithm: #{alg}. Supported algorithms are: #{SUPPORTED_ALGORITHMS.join(', ')}"
          end
        end
      end

      class HMACHandler < BaseHandler
        def sign(signing_key, token)
          validate_key_length(signing_key)

          OpenSSL::HMAC.digest(digest, signing_key, token)
        end

        def verify(signing_key, token, signature)
          expected_signature = sign(signing_key, token)
          secure_compare(expected_signature, signature)
        end

        private

        def validate_key_length(key)
          return unless key.bytesize < digest.digest_length

          raise LightJWT::Error::InvalidKey,
                "Signing key must be at least #{digest.digest_length} bytes"
        end
      end

      class RSAHandler < BaseHandler
        def sign(private_key, token)
          rsa_private_key = OpenSSL::PKey::RSA.new(private_key)
          validate_key_size(rsa_private_key)

          rsa_private_key.sign(digest, token)
        end

        def verify(public_key, token, signature)
          rsa_public_key = OpenSSL::PKey::RSA.new(public_key)
          validate_key_size(rsa_public_key)

          rsa_public_key.verify(digest, signature, token)
        end

        private

        def validate_key_size(key)
          raise LightJWT::Error::InvalidKey, 'RSA key must be at least 2048 bits' if key.n.num_bits < 2048
        end
      end

      class ECDSAHandler < BaseHandler
        def sign(private_key, token)
          ec_private_key = OpenSSL::PKey::EC.new(private_key)

          asn1_to_raw(ec_private_key.sign(digest, token), ec_private_key)
        end

        def verify(public_key, token, signature)
          ec_public_key = OpenSSL::PKey::EC.new(public_key)

          raw_signature = raw_to_asn1(signature, ec_public_key)
          ec_public_key.verify(digest, raw_signature, token)
        end

        private

        # Convert ASN.1 DER format to raw signature, because RFC7518 requires it
        # https://datatracker.ietf.org/doc/html/rfc7518#section-3.4
        def asn1_to_raw(signature, private_key)
          byte_size = (private_key.group.degree + 7) / 8
          OpenSSL::ASN1.decode(signature).value.map { |value| value.value.to_s(2).rjust(byte_size, "\x00") }.join
        end

        # Convert raw signature to ASN.1 DER format. A raw ECDSA signature is comprised of two integers "r" and "s".
        # OpenSSL expects them to be wrapped up inside a DER encoded representation.
        # https://stackoverflow.com/questions/59904522/asn1-encoding-routines-errors-when-verifying-ecdsa-signature-type-with-openssl
        def raw_to_asn1(signature, public_key)
          byte_size = (public_key.group.degree + 7) / 8
          r = signature[0..(byte_size - 1)]
          s = signature[byte_size..]
          OpenSSL::ASN1::Sequence.new([r, s].map { |int| OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(int, 2)) }).to_der
        end
      end

      class NoneHandler < BaseHandler
        def sign(_, _)
          ''
        end

        def verify(_, _, signature)
          signature == ''
        end
      end
    end
  end
end
