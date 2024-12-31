# frozen_string_literal: true

module LightJWT
  class JWT
    attr_accessor :claims

    class << self
      def decode(input, key_or_options = {})
        key, options = parse_key_and_options(key_or_options)
        handler = handler_for(input)
        handler.decode(input, key, options)
      end

      private

      def handler_for(input)
        case input.count('.') + 1
        when JWS::NUM_OF_SEGMENTS
          JWSHandler.new
        when JWE::NUM_OF_SEGMENTS
          JWEHandler.new
        else
          raise ArgumentError, 'Invalid JWT format'
        end
      end

      def parse_key_and_options(key_or_options)
        case key_or_options
        when Hash
          [nil, key_or_options]
        else
          [key_or_options, {}]
        end
      end
    end

    def initialize(claims: {})
      @claims = claims
    end

    def sign(alg, signing_key)
      JWSHandler.new.sign(claims, alg, signing_key)
    end

    def encrypt(alg, enc, public_key)
      JWEHandler.new.encrypt(claims, alg, enc, public_key)
    end
  end

  class BaseHandler
    def base64_encode(data)
      Base64.urlsafe_encode64(data.to_json, padding: false)
    end
  end

  class JWSHandler < BaseHandler
    def sign(claims, alg, signing_key)
      jose_header = { alg:, typ: 'JWT' }
      token = [jose_header, claims].map { |segment| base64_encode(segment) }.join('.')
      jws = JWS.new(token, alg, signing_key)
      jws.sign!
    end

    def decode(input, key, options)
      jws = JWS.decode_compact_serialized(input, key)
      jws.verify! unless options[:skip_verification]
      jws
    end
  end

  class JWEHandler < BaseHandler
    def encrypt(claims, alg, enc, public_key)
      jwe = JWE.new(public_key)
      jwe.alg = alg
      jwe.enc = enc
      jwe.plain_text = claims.to_json
      jwe.encrypt!
    end

    def decode(input, key, _)
      jwe = JWE.decode_compact_serialized(input, key)
      jwe.decrypt!
      jwe
    end
  end
end
