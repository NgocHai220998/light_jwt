# frozen_string_literal: true

module LightJWT
  class JWS
    attr_reader :header, :payload, :signature, :alg, :key

    NUM_OF_SEGMENTS = 3

    class << self
      def decode_compact_serialized(jwt_token, key)
        segments = jwt_token.split('.')
        validate_segment_count(segments)

        header, payload, signature = segments
        parsed_header = parse_segment(header)

        new("#{header}.#{payload}", parsed_header[:alg], key, signature)
      end

      private

      def parse_segment(segment)
        JSON.parse(Base64.urlsafe_decode64(segment), symbolize_names: true)
      rescue JSON::ParserError, ArgumentError
        raise ArgumentError, 'Invalid segment encoding'
      end

      def validate_segment_count(segments)
        return if segments.size == NUM_OF_SEGMENTS

        raise ArgumentError,
              "JWT Token must have exactly #{NUM_OF_SEGMENTS} segments"
      end
    end

    def initialize(signing_data, alg, key, signature = nil)
      @signing_data = signing_data
      @alg = alg
      @key = key
      @signature = signature
      @header, @payload = extract_header_and_payload
    end

    def sign!
      raw_signature = JWA::JWS.sign(alg, key, signing_data)
      @signature = encode_segment(raw_signature)

      self
    end

    def verify!
      raise Error::VerificationError, 'Signature verification failed' unless valid_signature?

      true
    end

    def to_s
      raise ArgumentError, 'Signature is missing' unless signature

      [encoded_header, encoded_payload, signature].join('.')
    end

    def as_json
      { header:, payload: }
    end

    private

    def valid_signature?
      raw_signature = decode_segment(signature)
      JWA::JWS.verify(alg, key, signing_data, raw_signature)
    end

    def signing_data
      @signing_data ||= [encoded_header, encoded_payload].join('.')
    end

    def encoded_header
      @encoded_header ||= encode_segment(header.to_json)
    end

    def encoded_payload
      @encoded_payload ||= encode_segment(payload.to_json)
    end

    def extract_header_and_payload
      @signing_data.split('.').map { |segment| self.class.send(:parse_segment, segment) }
    end

    def encode_segment(segment)
      Base64.urlsafe_encode64(segment, padding: false)
    end

    def decode_segment(segment)
      Base64.urlsafe_decode64(segment)
    rescue ArgumentError
      raise ArgumentError, 'Invalid Base64 URL-safe encoding'
    end
  end
end
