# frozen_string_literal: true

require 'json'
require 'base64'

module LightJWT
  class JWE
    attr_accessor :plain_text, :alg, :enc
    attr_reader :encrypted_key, :iv, :ciphertext, :auth_tag, :key, :jwt_token, :header
    
    NUM_OF_SEGMENTS = 5

    class << self
      def decode_compact_serialized(jwt_token, private_key)
        jwe = new(private_key, jwt_token)
        jwe.extract!
      end
    end

    def initialize(key = nil, jwt_token = nil)
      @key = key
      @jwt_token = jwt_token
    end

    def encrypt!
      validate_encrypt_requirements!

      result = JWA::JWE.encrypt(alg, enc, plain_text, key)

      @header = { alg:, enc: }
      @encrypted_key = result[:encrypted_key]
      @iv = result[:iv]
      @ciphertext = result[:ciphertext]
      @auth_tag = result[:auth_tag]

      self
    end

    def decrypt!
      validate_decrypt_requirements!

      @plain_text = JWA::JWE.decrypt(alg, enc, encrypted_key, iv, ciphertext, auth_tag, key)

      self
    end

    def to_s
      serialize_compact_format
    end

    def as_json
      { payload: plain_text }
    end

    def extract!
      segments = split_and_decode_segments
      @encrypted_key, @iv, @ciphertext, @auth_tag = segments[1..]
      @header = parse_header(segments[0])

      @alg, @enc = header.values_at(:alg, :enc)

      self
    end

    private

    def validate_decrypt_requirements!
      %i[alg enc key encrypted_key iv ciphertext auth_tag].each do |attr|
        raise ArgumentError, "#{attr.to_s.capitalize} must be set" unless instance_variable_get("@#{attr}")
      end
    end

    def validate_encrypt_requirements!
      %i[alg enc key plain_text].each do |attr|
        raise ArgumentError, "#{attr.to_s.capitalize} must be set" unless instance_variable_get("@#{attr}")
      end
    end

    def serialize_compact_format
      [
        header.to_json,
        encrypted_key,
        iv,
        ciphertext,
        auth_tag
      ].map { |segment| encode_segment(segment) }.join('.')
    end

    def encode_segment(segment)
      Base64.urlsafe_encode64(segment, padding: false)
    end

    def parse_header(header_segment)
      JSON.parse(header_segment, symbolize_names: true)
    rescue JSON::ParserError
      raise ArgumentError, 'Invalid protected header JSON format'
    end

    def split_and_decode_segments
      segments = jwt_token.split('.')
      raise ArgumentError, "JWT Token must contain exactly #{NUM_OF_SEGMENTS} segments" unless segments.size == NUM_OF_SEGMENTS

      segments.map { |segment| Base64.urlsafe_decode64(segment) }
    end
  end
end
