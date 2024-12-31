# frozen_string_literal: true

require 'json'
require 'net/http'
require 'openssl'

module LightJWT
  class JWK
    SUPPORTED_KEY_TYPES = %w[RSA EC].freeze
    SUPPORTED_KEY_USES = %w[sig enc].freeze
    SUPPORTED_CURVES = %w[P-256 P-384 P-521].freeze

    attr_reader :keys

    def initialize(jwks_uri)
      @jwks_uri = jwks_uri
      @keys = fetch_jwks
    end

    def get(kid)
      key_data = @keys.find { |k| k['kid'] == kid }
      raise ArgumentError, "JWK with kid '#{kid}' not found" unless key_data

      Key.new(key_data)
    end

    class Key
      attr_reader :key_data, :kty, :use, :alg, :kid, :n, :e, :x, :y, :crv

      def initialize(key_data)
        @key_data = key_data
        @kty = key_data['kty']
        @use = key_data['use']
        @alg = key_data['alg']
        @kid = key_data['kid']
        @n = key_data['n']
        @e = key_data['e']
        @x = key_data['x']
        @y = key_data['y']
        @crv = key_data['crv']

        validate_key
      end

      def public_key
        case kty
        when 'RSA'
          build_rsa_public_key
        when 'EC'
          build_ec_public_key
        else
          raise ArgumentError, "Unsupported key type: #{kty}"
        end
      end

      private

      def validate_key
        raise ArgumentError, 'Unsupported key type' unless SUPPORTED_KEY_TYPES.include?(kty)
        raise ArgumentError, 'Invalid key use' unless SUPPORTED_KEY_USES.include?(use)
        raise ArgumentError, 'Missing required parameters for RSA key' if rsa_key_missing?
        raise ArgumentError, 'Missing required parameters for EC key' if ec_key_missing?
      end

      def rsa_key_missing?
        kty == 'RSA' && (n.nil? || e.nil?)
      end

      def ec_key_missing?
        kty == 'EC' && (x.nil? || y.nil? || !SUPPORTED_CURVES.include?(crv))
      end

      def build_rsa_public_key
        asn1_sequence = OpenSSL::ASN1::Sequence.new([
                                                      OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(base64url_decode(n),
                                                                                                 2)),
                                                      OpenSSL::ASN1::Integer.new(OpenSSL::BN.new(base64url_decode(e),
                                                                                                 2))
                                                    ])

        OpenSSL::PKey::RSA.new(asn1_sequence.to_der)
      end

      def build_ec_public_key
        curve_name = curve_name_from_crv

        raw_x = base64url_decode(x)
        raw_y = base64url_decode(y)

        point = OpenSSL::PKey::EC::Point.new(
          OpenSSL::PKey::EC::Group.new(curve_name),
          OpenSSL::BN.new(["04#{raw_x.unpack1('H*')}#{raw_y.unpack1('H*')}"].pack('H*'), 2)
        )

        data_sequence = OpenSSL::ASN1::Sequence([
                                                  OpenSSL::ASN1::Sequence([
                                                                            OpenSSL::ASN1::ObjectId('id-ecPublicKey'),
                                                                            OpenSSL::ASN1::ObjectId(curve_name)
                                                                          ]),
                                                  OpenSSL::ASN1::BitString(point.to_octet_string(:uncompressed))
                                                ])

        OpenSSL::PKey::EC.new(data_sequence.to_der)
      end

      def curve_name_from_crv
        case crv
        when 'P-256' then 'prime256v1'
        when 'P-384' then 'secp384r1'
        when 'P-521' then 'secp521r1'
        else
          raise ArgumentError, "Unsupported EC curve: #{crv}"
        end
      end

      def ec_point_from_coordinates(group)
        x_bn = OpenSSL::BN.new(base64url_decode(x), 2)
        y_bn = OpenSSL::BN.new(base64url_decode(y), 2)
        OpenSSL::PKey::EC::Point.new(group, OpenSSL::BN.new("04#{x_bn.to_s(16)}#{y_bn.to_s(16)}", 16))
      end

      def base64url_decode(data)
        Base64.urlsafe_decode64(data)
      rescue StandardError
        raise ArgumentError, "Invalid base64url encoding: #{data}"
      end
    end

    private

    def fetch_jwks
      uri = URI(@jwks_uri)
      response = Net::HTTP.get(uri)
      jwks = JSON.parse(response)
      raise ArgumentError, 'Invalid JWK Set format' unless jwks['keys'].is_a?(Array)

      jwks['keys']
    end
  end
end
