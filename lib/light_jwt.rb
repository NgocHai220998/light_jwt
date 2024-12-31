# frozen_string_literal: true

require_relative 'light_jwt/version'

module LightJWT
  autoload :Error, 'light_jwt/error'
  autoload :JWT, 'light_jwt/jwt'
  autoload :JWE, 'light_jwt/jwe'
  autoload :JWS, 'light_jwt/jws'
  autoload :JWK, 'light_jwt/jwk'
  module JWA
    autoload :JWS, 'light_jwt/jwa/jws'
    autoload :JWE, 'light_jwt/jwa/jwe'
  end
end

require 'openssl'
require 'base64'
require 'json'
require 'net/http'
