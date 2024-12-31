# frozen_string_literal: true

module LightJWT
  module Error
    class Error < StandardError; end

    class UnsupportedAlgorithm < Error; end
    class InvalidKey < Error; end
    class VerificationError < Error; end
    class JWKKeyTypeError < Error; end
    class JWKKeyIDError < Error; end
  end
end
