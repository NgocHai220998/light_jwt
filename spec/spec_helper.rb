# frozen_string_literal: true

require 'rspec'
require 'webmock/rspec'

# TODO: Refactor and add more test cases, current tests are not enough and not well structured
RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = :expect
  end
end

require_relative '../lib/light_jwt'
