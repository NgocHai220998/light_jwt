# frozen_string_literal: true

require_relative 'lib/light_jwt/version'

Gem::Specification.new do |spec|
  spec.name = 'light_jwt'
  spec.version = LightJWT::VERSION
  spec.authors = ['Nguyen Ngoc Hai']
  spec.email = ['ngochai220998@gmail.com']

  spec.summary = 'JSON Web Token implementation in Ruby, compliant with RFC 7519'
  spec.description = 'Ruby implementation of JWT (JSON Web Token) and its related specifications, compliant with RFC 7515 (JWS), RFC 7516 (JWE), RFC 7517 (JWK), RFC 7518 (JWA), and RFC 7519 (JWT) as much as possible.'
  spec.homepage = "https://github.com/NgocHai220998/light_jwt"
  spec.license = 'MIT'
  spec.required_ruby_version = '>= 3.0.0'

  spec.metadata['homepage_uri'] = spec.homepage

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git appveyor Gemfile])
    end
  end
  spec.bindir = 'exe'
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

  spec.add_dependency 'base64'
  spec.add_dependency 'json', '~> 2.9.1'
  spec.add_dependency 'openssl', '~> 3.3.0'

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
