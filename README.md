# LightJWT

**LightJWT** is a Ruby implementation of JWT (JSON Web Token) and its related specifications, compliant with RFC 7515 (JWS), RFC 7516 (JWE), RFC 7517 (JWK), RFC 7518 (JWA), and RFC 7519 (JWT) as much as possible.

## Installation

Install the gem by running:

```bash
gem install light_jwt
```

Add this line to your application's Gemfile:

```ruby
gem 'light_jwt'
```

Then, execute:

```bash
bundle install
```

## Features

### Signing and Verification
- Supports **HMAC**, **RSA**, and **ECDSA** with SHA-256, SHA-384, and SHA-512.
- Includes full support for **JWK-based key management**.

### Encryption and Decryption
- Supported algorithms include **RSA1_5**, **RSA-OAEP**, and **AES-GCM** (128-bit and 256-bit keys).

### JWK and JWKS
- Fetch and use keys from a **JWKS URI**.

## Supported Algorithms

| Purpose       | Algorithms                                  |
|---------------|---------------------------------------------|
| **Signing**   | `HS256`, `HS384`, `HS512`, `RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `ES512` |
| **Encryption**| `RSA1_5`, `RSA-OAEP`, `A128GCM`, `A256GCM`  |
| **None**      | Not supported (planned for future updates). |

---

## Usage

### **Signing**

Sign a payload using a private key:

```ruby
require 'light_jwt'

claims = { sub: '1234567890', name: 'John Doe' }

# Signing
jws = LightJWT::JWT.new(claims).sign('RS256', private_key)
jwt_token = jws.to_s # Outputs: header.payload.signature
```
### **Verification**

Verify a signed JWT using a public key:

```ruby
# Verification
jws = LightJWT::JWT.decode(jwt_token, public_key)
payload = jws.payload # Decoded claims: { sub: '1234567890', name: 'John Doe' }
```

Bypass verification (use only for debugging purposes):

```ruby
jws = LightJWT::JWT.decode(jwt_token, skip_verification: true)
payload = jws.payload
```

### **Using JWK**

Fetch and verify using a JWKS URI:

```ruby
jwk = LightJWT::JWK.new(jwks_uri) # JWKS URI
key = jwk.get(kid)                # Retrieve key by `kid`
jws = LightJWT::JWT.decode(jwt_token, key)
payload = jws.payload
```

### **Encryption**

Encrypt a payload using a public key:

```ruby
alg = 'RSA-OAEP'
enc = 'A256GCM'
jwe = LightJWT::JWT.new(claims).encrypt(alg, enc, public_key)
encrypted_token = jwe.to_s # Outputs: header.encrypted_key.iv.ciphertext.auth_tag
```

### **Decryption**

Decrypt an encrypted JWT using a private key:

```ruby
jwe = LightJWT::JWT.decode(encrypted_token, private_key)
payload = jwe.payload # Decrypted claims: { sub: '1234567890', name: 'John Doe' }
```

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
