# JWT Token Binding (Proof of Possession)

This module implements token binding to cryptographically tie JWT tokens to client certificates, preventing bearer token replay attacks even if tokens are stolen.

## The Problem

Bearer tokens follow the "whoever holds the string wins" model. If stolen through:
- Application logs
- XSS attacks  
- Network interception
- Proxy exposure

They work from any location until expiry.

## Solution: Certificate Binding

Token binding cryptographically ties tokens to client certificates using the `cnf` (confirmation) claim:

1. **Token Creation**: Include client certificate thumbprint in `cnf` claim
2. **Token Validation**: Verify current client certificate matches bound certificate
3. **Replay Prevention**: Stolen tokens fail validation without matching certificate

## Features

- **Certificate Thumbprint Binding**: Uses X.509 certificate thumbprints for binding
- **Proof of Possession**: Tokens only work with matching client certificates
- **Middleware Integration**: Automatic validation in ASP.NET Core pipeline
- **Replay Attack Prevention**: Blocks token usage from unauthorized clients

## Usage

### Service Registration

```csharp
services.AddSingleton<TokenBindingService>();
```

### Token Creation

```csharp
var tokenService = serviceProvider.GetService<TokenBindingService>();
var user = GetCurrentUser();
var clientCert = await httpContext.Connection.GetClientCertificateAsync();
var signingKey = GetSigningKey();

var boundToken = tokenService.CreateBoundToken(user, clientCert, signingKey);
```

### Middleware Configuration

```csharp
app.UseTokenBinding(validationKey);
```

### Manual Validation

```csharp
var clientCert = await httpContext.Connection.GetClientCertificateAsync();
var result = await tokenService.ValidateTokenAsync(token, validationKey, clientCert);

if (!result.IsValid)
{
    // Handle validation failure
    throw new UnauthorizedAccessException(result.ErrorMessage);
}
```

## Certificate Binding Flow

1. **Client Authentication**: Client presents certificate during TLS handshake
2. **Token Creation**: Server binds token to certificate thumbprint via `cnf` claim
3. **Subsequent Requests**: Server validates token AND certificate match
4. **Automatic Rejection**: Tokens without matching certificates are rejected

## Security Benefits

- **Replay Attack Mitigation**: Stolen tokens useless without client certificate
- **Cryptographic Proof**: Mathematical binding between token and certificate
- **Zero Trust Validation**: Every request validates certificate binding
- **High Security Compliance**: Meets requirements for sensitive applications

## Implementation Notes

- Requires client certificate authentication (mutual TLS)
- Uses standard `cnf` claim from RFC 7800
- Automatic middleware integration for transparent validation
- Configurable validation parameters and error handling