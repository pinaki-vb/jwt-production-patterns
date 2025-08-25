# Multi-Tenant JWT Security

This module prevents privilege escalation vulnerabilities in multi-tenant applications by cryptographically binding tokens to specific tenants using per-tenant signing keys.

## The Vulnerability

Common anti-pattern: Adding `tenant_id` as a claim creates privilege escalation risk where manipulated claims can expose cross-tenant data.

```csharp
// ❌ VULNERABLE: tenant_id in claims can be manipulated
new Claim("tenant_id", user.TenantId.ToString()) 
```

## Solution: Tenant-Bound Cryptographic Signing

Instead of relying on claims, bind tenant identity cryptographically using per-tenant signing keys:

- Each tenant has a unique signing key
- Tokens signed with Tenant A's key cannot be validated by Tenant B's endpoints
- No `tenant_id` claim needed - tenant identity is implicit in the signature

## Features

- **Per-Tenant Keys**: Isolated signing keys for each tenant
- **Cryptographic Binding**: Tenant identity proven by signature, not claims
- **Cross-Tenant Protection**: Tokens from one tenant rejected by others
- **Key Rotation**: Per-tenant key rotation capabilities
- **Strict Validation**: Zero clock skew for high-security scenarios

## Usage

### Service Registration

```csharp
services.AddSingleton<ITenantKeyManager, TenantKeyManager>();
services.AddSingleton<MultiTenantTokenService>();
services.AddSingleton<ITenantRepository, TenantRepository>();
```

### Token Creation

```csharp
var tokenService = serviceProvider.GetService<MultiTenantTokenService>();
var user = GetCurrentUser();
var tenant = GetCurrentTenant();

var token = tokenService.CreateToken(user, tenant);
```

### Token Validation

```csharp
// Validate token against specific tenant
var claimsPrincipal = await tokenService.ValidateTokenAsync(token, expectedTenantId);
```

## Security Benefits

- **Privilege Escalation Prevention**: Tokens cannot be used across tenants
- **Claim Manipulation Protection**: No tenant claims to manipulate  
- **Cryptographic Assurance**: Tenant identity proven by signature
- **Tenant Isolation**: Complete separation of tenant token spaces

## Implementation Notes

- Issuer and Audience include tenant ID for additional validation
- Keys are generated per-tenant and stored securely
- Rotation can be performed per-tenant without affecting others
- Strict temporal validation with zero clock skew