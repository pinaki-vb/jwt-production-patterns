# JWT Key Rotation

This module provides battle-tested key rotation patterns to prevent race conditions during rolling deployments in distributed ASP.NET Core applications.

## The Problem

Rolling deployments create key rotation race conditions when nodes switch keys at different times:
- Some nodes sign with new key
- Others still validate with old key  
- Result: Valid tokens rejected, users logged out mid-flow

## Solution: Multi-Phase Key Rotation

1. **Phase 1**: Publish new key to all nodes
2. **Phase 2**: Sign with new key, validate with both old + new keys
3. **Phase 3**: Retire old key after buffer window

## Features

- **IssuerSigningKeyResolver**: Dynamic key selection during validation
- **Rotation Window Management**: Configurable overlap period for key transitions  
- **Multi-Key Validation**: Accept both current and previous keys during rotation
- **Safe Key Retirement**: Automated cleanup after rotation window expires

## Usage

### Service Registration

```csharp
services.AddSingleton<IKeyManager, KeyManager>();
services.AddSingleton<IKeyStorage, KeyStorage>();

// Configure JWT authentication with multi-key support
KeyRotationService.ConfigureJwtAuthentication(services);
```

### Key Rotation Process

```csharp
// Initiate key rotation
await keyManager.RotateKeyAsync();

// After rotation window (e.g., 2 hours)
await keyManager.CompleteRotationAsync();
```

## Implementation Details

- **Rotation Window**: 2-hour default overlap period
- **Key Storage**: Abstracted interface for various storage backends
- **Thread Safety**: Safe for concurrent access during rotation
- **Validation Logic**: Automatic fallback to previous key if current fails

## Best Practices

- Coordinate rotation across all nodes before signing with new key
- Use distributed storage for key synchronization
- Monitor rotation window completion
- Set rotation window longer than your longest deployment time