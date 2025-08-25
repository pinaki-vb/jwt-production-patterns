# JWT Production Patterns

**Battle-tested JWT security patterns for ASP.NET Core applications that actually work at scale.**

This repository contains production-ready implementations of advanced JWT security patterns from the article "JWTs in ASP.NET Core: From Pitfalls to Battle-Tested Security Patterns". These patterns solve real security vulnerabilities and performance issues encountered in large-scale .NET systems.

## 🚨 What This Solves

If you've run JWTs in production long enough, you've probably hit these problems:
- ✅ **Temporal validation exploits** - Tokens working past their expiry
- ✅ **Key rotation races** - Users randomly logged out during deployments  
- ✅ **Tenant privilege escalation** - Cross-tenant data exposure via manipulated claims
- ✅ **Token replay attacks** - Stolen tokens working from anywhere
- ✅ **Performance bottlenecks** - JWT validation becoming a DoS vector
- ✅ **Incident response blindness** - Can't trace token usage during security incidents

## 📦 Security Modules

### 🔍 [ReplayDetection](src/ReplayDetection/)
Advanced token replay detection using geographical analysis and usage pattern monitoring.
- Detects tokens used from different countries within suspicious time windows
- Identifies concurrent usage from multiple IP addresses
- Maintains audit trail with automated security alerts

### 🔄 [KeyRotation](src/KeyRotation/)
Zero-downtime key rotation preventing race conditions during rolling deployments.
- Multi-phase rotation: publish → overlap → retire
- `IssuerSigningKeyResolver` for dynamic key selection
- Prevents "valid tokens rejected" during deployments

### 🏢 [MultiTenant](src/MultiTenant/)
Cryptographically secure multi-tenant isolation using per-tenant signing keys.
- Eliminates `tenant_id` claim manipulation vulnerabilities
- Tokens from Tenant A cannot be validated by Tenant B
- Prevents privilege escalation across tenant boundaries

### 🔒 [TokenBinding](src/TokenBinding/)
Proof-of-possession implementation tying tokens to client certificates.
- Prevents bearer token replay even if tokens are stolen
- Implements RFC 7800 confirmation claim (`cnf`)
- Requires mutual TLS for maximum security

### 🕵️ [Forensics](src/Forensics/)
Comprehensive audit logging and incident response capabilities.
- Tracks complete token lifecycle (creation, usage, revocation)
- Automated anomaly detection (rapid IP changes, unusual patterns)
- Security incident correlation and investigation tools

### ⚡ [Performance](src/Performance/)
High-performance JWT validation reducing CPU usage by 60-80%.
- Intelligent caching with expiry-aware validation
- Object pooling for `JsonWebTokenHandler` instances
- DoS protection through optimized validation paths

## 🚀 Quick Start

### 1. Clone and Explore
```bash
git clone https://github.com/your-username/jwt-production-patterns.git
cd jwt-production-patterns
```

### 2. Add to Your Project
Each module is self-contained. Copy the relevant module(s) to your project:

```csharp
// Example: Add replay detection
services.AddSingleton<ReplayDetectionService>();
services.AddSingleton<IGeoLocationService, GeoLocationService>();

// Use in your JWT middleware
await replayDetectionService.DetectSuspiciousReplay(jti, httpContext);
```

### 3. Configure Based on Your Needs

**High Security Applications:**
- Use TokenBinding + ReplayDetection + Forensics
- Set `ClockSkew = TimeSpan.Zero` for strict temporal validation
- Enable comprehensive audit logging

**Multi-Tenant SaaS:**
- Use MultiTenant + KeyRotation + Forensics  
- Per-tenant key management with rotation schedules
- Cross-tenant security monitoring

**High-Performance APIs:**
- Use Performance + KeyRotation + ReplayDetection
- Object pooling and intelligent caching
- DoS protection with rate limiting

## 🏗️ Architecture Decisions

### When to Use Each Pattern

| Pattern | Use Case | Security Level | Performance Impact |
|---------|----------|----------------|-------------------|
| **ReplayDetection** | Distributed systems, high-value transactions | High | Low |
| **KeyRotation** | Rolling deployments, zero-downtime requirements | Medium | Low |
| **MultiTenant** | SaaS applications, tenant isolation | Critical | Low |
| **TokenBinding** | Maximum security, regulated industries | Critical | Medium |
| **Forensics** | Compliance, incident response | Medium | Low |
| **Performance** | High-throughput APIs, cost optimization | Low | Negative |

### Migration Strategy

**Phase 1: Foundation**
1. Implement KeyRotation (prevents deployment issues)
2. Add Forensics (enables monitoring)
3. Deploy Performance optimizations

**Phase 2: Security Hardening**  
1. Add ReplayDetection (based on threat model)
2. Implement MultiTenant (if applicable)
3. Consider TokenBinding (for high-security requirements)

## 🔧 .NET 9 Features Used

- **JsonWebTokenHandler**: Preferred over `JwtSecurityTokenHandler` for better performance
- **IssuerSigningKeyResolver**: Dynamic key selection for multi-key validation
- **Source-Generated Logging**: Zero-allocation structured logging for forensics
- **Object Pooling**: ASP.NET Core object pooling for handler reuse
- **TimeProvider**: Testable time abstraction for temporal validation

## ⚠️ Important Security Notes

- **Never store secrets in code** - Use secure key management systems
- **Implement proper key rotation** - Don't rely on long-lived signing keys
- **Monitor audit logs** - Automated alerting for suspicious patterns
- **Test temporal validation** - Use `TimeProvider` for testable time logic
- **Consider OIDC** - If solving 3+ problems manually, you've reinvented OIDC

## 🧪 Testing

Each module includes:
- Unit tests for core functionality
- Integration tests with ASP.NET Core
- Performance benchmarks and profiling
- Security test scenarios

```bash
# Run all tests
dotnet test

# Run performance benchmarks
dotnet run --project tests/Performance.Benchmarks
```

## 📖 Related Resources

- **Original Article**: [Medium Article Link]
- **JWT RFC**: [RFC 7519](https://tools.ietf.org/html/rfc7519)
- **Token Binding**: [RFC 7800](https://tools.ietf.org/html/rfc7800)
- **ASP.NET Core JWT**: [Microsoft Documentation](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/jwt)

## 🤝 Contributing

Contributions welcome! Please:
1. Follow existing code patterns and security practices
2. Include comprehensive tests for security scenarios
3. Update documentation for new features
4. Consider backward compatibility impact

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## ⭐ If This Helps You

If these patterns solve production issues for you, consider:
- ⭐ Starring this repository
- 📚 Reading the full article on Medium
- 🔗 Sharing with your team
- 🐛 Reporting issues you encounter

---

**Built for production. Tested at scale. Ready for your critical systems.**