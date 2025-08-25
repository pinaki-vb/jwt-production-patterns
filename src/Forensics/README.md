# JWT Forensics & Incident Response

This module provides comprehensive audit logging and forensics capabilities for JWT tokens to enable effective incident response and security investigations.

## The Problem

Production pain point: Teams can't answer *"where did this token come from, and who used it when?"* during security incidents.

Without audit trails:
- Revocation decisions are guesswork
- Investigation is impossible  
- Incident scope is unknown
- Attack patterns go undetected

## Solution: Comprehensive Token Forensics

Complete audit trail of JWT lifecycle events with automated anomaly detection and incident response capabilities.

## Features

- **Structured Audit Logging**: Source-generated high-performance logging
- **Token Lifecycle Tracking**: Creation, usage, and revocation events
- **Anomaly Detection**: Automated detection of suspicious usage patterns
- **Forensic Investigation**: Detailed analysis of token usage history
- **Incident Response**: Related token discovery and impact analysis
- **Pattern Recognition**: Identification of attack patterns across tokens

## Tracked Events

### Token Creation
- User ID, IP address, User-Agent
- Timestamp and creation context
- Associated permissions/scopes

### Token Usage  
- Each API request using the token
- IP address and User-Agent tracking
- Geographical and temporal patterns

### Token Revocation
- Who revoked the token and why
- Revocation timestamp and method
- Related security events

## Usage

### Service Registration

```csharp
services.AddSingleton<JwtForensicsService>();
services.AddSingleton<IAuditStore, AuditStore>();
```

### Logging Token Events

```csharp
// Token creation
await forensicsService.LogTokenCreation(jti, userId, ipAddress, userAgent);

// Token usage (in middleware)
await forensicsService.LogTokenUsage(jti, ipAddress, userAgent, user);

// Token revocation
await forensicsService.LogTokenRevocation(jti, adminUserId, "Security incident");
```

### Forensic Investigation

```csharp
// Investigate specific token
var report = await forensicsService.InvestigateToken(jti);

// Security incident analysis
var incidentReport = await forensicsService.AnalyzeSecurityIncident(userId, incidentTime);

// Find related tokens
var relatedTokens = await forensicsService.FindRelatedTokens(userId, timeWindow);
```

## Anomaly Detection

### Automatic Detection
- **Rapid IP Changes**: Token used from different IPs within minutes
- **High Frequency Usage**: Unusual request patterns indicating automation
- **Geographical Anomalies**: Usage from impossible locations
- **Concurrent Sessions**: Same token used from multiple locations

### Custom Patterns
- Configurable thresholds for your environment
- Domain-specific anomaly rules
- Integration with external threat intelligence

## Investigation Capabilities

### Token Forensics Report
```csharp
public class TokenForensicsReport
{
    public string TokenId { get; set; }
    public TokenAuditEvent CreationContext { get; set; }
    public UsagePattern UsagePattern { get; set; }
    public List<AnomalousActivity> AnomalousActivity { get; set; }
    public List<TokenAuditEvent> RevocationHistory { get; set; }
    public int TotalUsageCount { get; set; }
    public DateTimeOffset? FirstUsed { get; set; }
    public DateTimeOffset? LastUsed { get; set; }
}
```

### Security Incident Response
- Timeline reconstruction
- Impact assessment
- Related token identification  
- Automated remediation recommendations

## Performance Considerations

- **Source-Generated Logging**: Zero allocation structured logging
- **Async Audit Storage**: Non-blocking event persistence
- **Configurable Retention**: Automatic cleanup of old audit data
- **Efficient Querying**: Optimized search patterns for investigations

## Best Practices

- Store audit events in separate, secured database
- Implement proper data retention policies
- Monitor for audit system tampering
- Integrate with SIEM systems for broader correlation
- Regular review of detected anomalies