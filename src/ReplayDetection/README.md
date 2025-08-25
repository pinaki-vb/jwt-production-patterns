# JWT Replay Detection

This module provides advanced replay detection for JWT tokens in distributed systems using geographical analysis and usage pattern monitoring.

## Features

- **Geographical Analysis**: Detects tokens used from different countries within suspicious time windows
- **Concurrent Usage Detection**: Identifies tokens being used from multiple IP addresses simultaneously
- **Usage History Tracking**: Maintains audit trail of token usage patterns
- **Security Alerts**: Automated notifications for suspicious activity

## Implementation

The `ReplayDetectionService` tracks token usage patterns and flags suspicious activities:

- Tokens used from different countries within 30 minutes
- Concurrent usage from multiple IP addresses within 5 minutes
- Maintains 2-hour usage history for analysis

## Usage

```csharp
// Register services
services.AddSingleton<ReplayDetectionService>();
services.AddSingleton<IGeoLocationService, GeoLocationService>();
services.AddSingleton<ISecurityAlertService, SecurityAlertService>();

// In your JWT middleware
await replayDetectionService.DetectSuspiciousReplay(jti, httpContext);
```

## Security Considerations

- Combine with temporal validation (`ClockSkew = TimeSpan.Zero`)
- Implement rate limiting per `jti`
- Store usage history in distributed cache for multi-node scenarios
- Configure appropriate alert thresholds based on your user base