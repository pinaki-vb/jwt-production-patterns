# JWT Replay Detection: When Tokens Travel Too Far, Too Fast

## The "Impossible Geography" Problem

Here's a scenario that happened at a financial services company: a user's JWT was used to access sensitive data from San Francisco at 2:15 PM, then again from Lagos, Nigeria at 2:17 PM. Physically impossible? Yes. Security breach? Definitely.

Traditional JWT validation would happily accept both requests because the token was technically valid. The problem isn't the token - it's that someone intercepted it.

## How We Catch These "Teleporting" Tokens

Let's walk through the core detection logic:

```csharp
public async Task<bool> DetectSuspiciousReplay(string jti, HttpContext context)
{
    var currentUsage = new TokenUsage 
    {
        IpAddress = context.Connection.RemoteIpAddress?.ToString(),
        UserAgent = context.Request.Headers.UserAgent,
        Timestamp = DateTimeOffset.UtcNow,
        Country = await _geoService.GetCountryAsync(context.Connection.RemoteIpAddress)
    };
```

First, we capture the "fingerprint" of this token usage - not just IP and User-Agent, but **geographical context**. This is crucial because attackers often operate from different continents than your users.

### Pattern 1: The Impossible Journey

```csharp
// Flag: Token used from different countries within 30 minutes
var suspiciousLocation = recentUsages?.Any(u => 
    u.Country != currentUsage.Country && 
    (currentUsage.Timestamp - u.Timestamp).TotalMinutes < 30);
```

This catches the "teleportation" problem. If your user was authenticated from the US and suddenly appears in Russia 5 minutes later, we flag it. The 30-minute window accounts for legitimate edge cases (VPN switching, mobile roaming) while catching obvious breaches.

**Real-world adjustment**: You might tune this based on your user base. A global company might use 60 minutes; a local business might use 15.

### Pattern 2: The Concurrent Sessions Attack

```csharp
// Flag: Concurrent usage from multiple IPs
var concurrentUsage = recentUsages?
    .Where(u => (currentUsage.Timestamp - u.Timestamp).TotalMinutes < 5)
    .Select(u => u.IpAddress)
    .Distinct()
    .Count() > 1;
```

This detects when the same token is being used from multiple locations simultaneously. Legitimate users don't typically browse your app from 3 different IP addresses in the same 5-minute window.

**Why 5 minutes?** It's long enough to catch overlapping sessions but short enough to avoid false positives from legitimate network switching.

## Thread Safety: The Devil in the Details

Notice this implementation detail:

```csharp
public static void AddToList<T>(this IMemoryCache cache, string key, T item, TimeSpan expiration)
{
    lock (cache) // Simple lock for thread safety
    {
        var list = cache.Get<List<T>>(key) ?? new List<T>();
        list.Add(item);
        cache.Set(key, list, expiration);
    }
}
```

**Why the lock?** Without it, you get race conditions where two concurrent requests might both read an empty list, add their item, and overwrite each other. The second usage gets lost, and your security detection fails.

**Production consideration**: This simple lock works for moderate loads, but for high-throughput APIs, consider using `ConcurrentDictionary<string, ConcurrentBag<TokenUsage>>` or distributed caching with atomic operations.

## The Security Response Chain

When we detect suspicious activity:

```csharp
if (suspiciousLocation == true || concurrentUsage == true)
{
    await _alertService.NotifySecurityTeam(jti, currentUsage, recentUsages);
    throw new SecurityTokenException("Suspicious token usage detected");
}
```

This does two critical things:
1. **Immediate blocking** - The request fails with a security exception
2. **Alert generation** - Your security team gets context about what triggered the alert

**Design choice**: We throw an exception rather than returning false because this is a security event, not a validation failure. The calling code needs to know something serious happened.

## What This Doesn't Catch

This implementation focuses on geographical and temporal anomalies, but attackers have other techniques:

- **Same-country attacks**: If the attacker is in the same country, this won't trigger
- **VPN evasion**: Sophisticated attackers use VPNs matching the user's location
- **Slow-and-low attacks**: Patient attackers who wait between requests won't trigger time-based detection

For comprehensive protection, combine this with:
- Rate limiting per token
- Behavioral analysis (unusual API usage patterns)
- Device fingerprinting
- User-agent analysis

## The Trade-offs

**False positives**: Legitimate users with VPNs, frequent travelers, or corporate proxy switching might trigger alerts. Monitor your false positive rate and adjust thresholds.

**Performance**: Each token validation now requires cache lookup and geographical analysis. The geo lookup is typically cached, but still adds latency.

**Storage**: We're storing usage history for every token. In high-volume systems, this can consume significant memory. Consider using Redis with TTL for distributed scenarios.

## A Real Attack Scenario

Here's how this plays out in practice:

1. **Initial breach**: Attacker dumps application logs and finds JWT tokens
2. **Token replay**: Attacker uses stolen token from their location (different country)  
3. **Detection**: Our system notices impossible geography and blocks the request
4. **Alert**: Security team gets notified with full context
5. **Response**: Token gets revoked, user gets notified to re-authenticate

Without this pattern, the attacker would have free access until the token naturally expires - potentially hours of unauthorized access to sensitive data.