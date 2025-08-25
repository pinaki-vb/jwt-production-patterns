using Microsoft.Extensions.Logging;
using System.Security.Claims;
using System.Text.Json;

namespace JwtProductionPatterns.Forensics;

public partial class JwtForensicsService
{
    private readonly IAuditStore _auditStore;
    private readonly ILogger<JwtForensicsService> _logger;

    public JwtForensicsService(IAuditStore auditStore, ILogger<JwtForensicsService> logger)
    {
        _auditStore = auditStore;
        _logger = logger;
    }

    public async Task LogTokenCreation(string jti, string userId, string ipAddress, string userAgent)
    {
        var creationEvent = new TokenAuditEvent
        {
            TokenId = jti,
            EventType = TokenEventType.Created,
            UserId = userId,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Timestamp = DateTimeOffset.UtcNow
        };

        await _auditStore.StoreAuditEventAsync(creationEvent);
        LogTokenCreation(_logger, jti, userId, ipAddress);
    }

    public async Task LogTokenUsage(string jti, string ipAddress, string userAgent, ClaimsPrincipal user)
    {
        var usageEvent = new TokenAuditEvent
        {
            TokenId = jti,
            EventType = TokenEventType.Used,
            UserId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value ?? "unknown",
            IpAddress = ipAddress,
            UserAgent = userAgent,
            Timestamp = DateTimeOffset.UtcNow
        };

        await _auditStore.StoreAuditEventAsync(usageEvent);
        LogTokenUsage(_logger, jti, ipAddress, usageEvent.Timestamp);
    }

    public async Task LogTokenRevocation(string jti, string revokedBy, string reason)
    {
        var revocationEvent = new TokenAuditEvent
        {
            TokenId = jti,
            EventType = TokenEventType.Revoked,
            UserId = revokedBy,
            Reason = reason,
            Timestamp = DateTimeOffset.UtcNow
        };

        await _auditStore.StoreAuditEventAsync(revocationEvent);
        LogTokenRevocation(_logger, jti, revokedBy, reason);
    }

    public async Task<TokenForensicsReport> InvestigateToken(string jti)
    {
        var allEvents = await _auditStore.GetTokenEventsAsync(jti);
        var creationEvents = allEvents.Where(e => e.EventType == TokenEventType.Created).ToList();
        var usageEvents = allEvents.Where(e => e.EventType == TokenEventType.Used).ToList();
        var revocationEvents = allEvents.Where(e => e.EventType == TokenEventType.Revoked).ToList();

        var report = new TokenForensicsReport
        {
            TokenId = jti,
            CreationContext = creationEvents.FirstOrDefault(),
            UsagePattern = AnalyzeUsagePattern(usageEvents),
            AnomalousActivity = DetectAnomalies(usageEvents),
            RevocationHistory = revocationEvents,
            TotalUsageCount = usageEvents.Count,
            FirstUsed = usageEvents.MinBy(e => e.Timestamp)?.Timestamp,
            LastUsed = usageEvents.MaxBy(e => e.Timestamp)?.Timestamp
        };

        return report;
    }

    public async Task<List<string>> FindRelatedTokens(string userId, DateTimeOffset timeWindow)
    {
        return await _auditStore.FindTokensByUserAndTimeAsync(userId, timeWindow);
    }

    public async Task<SecurityIncidentReport> AnalyzeSecurityIncident(string userId, DateTimeOffset incidentTime)
    {
        var timeWindow = TimeSpan.FromHours(24);
        var startTime = incidentTime.Subtract(timeWindow);
        var endTime = incidentTime.Add(timeWindow);
        
        var relatedTokens = await _auditStore.FindTokensByUserAndTimeRangeAsync(userId, startTime, endTime);
        var tokenReports = new List<TokenForensicsReport>();

        foreach (var tokenId in relatedTokens)
        {
            tokenReports.Add(await InvestigateToken(tokenId));
        }

        return new SecurityIncidentReport
        {
            UserId = userId,
            IncidentTime = incidentTime,
            RelatedTokens = tokenReports,
            SuspiciousPatterns = IdentifySuspiciousPatterns(tokenReports),
            RecommendedActions = GenerateRecommendedActions(tokenReports)
        };
    }

    private UsagePattern AnalyzeUsagePattern(List<TokenAuditEvent> usageEvents)
    {
        if (!usageEvents.Any()) return new UsagePattern();

        var ipAddresses = usageEvents.Select(e => e.IpAddress).Distinct().ToList();
        var userAgents = usageEvents.Select(e => e.UserAgent).Distinct().ToList();
        var timeSpan = usageEvents.Max(e => e.Timestamp) - usageEvents.Min(e => e.Timestamp);

        return new UsagePattern
        {
            UniqueIpAddresses = ipAddresses,
            UniqueUserAgents = userAgents,
            UsageTimeSpan = timeSpan,
            UsageFrequency = CalculateUsageFrequency(usageEvents)
        };
    }

    private List<AnomalousActivity> DetectAnomalies(List<TokenAuditEvent> usageEvents)
    {
        var anomalies = new List<AnomalousActivity>();

        // Detect rapid IP changes
        var ipChanges = DetectRapidIpChanges(usageEvents);
        anomalies.AddRange(ipChanges);

        // Detect unusual usage patterns
        var unusualPatterns = DetectUnusualUsagePatterns(usageEvents);
        anomalies.AddRange(unusualPatterns);

        return anomalies;
    }

    private List<AnomalousActivity> DetectRapidIpChanges(List<TokenAuditEvent> events)
    {
        var anomalies = new List<AnomalousActivity>();
        var sortedEvents = events.OrderBy(e => e.Timestamp).ToList();

        for (int i = 1; i < sortedEvents.Count; i++)
        {
            var current = sortedEvents[i];
            var previous = sortedEvents[i - 1];

            if (current.IpAddress != previous.IpAddress && 
                (current.Timestamp - previous.Timestamp).TotalMinutes < 5)
            {
                anomalies.Add(new AnomalousActivity
                {
                    Type = "RapidIpChange",
                    Description = $"IP changed from {previous.IpAddress} to {current.IpAddress} within 5 minutes",
                    Timestamp = current.Timestamp,
                    SeverityLevel = SeverityLevel.High
                });
            }
        }

        return anomalies;
    }

    private List<AnomalousActivity> DetectUnusualUsagePatterns(List<TokenAuditEvent> events)
    {
        var anomalies = new List<AnomalousActivity>();
        
        // Detect unusually high frequency usage
        if (events.Count > 100) // More than 100 uses
        {
            var timeSpan = events.Max(e => e.Timestamp) - events.Min(e => e.Timestamp);
            if (timeSpan.TotalHours < 1) // In less than an hour
            {
                anomalies.Add(new AnomalousActivity
                {
                    Type = "HighFrequencyUsage",
                    Description = $"Token used {events.Count} times in {timeSpan.TotalMinutes:F0} minutes",
                    Timestamp = events.Max(e => e.Timestamp),
                    SeverityLevel = SeverityLevel.Medium
                });
            }
        }

        return anomalies;
    }

    private double CalculateUsageFrequency(List<TokenAuditEvent> events)
    {
        if (events.Count < 2) return 0;

        var timeSpan = events.Max(e => e.Timestamp) - events.Min(e => e.Timestamp);
        return timeSpan.TotalMinutes > 0 ? events.Count / timeSpan.TotalMinutes : 0;
    }

    private List<SuspiciousPattern> IdentifySuspiciousPatterns(List<TokenForensicsReport> reports)
    {
        var patterns = new List<SuspiciousPattern>();

        // Pattern: Multiple tokens with rapid IP changes
        var tokensWithIpChanges = reports.Where(r => r.AnomalousActivity.Any(a => a.Type == "RapidIpChange")).ToList();
        if (tokensWithIpChanges.Count > 1)
        {
            patterns.Add(new SuspiciousPattern
            {
                Type = "MultipleTokensWithIpChanges",
                Description = $"{tokensWithIpChanges.Count} tokens show rapid IP address changes",
                Severity = SeverityLevel.High,
                RelatedTokens = tokensWithIpChanges.Select(r => r.TokenId).ToList()
            });
        }

        return patterns;
    }

    private List<string> GenerateRecommendedActions(List<TokenForensicsReport> reports)
    {
        var actions = new List<string>();

        if (reports.Any(r => r.AnomalousActivity.Any(a => a.SeverityLevel == SeverityLevel.High)))
        {
            actions.Add("Immediately revoke all related tokens");
            actions.Add("Force user to re-authenticate with MFA");
            actions.Add("Review account for unauthorized changes");
        }

        if (reports.Any(r => r.UsagePattern.UniqueIpAddresses.Count > 5))
        {
            actions.Add("Investigate geographical usage patterns");
            actions.Add("Consider implementing geo-blocking");
        }

        return actions;
    }

    // Source-generated structured logging
    [LoggerMessage(EventId = 1001, Level = LogLevel.Information,
        Message = "Token {Jti} created for user {UserId} from {IpAddress}")]
    static partial void LogTokenCreation(ILogger logger, string jti, string userId, string ipAddress);

    [LoggerMessage(EventId = 1002, Level = LogLevel.Information,
        Message = "Token {Jti} used from {IpAddress} at {Timestamp}")]  
    static partial void LogTokenUsage(ILogger logger, string jti, string ipAddress, DateTimeOffset timestamp);

    [LoggerMessage(EventId = 1003, Level = LogLevel.Warning,
        Message = "Token {Jti} revoked by {RevokedBy} - Reason: {Reason}")]
    static partial void LogTokenRevocation(ILogger logger, string jti, string revokedBy, string reason);
}

// Data models and interfaces would go in separate files
public class TokenAuditEvent
{
    public string TokenId { get; set; } = string.Empty;
    public TokenEventType EventType { get; set; }
    public string UserId { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string UserAgent { get; set; } = string.Empty;
    public string Reason { get; set; } = string.Empty;
    public DateTimeOffset Timestamp { get; set; }
}

public enum TokenEventType
{
    Created,
    Used,
    Revoked
}

public class TokenForensicsReport
{
    public string TokenId { get; set; } = string.Empty;
    public TokenAuditEvent? CreationContext { get; set; }
    public UsagePattern UsagePattern { get; set; } = new();
    public List<AnomalousActivity> AnomalousActivity { get; set; } = new();
    public List<TokenAuditEvent> RevocationHistory { get; set; } = new();
    public int TotalUsageCount { get; set; }
    public DateTimeOffset? FirstUsed { get; set; }
    public DateTimeOffset? LastUsed { get; set; }
}

public class UsagePattern
{
    public List<string> UniqueIpAddresses { get; set; } = new();
    public List<string> UniqueUserAgents { get; set; } = new();
    public TimeSpan UsageTimeSpan { get; set; }
    public double UsageFrequency { get; set; }
}

public class AnomalousActivity
{
    public string Type { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public DateTimeOffset Timestamp { get; set; }
    public SeverityLevel SeverityLevel { get; set; }
}

public class SecurityIncidentReport
{
    public string UserId { get; set; } = string.Empty;
    public DateTimeOffset IncidentTime { get; set; }
    public List<TokenForensicsReport> RelatedTokens { get; set; } = new();
    public List<SuspiciousPattern> SuspiciousPatterns { get; set; } = new();
    public List<string> RecommendedActions { get; set; } = new();
}

public class SuspiciousPattern
{
    public string Type { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
    public SeverityLevel Severity { get; set; }
    public List<string> RelatedTokens { get; set; } = new();
}

public enum SeverityLevel
{
    Low,
    Medium,
    High,
    Critical
}

public interface IAuditStore
{
    Task StoreAuditEventAsync(TokenAuditEvent auditEvent);
    Task<List<TokenAuditEvent>> GetTokenEventsAsync(string tokenId);
    Task<List<string>> FindTokensByUserAndTimeAsync(string userId, DateTimeOffset timeWindow);
    Task<List<string>> FindTokensByUserAndTimeRangeAsync(string userId, DateTimeOffset startTime, DateTimeOffset endTime);
}