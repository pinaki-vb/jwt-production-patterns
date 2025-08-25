using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

namespace JwtProductionPatterns.ReplayDetection;

public class ReplayDetectionService
{
    private readonly IMemoryCache _cache;
    private readonly IGeoLocationService _geoService;
    private readonly ISecurityAlertService _alertService;
    private readonly ILogger<ReplayDetectionService> _logger;

    public ReplayDetectionService(
        IMemoryCache cache,
        IGeoLocationService geoService,
        ISecurityAlertService alertService,
        ILogger<ReplayDetectionService> logger)
    {
        _cache = cache;
        _geoService = geoService;
        _alertService = alertService;
        _logger = logger;
    }

    public async Task<bool> DetectSuspiciousReplay(string jti, HttpContext context)
    {
        var currentUsage = new TokenUsage 
        {
            IpAddress = context.Connection.RemoteIpAddress?.ToString(),
            UserAgent = context.Request.Headers.UserAgent,
            Timestamp = DateTimeOffset.UtcNow,
            Country = await _geoService.GetCountryAsync(context.Connection.RemoteIpAddress)
        };
        
        var recentUsages = _cache.GetList<TokenUsage>($"usage_history:{jti}");
        
        // Flag: Token used from different countries within 30 minutes
        var suspiciousLocation = recentUsages?.Any(u => 
            u.Country != currentUsage.Country && 
            (currentUsage.Timestamp - u.Timestamp).TotalMinutes < 30);
        
        // Flag: Concurrent usage from multiple IPs
        var concurrentUsage = recentUsages?
            .Where(u => (currentUsage.Timestamp - u.Timestamp).TotalMinutes < 5)
            .Select(u => u.IpAddress)
            .Distinct()
            .Count() > 1;
        
        if (suspiciousLocation == true || concurrentUsage == true)
        {
            await _alertService.NotifySecurityTeam(jti, currentUsage, recentUsages);
            throw new SecurityTokenException("Suspicious token usage detected");
        }
        
        // Store current usage for future analysis
        _cache.AddToList($"usage_history:{jti}", currentUsage, TimeSpan.FromHours(2));
        return true;
    }
}

public class TokenUsage
{
    public string? IpAddress { get; set; }
    public string? UserAgent { get; set; }
    public DateTimeOffset Timestamp { get; set; }
    public string? Country { get; set; }
}

public interface IGeoLocationService
{
    Task<string> GetCountryAsync(System.Net.IPAddress? ipAddress);
}

public interface ISecurityAlertService
{
    Task NotifySecurityTeam(string jti, TokenUsage currentUsage, IEnumerable<TokenUsage>? recentUsages);
}

public static class MemoryCacheExtensions
{
    public static List<T>? GetList<T>(this IMemoryCache cache, string key)
    {
        return cache.Get<List<T>>(key);
    }

    public static void AddToList<T>(this IMemoryCache cache, string key, T item, TimeSpan expiration)
    {
        lock (cache) // Simple lock for thread safety - consider more sophisticated locking in production
        {
            var list = cache.Get<List<T>>(key) ?? new List<T>();
            list.Add(item);
            cache.Set(key, list, expiration);
        }
    }
}