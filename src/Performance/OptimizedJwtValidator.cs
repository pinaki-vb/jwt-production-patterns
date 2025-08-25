using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.ObjectPool;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;
using System.Text;

namespace JwtProductionPatterns.Performance;

public class OptimizedJwtValidator
{
    private readonly IMemoryCache _cache;
    private readonly IObjectPool<JsonWebTokenHandler> _handlerPool;
    private readonly TokenValidationParameters _validationParameters;

    public OptimizedJwtValidator(
        IMemoryCache cache,
        IObjectPool<JsonWebTokenHandler> handlerPool,
        TokenValidationParameters validationParameters)
    {
        _cache = cache;
        _handlerPool = handlerPool;
        _validationParameters = validationParameters;
    }

    public async Task<TokenValidationResult> ValidateAsync(string token)
    {
        // Fast path: cache lookup by token hash
        var tokenHash = ComputeHash(token);
        var cacheKey = $"jwt_validation:{tokenHash}";
        
        if (_cache.TryGetValue(cacheKey, out TokenValidationResult? cached) && cached != null)
        {
            return cached;
        }
        
        // Validation with pooled handler
        var handler = _handlerPool.Get();
        try
        {
            var result = await handler.ValidateTokenAsync(token, _validationParameters);
            
            // Cache successful validations (respecting expiry)
            if (result.IsValid)
            {
                var cacheDuration = GetTokenExpiry(token) - DateTimeOffset.UtcNow;
                
                // Cache with 2-minute buffer before expiry to account for clock skew
                var safeCacheDuration = cacheDuration.Add(TimeSpan.FromMinutes(-2));
                
                if (safeCacheDuration > TimeSpan.Zero)
                {
                    _cache.Set(cacheKey, result, safeCacheDuration);
                }
            }
            
            return result;
        }
        finally 
        { 
            _handlerPool.Return(handler); 
        }
    }

    public async Task<bool> IsTokenValidAsync(string token)
    {
        var result = await ValidateAsync(token);
        return result.IsValid;
    }

    public void InvalidateToken(string token)
    {
        var tokenHash = ComputeHash(token);
        var cacheKey = $"jwt_validation:{tokenHash}";
        _cache.Remove(cacheKey);
    }

    public void ClearCache()
    {
        if (_cache is MemoryCache memoryCache)
        {
            memoryCache.Clear();
        }
    }

    private static string ComputeHash(string input)
    {
        using var sha256 = SHA256.Create();
        var hashBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToBase64String(hashBytes);
    }

    private DateTimeOffset GetTokenExpiry(string token)
    {
        try
        {
            var handler = new JsonWebTokenHandler();
            var jsonToken = handler.ReadJsonWebToken(token);
            
            if (jsonToken.ValidTo != DateTime.MinValue)
            {
                return new DateTimeOffset(jsonToken.ValidTo);
            }
        }
        catch
        {
            // If we can't read the token, return current time to prevent caching
        }
        
        return DateTimeOffset.UtcNow;
    }
}

public class JwtHandlerPoolPolicy : IPooledObjectPolicy<JsonWebTokenHandler>
{
    public JsonWebTokenHandler Create()
    {
        return new JsonWebTokenHandler();
    }

    public bool Return(JsonWebTokenHandler obj)
    {
        // JsonWebTokenHandler is stateless and thread-safe, so always return true
        return true;
    }
}

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddOptimizedJwtValidation(this IServiceCollection services)
    {
        // Register object pool for JsonWebTokenHandler
        services.AddSingleton<IObjectPool<JsonWebTokenHandler>>(serviceProvider =>
        {
            var poolProvider = serviceProvider.GetRequiredService<ObjectPoolProvider>();
            var policy = new JwtHandlerPoolPolicy();
            return poolProvider.Create(policy);
        });

        // Register the optimized validator
        services.AddSingleton<OptimizedJwtValidator>();

        return services;
    }

    public static IServiceCollection AddOptimizedJwtValidation(
        this IServiceCollection services, 
        Action<TokenValidationParameters> configureValidation)
    {
        services.AddOptimizedJwtValidation();

        // Configure validation parameters
        services.Configure<TokenValidationParameters>(configureValidation);
        
        return services;
    }
}

// High-performance JWT middleware
public class OptimizedJwtMiddleware
{
    private readonly RequestDelegate _next;
    private readonly OptimizedJwtValidator _validator;

    public OptimizedJwtMiddleware(RequestDelegate next, OptimizedJwtValidator validator)
    {
        _next = next;
        _validator = validator;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var token = ExtractTokenFromRequest(context);
        
        if (!string.IsNullOrEmpty(token))
        {
            var validationResult = await _validator.ValidateAsync(token);
            
            if (validationResult.IsValid && validationResult.ClaimsIdentity != null)
            {
                context.User = new System.Security.Claims.ClaimsPrincipal(validationResult.ClaimsIdentity);
            }
            else
            {
                context.Response.StatusCode = 401;
                await context.Response.WriteAsync("Invalid token");
                return;
            }
        }

        await _next(context);
    }

    private static string? ExtractTokenFromRequest(HttpContext context)
    {
        var authorization = context.Request.Headers.Authorization.FirstOrDefault();
        if (authorization?.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) == true)
        {
            return authorization.Substring("Bearer ".Length).Trim();
        }
        return null;
    }
}

// Performance monitoring
public class JwtValidationMetrics
{
    private long _totalValidations;
    private long _cacheHits;
    private long _cacheMisses;
    private readonly object _lock = new object();

    public void RecordValidation()
    {
        lock (_lock)
        {
            _totalValidations++;
        }
    }

    public void RecordCacheHit()
    {
        lock (_lock)
        {
            _cacheHits++;
        }
    }

    public void RecordCacheMiss()
    {
        lock (_lock)
        {
            _cacheMisses++;
        }
    }

    public JwtValidationStats GetStats()
    {
        lock (_lock)
        {
            return new JwtValidationStats
            {
                TotalValidations = _totalValidations,
                CacheHits = _cacheHits,
                CacheMisses = _cacheMisses,
                CacheHitRatio = _totalValidations > 0 ? (double)_cacheHits / _totalValidations : 0
            };
        }
    }

    public void Reset()
    {
        lock (_lock)
        {
            _totalValidations = 0;
            _cacheHits = 0;
            _cacheMisses = 0;
        }
    }
}

public class JwtValidationStats
{
    public long TotalValidations { get; set; }
    public long CacheHits { get; set; }
    public long CacheMisses { get; set; }
    public double CacheHitRatio { get; set; }
}

// Extension methods for IApplicationBuilder
public static class ApplicationBuilderExtensions
{
    public static IApplicationBuilder UseOptimizedJwtAuthentication(this IApplicationBuilder app)
    {
        return app.UseMiddleware<OptimizedJwtMiddleware>();
    }
}