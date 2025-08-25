using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtProductionPatterns.Common;

/// <summary>
/// NIST SP 800-63C compliant JWT token service
/// Implements all required assertion elements per federal standards
/// </summary>
public class NISTCompliantTokenService
{
    private readonly IAssertionTracker _assertionTracker;
    
    public NISTCompliantTokenService(IAssertionTracker assertionTracker)
    {
        _assertionTracker = assertionTracker;
    }

    public async Task<string> CreateCompliantTokenAsync(User user, SecurityKey signingKey, 
        string issuer, string audience)
    {
        var jti = Guid.NewGuid().ToString(); // ✅ Unique assertion identifier
        var authTime = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

        // ✅ NIST SP 800-63C: All required assertion elements
        var claims = new[]
        {
            // Required: Subject identifier  
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            
            // Required: Unique assertion identifier
            new Claim(JwtRegisteredClaimNames.Jti, jti),
            
            // Required: Authentication time
            new Claim(JwtRegisteredClaimNames.AuthTime, authTime.ToString()),
            
            // Required: Issuance timestamp
            new Claim(JwtRegisteredClaimNames.Iat, issuedAt.ToString()),
            
            // Optional: User context for additional security
            new Claim("user_context", await GenerateUserContextAsync(user))
        };

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            
            // ✅ Required: Explicit issuer identifier
            Issuer = issuer,
            
            // ✅ Required: Explicit audience identifier  
            Audience = audience,
            
            // ✅ Required: Expiration timestamp (15 min per NIST recommendations)
            Expires = DateTime.UtcNow.AddMinutes(15),
            
            // ✅ Required: Cryptographic signature with approved algorithms
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)
        };

        var handler = new JsonWebTokenHandler();
        var token = handler.CreateToken(tokenDescriptor);

        // ✅ NIST SP 800-63C: Track assertion for replay prevention
        await _assertionTracker.TrackAssertionAsync(new AssertionRecord
        {
            AssertionId = jti,
            Subject = user.Id.ToString(),
            Issuer = issuer,
            Audience = audience,
            AuthenticationTime = DateTimeOffset.FromUnixTimeSeconds(authTime),
            ExpirationTime = DateTime.UtcNow.AddMinutes(15),
            IssuedAt = DateTimeOffset.FromUnixTimeSeconds(issuedAt)
        });

        return token;
    }

    public async Task<ValidationResult> ValidateCompliantTokenAsync(string token, 
        TokenValidationParameters validationParameters)
    {
        var handler = new JsonWebTokenHandler();
        
        try
        {
            // ✅ Enhanced validation parameters per NIST requirements
            var enhancedParams = validationParameters.Clone();
            enhancedParams.ValidateLifetime = true;
            enhancedParams.ValidateIssuer = true;
            enhancedParams.ValidateAudience = true;
            enhancedParams.ValidateIssuerSigningKey = true;
            enhancedParams.ClockSkew = TimeSpan.Zero; // Strict temporal validation
            
            // ✅ CRITICAL: Algorithm whitelist (prevent CVE-2024-54150)
            enhancedParams.ValidAlgorithms = new[] { SecurityAlgorithms.HmacSha256 };

            var result = await handler.ValidateTokenAsync(token, enhancedParams);
            
            if (!result.IsValid)
                return ValidationResult.Invalid("Token validation failed");

            // ✅ NIST SP 800-63C: Check assertion replay
            var jtiClaim = result.ClaimsIdentity.FindFirst(JwtRegisteredClaimNames.Jti)?.Value;
            if (string.IsNullOrEmpty(jtiClaim))
                return ValidationResult.Invalid("Missing required assertion identifier (jti)");

            var isReplay = await _assertionTracker.IsAssertionReplayAsync(jtiClaim);
            if (isReplay)
                return ValidationResult.Invalid("Assertion replay detected");

            // ✅ Validate required NIST claims
            var authTimeClaim = result.ClaimsIdentity.FindFirst(JwtRegisteredClaimNames.AuthTime)?.Value;
            if (string.IsNullOrEmpty(authTimeClaim))
                return ValidationResult.Invalid("Missing required authentication time (auth_time)");

            return ValidationResult.Valid(new ClaimsPrincipal(result.ClaimsIdentity));
        }
        catch (SecurityTokenException ex)
        {
            return ValidationResult.Invalid($"Security token validation failed: {ex.Message}");
        }
    }

    private async Task<string> GenerateUserContextAsync(User user)
    {
        // Generate cryptographically secure user context
        var contextBytes = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(contextBytes);
        
        // Hash with user-specific data for binding
        using var sha256 = SHA256.Create();
        var combined = contextBytes.Concat(Encoding.UTF8.GetBytes($"{user.Id}:{user.LastLoginTime}")).ToArray();
        var hash = sha256.ComputeHash(combined);
        
        return Convert.ToBase64String(hash);
    }
}

public class AssertionRecord
{
    public string AssertionId { get; set; } = string.Empty;
    public string Subject { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public DateTimeOffset AuthenticationTime { get; set; }
    public DateTime ExpirationTime { get; set; }
    public DateTimeOffset IssuedAt { get; set; }
}

public interface IAssertionTracker
{
    Task TrackAssertionAsync(AssertionRecord assertion);
    Task<bool> IsAssertionReplayAsync(string assertionId);
    Task CleanupExpiredAssertionsAsync();
}

public class ValidationResult
{
    public bool IsValid { get; private set; }
    public string? ErrorMessage { get; private set; }
    public ClaimsPrincipal? Principal { get; private set; }

    private ValidationResult() { }

    public static ValidationResult Valid(ClaimsPrincipal principal)
    {
        return new ValidationResult { IsValid = true, Principal = principal };
    }

    public static ValidationResult Invalid(string errorMessage)
    {
        return new ValidationResult { IsValid = false, ErrorMessage = errorMessage };
    }
}

// Supporting models
public class User
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public DateTimeOffset LastLoginTime { get; set; }
}