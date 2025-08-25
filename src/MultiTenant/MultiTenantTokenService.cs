using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Text.Json;

namespace JwtProductionPatterns.MultiTenant;

public class MultiTenantTokenService
{
    private readonly ITenantKeyManager _keyManager;
    private readonly JsonWebTokenHandler _tokenHandler;

    public MultiTenantTokenService(ITenantKeyManager keyManager)
    {
        _keyManager = keyManager;
        _tokenHandler = new JsonWebTokenHandler();
    }

    public string CreateToken(User user, Tenant tenant)
    {
        var tenantKey = _keyManager.GetTenantKey(tenant.Id);
        
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim("permissions", string.Join(",", user.GetPermissions(tenant.Id)))
            // No tenant_id claim needed - implicit in signing key
        };
        
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = $"https://app.com/tenant/{tenant.Id}",
            Audience = $"api://app/tenant/{tenant.Id}",
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = new SigningCredentials(tenantKey, SecurityAlgorithms.HmacSha256)
        };
        
        return _tokenHandler.CreateToken(tokenDescriptor);
    }

    public async Task<ClaimsPrincipal?> ValidateTokenAsync(string token, string expectedTenantId)
    {
        var tenantKey = _keyManager.GetTenantKey(expectedTenantId);
        
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = $"https://app.com/tenant/{expectedTenantId}",
            ValidateAudience = true,
            ValidAudience = $"api://app/tenant/{expectedTenantId}",
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = tenantKey,
            ClockSkew = TimeSpan.Zero // Strict temporal validation
        };

        try
        {
            var result = await _tokenHandler.ValidateTokenAsync(token, validationParameters);
            return result.IsValid ? new ClaimsPrincipal(result.ClaimsIdentity) : null;
        }
        catch
        {
            return null;
        }
    }
}

public class TenantKeyManager : ITenantKeyManager
{
    private readonly ITenantRepository _tenantRepository;
    private readonly IKeyStorage _keyStorage;

    public TenantKeyManager(ITenantRepository tenantRepository, IKeyStorage keyStorage)
    {
        _tenantRepository = tenantRepository;
        _keyStorage = keyStorage;
    }

    public SecurityKey GetTenantKey(string tenantId)
    {
        // Validate tenant exists
        var tenant = _tenantRepository.GetTenant(tenantId);
        if (tenant == null)
            throw new ArgumentException($"Tenant {tenantId} not found", nameof(tenantId));

        // Get or generate tenant-specific key
        var key = _keyStorage.GetKey($"tenant:{tenantId}");
        if (key == null)
        {
            key = GenerateTenantKey();
            _keyStorage.StoreKey($"tenant:{tenantId}", key);
        }

        return key;
    }

    public async Task RotateTenantKeyAsync(string tenantId)
    {
        var newKey = GenerateTenantKey();
        
        // Store new key with versioning for gradual rotation
        await _keyStorage.StoreKeyAsync($"tenant:{tenantId}:new", newKey);
        
        // After rotation window, promote to current
        await Task.Delay(TimeSpan.FromHours(1)); // Simplified - use proper scheduling
        await _keyStorage.StoreKeyAsync($"tenant:{tenantId}", newKey);
        await _keyStorage.DeleteKeyAsync($"tenant:{tenantId}:new");
    }

    private static SecurityKey GenerateTenantKey()
    {
        using var hmac = new System.Security.Cryptography.HMACSHA256();
        return new SymmetricSecurityKey(hmac.Key);
    }
}

// Domain models
public class User
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
    
    public List<string> GetPermissions(string tenantId)
    {
        // Return user's permissions for specific tenant
        return new List<string> { "read", "write" };
    }
}

public class Tenant
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
}

// Interfaces
public interface ITenantKeyManager
{
    SecurityKey GetTenantKey(string tenantId);
    Task RotateTenantKeyAsync(string tenantId);
}

public interface ITenantRepository
{
    Tenant? GetTenant(string tenantId);
    Task<List<Tenant>> GetAllTenantsAsync();
}

public interface IKeyStorage
{
    SecurityKey? GetKey(string keyId);
    Task StoreKeyAsync(string keyId, SecurityKey key);
    void StoreKey(string keyId, SecurityKey key);
    Task DeleteKeyAsync(string keyId);
}