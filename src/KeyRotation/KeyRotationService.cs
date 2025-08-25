using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

namespace JwtProductionPatterns.KeyRotation;

public class KeyRotationService
{
    private readonly IKeyManager _keyManager;

    public KeyRotationService(IKeyManager keyManager)
    {
        _keyManager = keyManager;
    }

    public static void ConfigureJwtAuthentication(IServiceCollection services)
    {
        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(options =>
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKeyResolver = (token, securityToken, kid, validationParameters) =>
                    {
                        var serviceProvider = options.BackchannelHttpHandler as IServiceProvider;
                        var keyManager = serviceProvider?.GetService<IKeyManager>();
                        
                        var keys = new List<SecurityKey>
                        {
                            keyManager?.GetCurrentKey() ?? throw new InvalidOperationException("Current key not available")
                        };
                        
                        // During rotation window, accept both current and previous keys
                        if (keyManager.IsInRotationWindow())
                        {
                            var previousKey = keyManager.GetPreviousKey();
                            if (previousKey != null)
                                keys.Add(previousKey);
                        }
                            
                        return keys;
                    }
                };
            });
    }
}

public class KeyManager : IKeyManager
{
    private readonly IKeyStorage _keyStorage;
    private SecurityKey? _currentKey;
    private SecurityKey? _previousKey;
    private DateTimeOffset _rotationWindowStart;
    private readonly TimeSpan _rotationWindow = TimeSpan.FromHours(2);

    public KeyManager(IKeyStorage keyStorage)
    {
        _keyStorage = keyStorage;
        LoadKeys();
    }

    public SecurityKey GetCurrentKey()
    {
        return _currentKey ?? throw new InvalidOperationException("Current key not available");
    }

    public SecurityKey? GetPreviousKey()
    {
        return _previousKey;
    }

    public bool IsInRotationWindow()
    {
        return DateTimeOffset.UtcNow < _rotationWindowStart.Add(_rotationWindow);
    }

    public async Task RotateKeyAsync()
    {
        // Phase 1: Generate new key
        var newKey = GenerateNewKey();
        
        // Phase 2: Store new key and mark rotation start
        await _keyStorage.StoreKeyAsync("current", newKey);
        if (_currentKey != null)
        {
            await _keyStorage.StoreKeyAsync("previous", _currentKey);
        }
        
        // Phase 3: Update in-memory references
        _previousKey = _currentKey;
        _currentKey = newKey;
        _rotationWindowStart = DateTimeOffset.UtcNow;
    }

    public async Task CompleteRotationAsync()
    {
        // Only complete rotation after buffer window
        if (!IsInRotationWindow())
        {
            await _keyStorage.DeleteKeyAsync("previous");
            _previousKey = null;
        }
    }

    private void LoadKeys()
    {
        _currentKey = _keyStorage.GetKey("current");
        _previousKey = _keyStorage.GetKey("previous");
        _rotationWindowStart = _keyStorage.GetRotationWindowStart();
    }

    private static SecurityKey GenerateNewKey()
    {
        using var hmac = new HMACSHA256();
        return new SymmetricSecurityKey(hmac.Key);
    }
}

public interface IKeyManager
{
    SecurityKey GetCurrentKey();
    SecurityKey? GetPreviousKey();
    bool IsInRotationWindow();
    Task RotateKeyAsync();
    Task CompleteRotationAsync();
}

public interface IKeyStorage
{
    SecurityKey? GetKey(string keyId);
    Task StoreKeyAsync(string keyId, SecurityKey key);
    Task DeleteKeyAsync(string keyId);
    DateTimeOffset GetRotationWindowStart();
}