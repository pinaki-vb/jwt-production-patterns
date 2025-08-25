using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace JwtProductionPatterns.TokenBinding;

public class TokenBindingService
{
    private readonly JsonWebTokenHandler _tokenHandler;

    public TokenBindingService()
    {
        _tokenHandler = new JsonWebTokenHandler();
    }

    public string CreateBoundToken(User user, X509Certificate2 clientCert, SecurityKey signingKey)
    {
        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new Claim("name", user.Name),
            new Claim("cnf", JsonSerializer.Serialize(new TokenConfirmation
            { 
                x5t = clientCert.Thumbprint 
            }))
        };
        
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = "https://your-app.com",
            Audience = "https://your-api.com",
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256)
        };
        
        return _tokenHandler.CreateToken(tokenDescriptor);
    }

    public async Task<ValidationResult> ValidateTokenAsync(string token, SecurityKey validationKey, X509Certificate2? clientCert = null)
    {
        var validationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = "https://your-app.com",
            ValidateAudience = true,
            ValidAudience = "https://your-api.com",
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = validationKey,
            ClockSkew = TimeSpan.Zero
        };

        try
        {
            var result = await _tokenHandler.ValidateTokenAsync(token, validationParameters);
            if (!result.IsValid)
                return ValidationResult.Invalid("Token validation failed");

            var claimsIdentity = result.ClaimsIdentity;
            
            // Check for certificate binding
            var cnfClaim = claimsIdentity?.FindFirst("cnf")?.Value;
            if (!string.IsNullOrEmpty(cnfClaim))
            {
                var confirmation = JsonSerializer.Deserialize<TokenConfirmation>(cnfClaim);
                if (confirmation?.x5t != null)
                {
                    if (clientCert?.Thumbprint != confirmation.x5t)
                    {
                        return ValidationResult.Invalid("Certificate binding validation failed");
                    }
                }
            }

            return ValidationResult.Valid(new ClaimsPrincipal(claimsIdentity));
        }
        catch (Exception ex)
        {
            return ValidationResult.Invalid($"Token validation error: {ex.Message}");
        }
    }
}

public class TokenBindingMiddleware
{
    private readonly RequestDelegate _next;
    private readonly TokenBindingService _tokenBindingService;
    private readonly SecurityKey _validationKey;

    public TokenBindingMiddleware(RequestDelegate next, TokenBindingService tokenBindingService, SecurityKey validationKey)
    {
        _next = next;
        _tokenBindingService = tokenBindingService;
        _validationKey = validationKey;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Skip binding validation for non-authenticated requests
        if (!context.User.Identity?.IsAuthenticated == true)
        {
            await _next(context);
            return;
        }

        var token = ExtractTokenFromRequest(context);
        if (string.IsNullOrEmpty(token))
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync("Missing token");
            return;
        }

        var clientCert = await context.Connection.GetClientCertificateAsync();
        var validationResult = await _tokenBindingService.ValidateTokenAsync(token, _validationKey, clientCert);
        
        if (!validationResult.IsValid)
        {
            context.Response.StatusCode = 401;
            await context.Response.WriteAsync($"Token binding validation failed: {validationResult.ErrorMessage}");
            return;
        }

        // Replace the context user with validated principal
        if (validationResult.Principal != null)
        {
            context.User = validationResult.Principal;
        }

        await _next(context);
    }

    private static string? ExtractTokenFromRequest(HttpContext context)
    {
        var authorization = context.Request.Headers.Authorization.FirstOrDefault();
        if (authorization?.StartsWith("Bearer ") == true)
        {
            return authorization.Substring("Bearer ".Length).Trim();
        }
        return null;
    }
}

// Supporting classes
public class User
{
    public int Id { get; set; }
    public string Name { get; set; } = string.Empty;
}

public class TokenConfirmation
{
    public string? x5t { get; set; }
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

// Extension methods
public static class TokenBindingExtensions
{
    public static IApplicationBuilder UseTokenBinding(this IApplicationBuilder app, SecurityKey validationKey)
    {
        return app.UseMiddleware<TokenBindingMiddleware>(validationKey);
    }
}