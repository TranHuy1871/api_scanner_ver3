using ApiCamScanner.Entities;
using ApiCamScanner.Manager;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ApiCamScanner.Token;

public class TokenGen
{
    private readonly TokenManager _tokenManager;
    private readonly IConfiguration _config;

    public TokenGen(TokenManager tokenManager, IConfiguration config)
    {
        _tokenManager = tokenManager;
        _config = config;
    }

    public TokenModel GenerateToken(User user)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();

        var secrectKeyBytes = Encoding.UTF8.GetBytes(_config["JWTSetting:SecrectKey"]);

        var tokenDesc = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new[]
            {
                new Claim("UserId", user.userId.ToString()),
                new Claim("UserName", user.username),

                new Claim(JwtRegisteredClaimNames.Jti,  Guid.NewGuid().ToString()), // id access token
                  
            }),

            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(secrectKeyBytes),
                SecurityAlgorithms.HmacSha512Signature)
        };

        var token = jwtTokenHandler.CreateToken(tokenDesc);

        var accessToken = jwtTokenHandler.WriteToken(token);
        var refreshToken = GenerateRefreshToken();

        // save entity refresh token vào db
        var refreshTokenEntity = new RefreshToken
        {
            TokenRefreshId = Guid.NewGuid().ToString(),
            JwtId = token.Id,
            UserId = user.userId,
            Token = refreshToken,
            IsUsed = false,
            IsRevoked = false,
            IssueAt = DateTime.UtcNow,
            ExpiredAt = DateTime.UtcNow.AddHours(2),
        };
        _tokenManager.AddRefreshToken(refreshTokenEntity, user.userId);


        return new TokenModel
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken
        };
    }

    // refresh token
    public string GenerateRefreshToken()
    {
        var random = new byte[32];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(random);

            return Convert.ToBase64String(random);
        }
    }

    // convert để check xem token đã hh chưa
    public DateTime ConvertUnixTimeToDateTime(long utcExpireDate)
    {
        var dateTimeInterval = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        dateTimeInterval.AddSeconds(utcExpireDate).ToUniversalTime();

        return dateTimeInterval;
    }
}
