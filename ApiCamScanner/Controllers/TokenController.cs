using ApiCamScanner.Entities;
using ApiCamScanner.Manager;
using ApiCamScanner.Token;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ApiCamScanner.Controllers;

[Route("api/[controller]")]
[ApiController]
public class TokenController : ControllerBase
{
    private readonly TokenManager _tokenManager;
    private readonly IConfiguration _config;
    private readonly TokenGen _token;

    public TokenController(TokenManager tokenManager, IConfiguration config, TokenGen token)
    {
        _tokenManager = tokenManager;
        _config = config;
        _token = token;
    }

    [HttpPost("RefreshToken")]
    public IActionResult RefreshToken(TokenModel tokenModel)
    {
        var jwtTokenHandler = new JwtSecurityTokenHandler();
        var secrectKeyBytes = Encoding.UTF8.GetBytes(_config["JWTSetting:SecrectKey"]);

        var tokenParam = new TokenValidationParameters
        {
            // tự cấp token
            ValidateIssuer = false,
            ValidateAudience = false,

            // ký vào token
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(secrectKeyBytes), // thuật toán đối xứng (tự động mã hóa)

            ClockSkew = TimeSpan.Zero,
            ValidateLifetime = false, // k check token hh
        };

        try
        {
            // check access token valid format
            var tokenInVerification = jwtTokenHandler.ValidateToken(
                tokenModel.AccessToken,
                tokenParam,
                out var validatedToken);

            // check alg
            if (validatedToken is JwtSecurityToken jwtSecurityToken)
            {
                var result = jwtSecurityToken.Header.Alg.Equals
                    (SecurityAlgorithms.HmacSha512,
                    StringComparison.InvariantCultureIgnoreCase);

                if (!result) // false
                {
                    return BadRequest("k đúng alg: " + result);
                }

            }

            // check access token expire
            var utcExpireDate = long.Parse(tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);
            var expireDate = _token.ConvertUnixTimeToDateTime(utcExpireDate);

            if (expireDate > DateTime.UtcNow)
            {
                return BadRequest("hết hạn");
            }

            // check refreshtoken có trong db k
            var storedToken = _tokenManager.GetToken(tokenModel);
             

            if (storedToken is null)
            {
                return BadRequest("token null");
            }

            // check refreshtoken đã use chưa
            if (storedToken.IsUsed)
            {
                return BadRequest("đã đc sử dụng");
            }

            // check refreshtoken đã revoke chưa
            if (storedToken.IsRevoked)
            {
                return BadRequest("đã bị thu hồi");
            }

            // check access token == jwtid trong refresh token k
            var jti = tokenInVerification.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

            if (storedToken.JwtId != jti)
            {
                return BadRequest("token đã hh k trùng");
            }

            // update token is used
            storedToken.IsUsed = true;
            storedToken.IsRevoked = true;

            _tokenManager.UpdateToken(storedToken);

            // create new token
            var user = _tokenManager.CreateNewToken(storedToken);
            var token = _token.GenerateToken(user);

            return Ok(token);
        }
        catch (Exception ex)
        {
            return BadRequest(ex.Message);
        }
    }
}
