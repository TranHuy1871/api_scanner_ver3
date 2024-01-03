using ApiCamScanner.Entities;
using Dapper;
using MySqlConnector;

namespace ApiCamScanner.Manager
{
    public class TokenManager
    {
        private readonly IConfiguration _config;

        public TokenManager(IConfiguration config)
        {
            _config = config;
        }

        private MySqlConnection CreateDbConnection()
        {
            return new MySqlConnection(_config.GetConnectionString("MyConnection"));
        }

        public void AddRefreshToken(RefreshToken refreshTokenDTO, int userId)
        {
            using (var connection = CreateDbConnection())
            {
                // Insert a new RefreshToken and associate it with the given UserId
                connection.Execute(
                    "INSERT INTO RefreshToken (TokenRefreshId, Token, JwtId, IsUsed, IsRevoked, IssueAt, ExpiredAt, UserId) " +
                    "VALUES (@TokenRefreshId, @Token, @JwtId, @IsUsed, @IsRevoked, @IssueAt, @ExpiredAt, @UserId)",
                    new
                    {
                        refreshTokenDTO.TokenRefreshId,
                        refreshTokenDTO.Token,
                        refreshTokenDTO.JwtId,
                        refreshTokenDTO.IsUsed,
                        refreshTokenDTO.IsRevoked,
                        refreshTokenDTO.IssueAt,
                        refreshTokenDTO.ExpiredAt,
                        UserId = userId  // Associate the RefreshToken with the given UserId
                    });
            }
        }


        public RefreshToken GetToken(TokenModel tokenModel)
        {
            using (var connection = CreateDbConnection())
            {
                var refreshToken = tokenModel.RefreshToken;

                return connection.QueryFirstOrDefault<RefreshToken>(
                    "SELECT *FROM RefreshToken WHERE Token = @RefreshToken",
                    new { RefreshToken = refreshToken });
            }
        }




        public void UpdateToken(RefreshToken refreshTokenDTO)
        {
            using (var connection = CreateDbConnection())
            {
                connection.Execute("UPDATE RefreshToken SET " +
                                   "Token = @Token, " +
                                   "JwtId = @JwtId, " +
                                   "IsUsed = @IsUsed, " +
                                   "IsRevoked = @IsRevoked, " +
                                   "IssueAt = @IssueAt, " +
                                   "ExpiredAt = @ExpiredAt " +
                                   "WHERE TokenRefreshId = @TokenRefreshId",
                                   new
                                   {
                                       refreshTokenDTO.Token,
                                       refreshTokenDTO.JwtId,
                                       refreshTokenDTO.IsUsed,
                                       refreshTokenDTO.IsRevoked,
                                       refreshTokenDTO.IssueAt,
                                       refreshTokenDTO.ExpiredAt,
                                       refreshTokenDTO.TokenRefreshId
                                   });
            }
        }


        public User CreateNewToken(RefreshToken refreshTokenDTO)
        {
            using (var connection = CreateDbConnection())
            {
                return connection.QueryFirstOrDefault<User>("SELECT * FROM Users WHERE UserId = @UserId", new { UserId = refreshTokenDTO.UserId });
            }
        }
    }
}
