using Dapper;
using Microsoft.Data.SqlClient;
using MyJWT.Models;
using System.Data;

namespace MyJWT.Repository
{
    public interface IUserRepository
    {
        User GetUserByEmail(string email);
        void UpdateSession(int userId, string sessionId);
        void UpdateTokenExpiration(int userId, DateTime tokenExpiryTime);
        void InvalidateSession(int userId);
        Task SaveRefreshTokenAsync(int userId, string refreshToken, DateTime expiryTime);
        Task<User> GetUserByRefreshTokenAsync(string refreshToken);
        Task<User> GetUserByIdAsync(int userId);
        bool ValidateToken(int userId, string sessionId);
    }
    public class UserRepository : IUserRepository
    {
        private readonly IDbConnection _dbConnection;

        public UserRepository(IDbConnection dbConnection)
        {
            _dbConnection = dbConnection;
        }

        public async Task SaveRefreshTokenAsync(int userId, string refreshToken, DateTime expiryTime)
        {
            var sql = "UPDATE Users SET RefreshToken = @RefreshToken, RefreshTokenExpiryTime = @ExpiryTime WHERE Id = @Id";
            await _dbConnection.ExecuteAsync(sql, new { RefreshToken = refreshToken, ExpiryTime = expiryTime, Id = userId });
        }

        public async Task<User> GetUserByRefreshTokenAsync(string refreshToken)
        {
            var sql = "SELECT * FROM Users WHERE RefreshToken = @RefreshToken";
            return await _dbConnection.QueryFirstOrDefaultAsync<User>(sql, new { RefreshToken = refreshToken });
        }

        public async Task<User> GetUserByIdAsync(int userId)
        {
            var sql = "SELECT * FROM Users WHERE Id = @Id";
            return await _dbConnection.QueryFirstOrDefaultAsync<User>(sql, new { Id = userId });
        }

        public void UpdateSession(int userId, string sessionId)
        {
            var sql = "UPDATE Users SET SessionId = @SessionId WHERE Id = @Id";
            _dbConnection.Execute(sql, new { SessionId = sessionId, Id = userId });
        }

        public void UpdateTokenExpiration(int userId, DateTime tokenExpiryTime)
        {
            var sql = "UPDATE Users SET TokenExpiryTime = @TokenExpiryTime WHERE Id = @Id";
            _dbConnection.Execute(sql, new { TokenExpiryTime = tokenExpiryTime, Id = userId });
        }

        public bool ValidateToken(int userId, string sessionId)
        {
            var sql = "SELECT TOP 1 * FROM Users WHERE Id = @Id AND SessionId = @SessionId";
            var user = _dbConnection.QueryFirstOrDefault<User>(sql, new { Id = userId, SessionId = sessionId });
            var now = DateTime.UtcNow;
            if (user is null || user.SessionId != sessionId || user.TokenExpiryTime < now)
            {
                return false;
            }
            return true;
        }

        public void InvalidateSession(int userId)
        {
            string? refreshToken = null;
            string? sessionId = null;
            var expirationTime = DateTime.UtcNow.AddYears(-30);
            var sql = @"UPDATE Users SET RefreshToken = @RefreshToken, SessionId = @SessionId, 
                            RefreshTokenExpiryTime = @RefreshTokenExpiryTime, TokenExpiryTime = @TokenExpiryTime
                            WHERE Id = @Id";
            _dbConnection.Execute(sql, new
            {
                RefreshToken = refreshToken,
                SessionId = sessionId,
                Id = userId,
                RefreshTokenExpiryTime = expirationTime,
                TokenExpiryTime = expirationTime
            });
        }

        public User? GetUserByEmail(string email)
        {
            var sql = "SELECT TOP 1 * FROM Users WHERE Email = @Email";
            return _dbConnection.QueryFirstOrDefault<User>(sql, new { Email = email });
        }
    }
}
