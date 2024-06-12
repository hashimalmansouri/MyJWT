using Dapper;
using Microsoft.Data.SqlClient;
using MyJwtAPI.Models;
using System.Data;

namespace MyJwtAPI.Repository
{
    public interface IUserRepository
    {
        User GetUserByEmail(string email);
        void InvalidateSession(int userId, int userLoginId);
        Task SaveRefreshTokenAsync(int userId, string refreshToken, DateTime expiryTime);
        Task<User> GetUserByRefreshTokenAsync(string refreshToken);
        Task<User> GetUserByIdAsync(int userId);
        bool ValidateToken(int userId, string sessionId);
        Task<UserLogin> GetUserLoginsAsync(int userId, string sessionId);
        Task SaveUserLoginAsync(UserLogin userLogin);
        Task UpdateUserLoginAsync(UserLogin userLogin);
        Task DeleteUserLoginsAsync(int userId);
        Task<UserLogin> GetUserLoginByRefreshTokenAsync(string refreshToken);
        Task<UserLogin> GetUserLoginBySessionIdAsync(string sessionId);

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

        public bool ValidateToken(int userId, string sessionId)
        {
            var sql = "SELECT COUNT(*) FROM UserLogins WHERE UserId = @UserId AND SessionId = @SessionId";
            var count = _dbConnection.ExecuteScalar<int>(sql, new { UserId = userId, SessionId = sessionId });
            return count > 0;
        }


        public void InvalidateSession(int userId, int userLoginId)
        {
            var sql = @"DELETE FROM UserLogins WHERE UserId = @UserId AND Id = @Id";
            _dbConnection.Execute(sql, new { UserId = userId, Id = userLoginId });
        }

        public User? GetUserByEmail(string email)
        {
            var sql = "SELECT TOP 1 * FROM Users WHERE Email = @Email";
            return _dbConnection.QueryFirstOrDefault<User>(sql, new { Email = email });
        }

        public async Task SaveUserLoginAsync(UserLogin userLogin)
        {
            var sql = @"INSERT INTO UserLogins (UserId, SessionId, RefreshToken, RefreshTokenExpiryTime, TokenExpiryTime) 
                    VALUES (@UserId, @SessionId, @RefreshToken, @RefreshTokenExpiryTime, @TokenExpiryTime)";
            await _dbConnection.ExecuteAsync(sql, userLogin);
        }
        public async Task UpdateUserLoginAsync(UserLogin userLogin)
        {
            var sql = @"UPDATE UserLogins SET SessionId = @SessionId, RefreshToken = @RefreshToken,
                        RefreshTokenExpiryTime = @RefreshTokenExpiryTime, TokenExpiryTime = @TokenExpiryTime
                        WHERE Id = @Id";
            await _dbConnection.ExecuteAsync(sql, userLogin);
        }

        public async Task DeleteUserLoginsAsync(int userId)
        {
            var sql = @"DELETE FROM UserLogins WHERE UserId = @UserId";
            await _dbConnection.ExecuteAsync(sql, new { UserId = userId });
        }


        public async Task<UserLogin> GetUserLoginByRefreshTokenAsync(string refreshToken)
        {
            var sql = "SELECT * FROM UserLogins WHERE RefreshToken = @RefreshToken";
            return await _dbConnection.QueryFirstOrDefaultAsync<UserLogin>(sql, new { RefreshToken = refreshToken });
        }

        public async Task<UserLogin> GetUserLoginBySessionIdAsync(string sessionId)
        {
            var sql = "SELECT * FROM UserLogins WHERE SessionId = @SessionId";
            return await _dbConnection.QueryFirstOrDefaultAsync<UserLogin>(sql, new { SessionId = sessionId });
        }

        public async Task<UserLogin> GetUserLoginsAsync(int userId, string sessionId)
        {
            var sql = "SELECT * FROM UserLogins WHERE UserId = @UserId AND SessionId = @SessionId";
            return await _dbConnection.QueryFirstOrDefaultAsync<UserLogin>(sql, new { UserId = userId, SessionId = sessionId });
        }
    }
}
