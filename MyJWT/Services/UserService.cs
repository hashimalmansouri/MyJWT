using MyJWT.Models;
using MyJWT.Repository;

namespace MyJWT.Services
{
    public interface IUserService
    {
        Task<User> GetUserByRefreshTokenAsync(string refreshToken);
        Task<User> GetUserByIdAsync(int userId);
        void UpdateSession(int userId, string sessionId);
        void UpdateTokenExpiration(int userId, int expireInSeconds);
        User GetUserByEmail(string email);
        Task SaveRefreshTokenAsync(int userId, string refreshToken, int expireInSeconds);
        void InvalidateSession(int userId, int userLoginId);
        bool ValidateToken(int userId, string sessionId);
        Task<UserLogin> GetUserLoginByRefreshTokenAsync(string refreshToken);
        Task<UserLogin> GetUserLoginBySessionIdAsync(string sessionId);
        Task SaveUserLoginAsync(UserLogin userLogin);
        Task UpdateUserLoginAsync(UserLogin userLogin);
        Task DeleteUserLoginsAsync(int userId);
        Task<UserLogin> GetUserLoginsAsync(int userId, string sessionId);
        void CleanupExpiredTokens();

    }
    public class UserService : IUserService
    {
        private readonly IUserRepository _userRepository;

        public UserService(IUserRepository userRepository)
        {
            _userRepository = userRepository;
        }

        public void CleanupExpiredTokens()
        {
            _userRepository.CleanupExpiredTokens();
        }

        public async Task DeleteUserLoginsAsync(int userId)
        {
            await _userRepository.DeleteUserLoginsAsync(userId); 
        }

        public User GetUserByEmail(string email)
        {
            return _userRepository.GetUserByEmail(email);   
        }

        public async Task<User> GetUserByIdAsync(int userId)
        {
            return await _userRepository.GetUserByIdAsync(userId);
        }

        public async Task<User> GetUserByRefreshTokenAsync(string refreshToken)
        {
            return await _userRepository.GetUserByRefreshTokenAsync(refreshToken);
        }

        public async Task<UserLogin> GetUserLoginByRefreshTokenAsync(string refreshToken)
        {
            return await _userRepository.GetUserLoginByRefreshTokenAsync(refreshToken);
        }

        public async Task<UserLogin> GetUserLoginBySessionIdAsync(string sessionId)
        {
            return await _userRepository.GetUserLoginBySessionIdAsync(sessionId);
        }

        public async Task<UserLogin> GetUserLoginsAsync(int userId, string sessionId)
        {
            return await _userRepository.GetUserLoginsAsync(userId, sessionId);
        }

        public void InvalidateSession(int userId, int userLoginId)
        {
            _userRepository.InvalidateSession(userId, userLoginId);
        }

        public async Task SaveRefreshTokenAsync(int userId, string refreshToken, int expireInSeconds)
        {
            var expiration = DateTime.UtcNow.AddSeconds(expireInSeconds);
            await _userRepository.SaveRefreshTokenAsync(userId, refreshToken, expiration);
        }

        public async Task SaveUserLoginAsync(UserLogin userLogin)
        {
            await _userRepository.SaveUserLoginAsync(userLogin);
        }

        public void UpdateSession(int userId, string sessionId)
        {
            _userRepository.UpdateSession(userId, sessionId);
        }

        public void UpdateTokenExpiration(int userId, int expireInSeconds)
        {
            var expiration = DateTime.UtcNow.AddSeconds(expireInSeconds);
            _userRepository.UpdateTokenExpiration(userId, expiration);
        }

        public async Task UpdateUserLoginAsync(UserLogin userLogin)
        {
            await _userRepository.UpdateUserLoginAsync(userLogin);
        }

        public bool ValidateToken(int userId, string sessionId)
        {
            return _userRepository.ValidateToken(userId, sessionId);   
        }
    }
}
