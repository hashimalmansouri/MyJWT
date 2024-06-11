using MyJWT.Models;
using MyJWT.Repository;

namespace MyJWT.Services
{
    public interface IUserService
    {
        Task<User> GetUserByRefreshTokenAsync(string refreshToken);
        Task<User> GetUserByIdAsync(int userId);
        void UpdateSession(int userId, string sessionId);
        void UpdateTokenExpiration(int userId, int expireInMinutes);
        User GetUserByEmail(string email);
        Task SaveRefreshTokenAsync(int userId, string refreshToken, int expireInMinutes);
        void InvalidateSession(int userId);
        bool ValidateToken(int userId, string sessionId);
    }
    public class UserService : IUserService
    {
        private readonly IUserRepository _userRepository;

        public UserService(IUserRepository userRepository)
        {
            _userRepository = userRepository;
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

        public void InvalidateSession(int userId)
        {
            _userRepository.InvalidateSession(userId);
        }

        public async Task SaveRefreshTokenAsync(int userId, string refreshToken, int expireInMinutes)
        {
            var expiration = DateTime.UtcNow.AddMinutes(expireInMinutes);
            await _userRepository.SaveRefreshTokenAsync(userId, refreshToken, expiration);
        }

        public void UpdateSession(int userId, string sessionId)
        {
            _userRepository.UpdateSession(userId, sessionId);
        }

        public void UpdateTokenExpiration(int userId, int expireInMinutes)
        {
            var expiration = DateTime.UtcNow.AddMinutes(expireInMinutes);
            _userRepository.UpdateTokenExpiration(userId, expiration);
        }

        public bool ValidateToken(int userId, string sessionId)
        {
            return _userRepository.ValidateToken(userId, sessionId);   
        }
    }
}
