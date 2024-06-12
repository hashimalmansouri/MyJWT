using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MyJwtAPI.Helpers;
using MyJwtAPI.Models;
using MyJwtAPI.Models.DTO.Authentication;
using MyJwtAPI.Repository;
using MyJwtAPI.Security;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace MyJwtAPI.Services
{
    public interface IAuthService
    {
        UserLoginResponse Login(string email, string password);
        string Hash512(string password, string salt);
        Task<AuthResponse> GenerateToken(int userId, int expireInSeconds);
        ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
        Task<(string Token, string RefreshToken)> RefreshTokenAsync(string token, string refreshToken);
        void InvalidateSession(int userId, int userLoginId);
        bool ValidateToken(int userId, string sessionId);
    }
    public class AuthService : IAuthService
    {
        private readonly IUserService _userService;
        private readonly IEncryption _encryption;
        private readonly IVisitorHelper _visitorHelper;
        private readonly JwtSettings _jwtSettings;

        public AuthService(
            IEncryption encryption,
            IVisitorHelper visitorHelper,
            IUserService userService,
            IUserRepository userRepository,
            IOptions<JwtSettings> jwtSettings)
        {
            _encryption = encryption;
            _visitorHelper = visitorHelper;
            _userService = userService;
            _jwtSettings = jwtSettings.Value;
        }

        public async Task<AuthResponse> GenerateToken(int userId, int expireInSeconds)
        {
            var response = new AuthResponse();
            var sessionId = Guid.NewGuid().ToString();
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expiration = DateTime.UtcNow.AddSeconds(expireInSeconds);
            var encryptedUserId = _encryption.Encrypt(userId.ToString());
            var claims = new[]
            {
            new Claim(ClaimTypes.NameIdentifier, encryptedUserId),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("SessionId", sessionId),
        };

            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: expiration,
                signingCredentials: creds
            );

            var refreshToken = Guid.NewGuid().ToString();
            

            response = new AuthResponse()
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                RefreshToken = refreshToken,
                Sessiond = sessionId 
            };
            return response;
        }

        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false,
                ValidateIssuerSigningKey = true,
                ValidIssuer = _jwtSettings.Issuer,
                ValidAudience = _jwtSettings.Audience,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret))
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;

            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
                throw new SecurityTokenException("Invalid token");

            return principal;
        }

        public UserLoginResponse Login(string email, string password)
        {
            var response = new UserLoginResponse();
            try
            {
                var user = _userService.GetUserByEmail(email);
                if (user == null)
                {
                    response.Code = "USER_NOT_FOUND";
                    return response;
                }
                var passwordHash = Hash512(password, user.SaltPassword);
                if (!passwordHash.Equals(user.HashPassword, StringComparison.CurrentCultureIgnoreCase))
                {
                    response.Code = "USER_INVALID_CREDENTIALS";
                    return response;
                }
                if (!user.IsActive)
                {
                    response.Code = "USER_INACTIVE";
                    return response;
                }
                response.Id = user.Id;
                response.RoleId = user.RoleId;
            }
            catch (Exception ex)
            {
                // Log the exception
                response.Code = "USER_EXCEPTION";
            }
            return response;
        }

        public string Hash512(string password, string salt)
        {
            byte[] convertedToBytes = Encoding.UTF8.GetBytes(password + salt);
            using var hashType = new SHA512Managed();
            byte[] hashBytes = hashType.ComputeHash(convertedToBytes);
            string hashedResult = Convert.ToBase64String(hashBytes);
            return hashedResult;
        }

        public async Task<(string Token, string RefreshToken)> RefreshTokenAsync(string token, string refreshToken)
        {
            var userLogin = await _userService.GetUserLoginByRefreshTokenAsync(refreshToken);
            if (userLogin != null && userLogin.RefreshTokenExpiryTime > DateTime.UtcNow)
            {
                var principal = GetPrincipalFromExpiredToken(token);
                var encryptedUserId = principal?.Claims.First(claim => claim.Type == ClaimTypes.NameIdentifier)?.Value;
                int userId = int.Parse(_encryption.Decrypt(encryptedUserId));
                var authResponse = await GenerateToken(userId, _jwtSettings.TokenExpiryInSeconds);
                userLogin.SessionId = authResponse.Sessiond;
                userLogin.TokenExpiryTime = DateTime.UtcNow.AddSeconds(_jwtSettings.TokenExpiryInSeconds);
                userLogin.RefreshToken = authResponse.RefreshToken;
                userLogin.RefreshTokenExpiryTime = DateTime.UtcNow.AddSeconds(_jwtSettings.RefreshTokenExpiryInSeconds);
                await _userService.UpdateUserLoginAsync(userLogin); // Update the refresh token
                return (authResponse.Token, authResponse.RefreshToken);
            }
            return (null, null);
        }

        public void InvalidateSession(int userId, int userLoginId)
        {
            // Assuming you have a method in IUserService to invalidate user sessions
            _userService.InvalidateSession(userId, userLoginId);
        }

        public bool ValidateToken(int userId, string sessionId)
        {
            // Assuming you have a method in IUserService to validate tokens
            return _userService.ValidateToken(userId, sessionId);
        }
    }

}
