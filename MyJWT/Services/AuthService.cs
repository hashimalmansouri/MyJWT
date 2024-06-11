using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using MyJWT.Helpers;
using MyJWT.Models;
using MyJWT.Models.DTO.Authentication;
using MyJWT.Repository;
using MyJWT.Security;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace MyJWT.Services
{
    public interface IAuthService
    {
        UserLoginResponse Login(string email, string password);
        string Hash512(string password, string salt);
        public AuthResponse GenerateToken(int userId, int expireInMinutes);
        public ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
        public Task<(string Token, string RefreshToken)> RefreshTokenAsync(string token, string refreshToken);

        void InvalidateSession(int userId);
        Task SaveRefreshTokenAsync(int userId, string refreshToken, int expireInMinutes);
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
            IOptions<JwtSettings> jwtSettings)
        {
            _encryption = encryption;
            _visitorHelper = visitorHelper;
            _userService = userService;
            _jwtSettings = jwtSettings.Value;
        }

        public AuthResponse GenerateToken(int userId, int expireInMinutes)
        {
            var response = new AuthResponse();
            var sessionId = Guid.NewGuid().ToString();
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.Secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expiration = DateTime.UtcNow.AddMinutes(expireInMinutes);
            var encryptedUserId = _encryption.Encrypt(userId.ToString());
            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, encryptedUserId),
                //new Claim(JwtRegisteredClaimNames.Sub, userId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim("SessionId", sessionId),
                //new Claim (ClaimTypes.Role, "1"),
            };

            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                claims: claims,
                expires: expiration,
                signingCredentials: creds
            );

            _userService.UpdateSession(userId, sessionId);
            _userService.UpdateTokenExpiration(userId, _jwtSettings.TokenExpiryInMinutes);

            var refreshToken = Guid.NewGuid().ToString();

            response = new AuthResponse()
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                RefreshToken = refreshToken
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
                if (user is null)
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
            catch (Exception)
            {
                response.Code = "USER_EXCEPTION";
            }   
            return response;
        }

        public string Hash512(string password, string salt)
        {
            byte[] convertedToBytes = Encoding.UTF8.GetBytes(password + salt);
            HashAlgorithm hashType = new SHA512Managed();
            byte[] hashBytes = hashType.ComputeHash(convertedToBytes);
            string hashedResult = Convert.ToBase64String(hashBytes);
            return hashedResult;
        }

        public async Task<(string Token, string RefreshToken)> RefreshTokenAsync(string token, string refreshToken)
        {
            var user = await _userService.GetUserByIdAsync(_visitorHelper.UserId);
            var now = DateTime.UtcNow;
            if (user != null && user.RefreshTokenExpiryTime > now)
            {
                var principal = GetPrincipalFromExpiredToken(token);
                //var userId = principal.Claims.FirstOrDefault(c => c.Type == JwtRegisteredClaimNames.Sub)?.Value;
                var encryptedUserId = principal?.Claims.First(claim => claim.Type == ClaimTypes.NameIdentifier)?.Value;
                int userId = int.Parse(_encryption.Decrypt(encryptedUserId));
                var authResponse = GenerateToken(userId, _jwtSettings.TokenExpiryInMinutes);
                await _userService.SaveRefreshTokenAsync(userId, authResponse.RefreshToken, _jwtSettings.RefreshTokenExpiryInMinutes); // Save the new refresh token
                return (authResponse.Token, authResponse.RefreshToken);
            }
            return (null, null);
        }

        public void InvalidateSession(int userId)
        {
            _userService.InvalidateSession(userId);
        }

        public async Task SaveRefreshTokenAsync(int userId, string refreshToken, int expireInMinutes)
        {
            await _userService.SaveRefreshTokenAsync(userId, refreshToken, expireInMinutes);
        }

        public bool ValidateToken(int userId, string sessionId)
        {
            return _userService.ValidateToken(userId, sessionId);
        }
    }

}
