using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using MyJwtAPI.Helpers;
using MyJwtAPI.Models;
using MyJwtAPI.Models.DTO.Authentication;
using MyJwtAPI.Services;

namespace MyJwtAPI.Controllers
{
    [AllowAnonymous]
    [ApiController]
    [Route("[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly IUserService _userService;
        private readonly IVisitorHelper _visitorHelper;
        private readonly JwtSettings _jwtSettings;
        public AuthController(IAuthService authService,
            IVisitorHelper visitorHelper,
            IOptions<JwtSettings> jwtSettings,
            IUserService userService)
        {
            _authService = authService;
            _visitorHelper = visitorHelper;
            _jwtSettings = jwtSettings.Value;
            _userService = userService;
        }

        [HttpPost("login")]
        //[ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginDTO login)
        {
            var user = _authService.Login(login.Email, login.Password);
            if (user.Code == "USER_NOT_FOUND") 
            {
                return Unauthorized(user.Code);
            }
            else if (user.Code == "USER_INVALID_CREDENTIALS")
            {
                return Unauthorized(user.Code);
            }
            else if (user.Code == "USER_INACTIVE")
            {
                return Unauthorized(user.Code);
            }
            var authResponse = await _authService.GenerateToken(user.Id, _jwtSettings.TokenExpiryInSeconds);
            if (string.IsNullOrEmpty(authResponse.Token) || 
                string.IsNullOrEmpty(authResponse.RefreshToken))
            {
                return Unauthorized(user.Code);
            }

            var userLogin = new UserLogin
            {
                UserId = user.Id,
                SessionId = authResponse.Sessiond,
                RefreshToken = authResponse.RefreshToken,
                RefreshTokenExpiryTime = DateTime.UtcNow.AddSeconds(_jwtSettings.RefreshTokenExpiryInSeconds),
                TokenExpiryTime = DateTime.UtcNow.AddSeconds(_jwtSettings.TokenExpiryInSeconds)
            };

            if (!_jwtSettings.AllowMultipleDevicesToLogin)
            {
                await _userService.DeleteUserLoginsAsync(user.Id);
            }
            await _userService.SaveUserLoginAsync(userLogin);

            return Ok(new AuthOkResponse { Token = authResponse.Token, RefreshToken = authResponse.RefreshToken });
        }

        [HttpPost("refresh")]
        public async Task<IActionResult> RefreshToken(TokenDTO tokenDTO)
        {
            if (tokenDTO is null)
                return BadRequest("INVALID_REQUEST");
            var newTokenResult = await _authService.RefreshTokenAsync(tokenDTO.Token, tokenDTO.RefreshToken);
            if (newTokenResult.Token is not null && newTokenResult.RefreshToken is not null)
            {
                return Ok(new AuthOkResponse()
                {
                    Token = newTokenResult.Token,
                    RefreshToken = newTokenResult.RefreshToken
                });
            }
            return BadRequest("INVALID_REQUEST");
        }
        [HttpPost("revoke"), Authorize]
        public IActionResult Revoke()
        {
            try
            {
                _authService.InvalidateSession(_visitorHelper.UserId, _visitorHelper.UserLoginId);
                return NoContent();
            }
            catch (Exception)
            {

                return BadRequest("INVALID_REQUEST");
            }
        }

    }
}
