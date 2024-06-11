using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using MyJWT.Helpers;
using MyJWT.Models;
using MyJWT.Services;

namespace MyJWT.Controllers
{
    [AllowAnonymous]
    public class AuthController : Controller
    {
        private readonly IAuthService _authService;
        private readonly IVisitorHelper _visitorHelper;
        private readonly JwtSettings _jwtSettings;
        public AuthController(IAuthService authService,
            IVisitorHelper visitorHelper,
            IOptions<JwtSettings> jwtSettings)
        {
            _authService = authService;
            _visitorHelper = visitorHelper;
            _jwtSettings = jwtSettings.Value;
        }

        [HttpGet]
        public IActionResult Login(string? returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(string email, string password, string? returnUrl)
        {
            var user = _authService.Login(email, password);
            if (user.Code == "USER_NOT_FOUND") 
            {
                return RedirectToAction(nameof(NotAuthorized), new { msg = "User is not found" });
                //return Unauthorized();
            }
            else if (user.Code == "USER_INVALID_CREDENTIALS")
            {
                return RedirectToAction(nameof(NotAuthorized));
                //return Unauthorized();
            }
            else if (user.Code == "USER_INACTIVE")
            {
                return RedirectToAction(nameof(NotAuthorized));
                //return Unauthorized();
            }
            var authResponse = _authService.GenerateToken(user.Id, _jwtSettings.TokenExpiryInMinutes);
            if (string.IsNullOrEmpty(authResponse.Token) || 
                string.IsNullOrEmpty(authResponse.RefreshToken))
            {
                return RedirectToAction(nameof(NotAuthorized));
                //return Unauthorized();
            }
            await _authService.SaveRefreshTokenAsync(user.Id, authResponse.RefreshToken, _jwtSettings.RefreshTokenExpiryInMinutes);
            HttpContext.Response.Cookies.Append("jwtToken", authResponse.Token, new CookieOptions { HttpOnly = true, Secure = true });
            HttpContext.Response.Cookies.Append("refreshToken", authResponse.RefreshToken, new CookieOptions { HttpOnly = true, Secure = true });
            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction("Index", "Home");
            }
        }

        public IActionResult NotAuthorized()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize]
        public IActionResult Logout()
        {
            try
            {
                HttpContext.Response.Cookies.Delete("jwtToken");
                HttpContext.Response.Cookies.Delete("refreshToken");
                _authService.InvalidateSession(_visitorHelper.UserId);
                return RedirectToAction(nameof(Login));
            }
            catch (Exception)
            {

                return BadRequest();
            }
        }

    }
}
