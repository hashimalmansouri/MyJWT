﻿using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.IdentityModel.Tokens;
using MyJWT.Helpers;
using MyJWT.Security;
using MyJWT.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace MyJWT.Middleware
{
    public class JwtTokenMiddleware
    {
        private readonly RequestDelegate _next;

        public JwtTokenMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context, IAuthService authService, IUserService userService)
        {
            if (IsTokenInHeader(context))
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return;
            }
            string? token = GetToken(context);
            if (token is not null)
            {
                var jwtTokenHandler = new JwtSecurityTokenHandler();
                JwtSecurityToken? jwtToken = null;

                try
                {
                    jwtToken = jwtTokenHandler.ReadJwtToken(token);
                    var exp = jwtToken.ValidTo;
                    var now = DateTime.UtcNow;
                    var _encryption = context.RequestServices.GetRequiredService<IEncryption>();
                    int userId = GetUserId(context, jwtToken);
                    var _userService = context.RequestServices.GetRequiredService<IUserService>();
                    var sessionId = jwtToken?.Claims.First(claim => claim.Type == "SessionId")?.Value;
                    SetVisitor(context, userId, sessionId, _userService);
                    if (IsEndpointAllowAnonymousOrNoAuthorization(context))
                    {
                        await _next(context);
                        return;
                    }
                    if (exp < now)
                    {
                        throw new SecurityTokenExpiredException();
                    }
                    if (userId == 0 || sessionId == null || !authService.ValidateToken(userId, sessionId))
                    {
                        ClearCookiesAndSignOut(context);
                    }
                }
                catch (Exception)
                {
                    var refreshToken = context.Request.Cookies["refreshToken"];
                    if (refreshToken is not null)
                    {
                        var userLogin = await userService.GetUserLoginByRefreshTokenAsync(refreshToken);
                        var now = DateTime.UtcNow;
                        if (userLogin is not null && userLogin.RefreshTokenExpiryTime > now)
                        {
                            var newTokenResult = await authService.RefreshTokenAsync(token, refreshToken);
                            if (newTokenResult.Token is not null && newTokenResult.RefreshToken is not null)
                            {
                                context.Response.Cookies.Append("jwtToken", newTokenResult.Token, new CookieOptions { HttpOnly = true, Secure = true });
                                context.Response.Cookies.Append("refreshToken", newTokenResult.RefreshToken, new CookieOptions { HttpOnly = true, Secure = true });
                                context.Request.Headers["Authorization"] = "Bearer " + newTokenResult.Token;
                            }
                            else // Invalid refresh token
                            {
                                ClearCookiesAndSignOut(context);
                            }
                        }
                        else // Invalid refresh token
                        {
                            ClearCookiesAndSignOut(context);
                        }
                    }
                    else // Refresh token not found
                    {
                        ClearCookiesAndSignOut(context);
                    }
                }
            }

            await _next(context);
        }

        private void ClearCookiesAndSignOut(HttpContext context)
        {
            //context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            context.Response.Cookies.Delete("jwtToken");
            context.Response.Cookies.Delete("refreshToken");
            // Reset the user context
            context.User = new ClaimsPrincipal(new ClaimsIdentity());
            // Check if the endpoint is allowed to be accessed anonymously or without authorization
            if (!IsEndpointAllowAnonymousOrNoAuthorization(context))
            {
                context.Response.Redirect("/Auth/Login");
            }
        }

        private string? GetToken(HttpContext context)
        {
            //string? token = context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last();
            //if (token is null)
            //{
            //    token = context.Request.Cookies["jwtToken"];
            //}
            string? token = context.Request.Cookies["jwtToken"];
            return token;
        }

        private bool IsTokenInHeader(HttpContext context)
        {
            return !string.IsNullOrEmpty(context.Request.Headers["Authorization"].FirstOrDefault()?.Split(" ").Last());
        }

        private void SetVisitor(HttpContext context, int userId, string sessionId, IUserService userService)
        {
            var user = userService.GetUserByIdAsync(userId).Result;
            var userLogin = userService.GetUserLoginBySessionIdAsync(sessionId).Result;
            var visitor = context.RequestServices.GetRequiredService<IVisitorHelper>();
            visitor.UserLoginId = userLogin.Id;
            visitor.UserId = user.Id;
            visitor.User = user;
            visitor.SetVisitor();
        }

        private int GetUserId(HttpContext context, JwtSecurityToken jwtToken)
        {
            var encryptedUserId = jwtToken.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value;
            return int.Parse(context.RequestServices.GetRequiredService<IEncryption>().Decrypt(encryptedUserId));
        }

        private bool IsEndpointAllowAnonymousOrNoAuthorization(HttpContext context)
        {
            var endpoint = context.GetEndpoint();
            if (endpoint != null)
            {
                var controllerActionDescriptor = endpoint.Metadata.GetMetadata<ControllerActionDescriptor>();
                if (controllerActionDescriptor != null)
                {
                    var actionAttributes = controllerActionDescriptor.MethodInfo.GetCustomAttributes(inherit: true);
                    var controllerAttributes = controllerActionDescriptor.ControllerTypeInfo.GetCustomAttributes(inherit: true);

                    // Check if `[AllowAnonymous]` is present at either level
                    if (actionAttributes.Any(attr => attr is IAllowAnonymous) ||
                        controllerAttributes.Any(attr => attr is IAllowAnonymous))
                    {
                        return true;
                    }

                    // Check if `[Authorize]` is absent at both levels
                    if (!actionAttributes.Any(attr => attr is AuthorizeAttribute) &&
                        !controllerAttributes.Any(attr => attr is AuthorizeAttribute))
                    {
                        return true;
                    }
                }
            }
            return false;
        }

    }

    public static class JwtTokenMiddlewareExtensions
    {
        public static IApplicationBuilder UseJwtTokenMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<JwtTokenMiddleware>();
        }
    }

}
