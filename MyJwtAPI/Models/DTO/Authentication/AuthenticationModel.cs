using System.ComponentModel.DataAnnotations;

namespace MyJwtAPI.Models.DTO.Authentication
{
    public class UserLoginResponse
    {
        public int Id { get; set; }
        public int RoleId { get; set; }
        public string? Message { get; set; }
        public string Code { get; set; } = string.Empty;
    }
    public class TokenDTO
    {
        public string? Token { get; set; }
        public string? RefreshToken { get; set; }
    }
    public class AuthOkResponse
    {
        public string? Token { get; set; }
        public string? RefreshToken { get; set; }
    }
    public class AuthResponse
    {
        public string? Token { get; set; }
        public string? RefreshToken { get; set; }
        public string? Sessiond { get; set; }
        //public string? Message { get; set; }
    }
    public class AuthErrorResponse
    {
        public string? Token { get; set; }
        public string? Message { get; set; }
    }
    public class LoginDTO
    {
        [Required]
        public string Email { get; set; } = null!;
        [Required]
        public string Password { get; set; } = null!;
    }
}
