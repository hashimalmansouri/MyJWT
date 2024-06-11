namespace MyJWT.Models.DTO.Authentication
{
    public class UserLoginResponse
    {
        public int Id { get; set; }
        public int RoleId { get; set; }
        public string? Message { get; set; }
        public string Code { get; set; } = string.Empty;
    }

    public class AuthResponse
    {
        public string? Token { get; set; }
        public string? RefreshToken { get; set; }
        public string? Sessiond { get; set; }
        public string? Message { get; set; }
    }
    public class AuthErrorResponse
    {
        public string? Token { get; set; }
        public string? Message { get; set; }
    }
}
