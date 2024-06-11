namespace MyJWT.Models
{
    public class User
    {
        public int Id { get; set; }
        public string Username { get; set; } = null!;
        public string Email { get; set; } = null!;
        public string HashPassword { get; set; } = null!;
        public string SaltPassword { get; set; } = null!;
        public bool IsActive { get; set; }
        public int RoleId { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiryTime { get; set; }
        public string? SessionId { get; set; }
        public DateTime? TokenExpiryTime { get; set; }
    }
}
