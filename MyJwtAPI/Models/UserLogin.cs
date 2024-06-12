namespace MyJwtAPI.Models
{
    public class UserLogin
    {
        public int Id { get; set; }
        public int UserId { get; set; }
        public string? RefreshToken { get; set; }
        public DateTime? RefreshTokenExpiryTime { get; set; }
        public string? SessionId { get; set; }
        public DateTime? TokenExpiryTime { get; set; }
    }
}
