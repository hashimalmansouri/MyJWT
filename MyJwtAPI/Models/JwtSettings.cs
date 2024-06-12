namespace MyJwtAPI.Models
{
    public class JwtSettings
    {
        public string Secret { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public int TokenExpiryInSeconds { get; set; }
        public int RefreshTokenExpiryInSeconds { get; set; }
        public bool AllowMultipleDevicesToLogin { get; set; }
    }

}
