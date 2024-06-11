﻿namespace MyJWT.Models
{
    public class JwtSettings
    {
        public string Secret { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public int TokenExpiryInMinutes { get; set; }
        public int RefreshTokenExpiryInMinutes { get; set; }
    }

}