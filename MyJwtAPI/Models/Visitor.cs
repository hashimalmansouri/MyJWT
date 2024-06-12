namespace MyJwtAPI.Models
{
    public class Visitor
    {
        public bool Init { get; set; }
        public string? IpAddress { get; set; }
        public string? RefererURL { get; set; }
        public string? Lang { get; set; }
        public User User { get; set; } = new User();
    }
}
