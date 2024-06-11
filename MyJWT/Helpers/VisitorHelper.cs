using MyJWT.Models;
using System.Net;

namespace MyJWT.Helpers
{
    public interface IVisitorHelper
    {
        void SetVisitor();
        Visitor Visitor { get; set; }
        int UserId { get; set; }
        User User { get; set; }
    }
    public class VisitorHelper : IVisitorHelper
    {
        private readonly IHttpContextAccessor _accessor;

        public VisitorHelper(IHttpContextAccessor accessor)
        {
            _accessor = accessor;
            if (Visitor == null)
                SetVisitor();
            Visitor = new Visitor();
            User = new User();
        }
        public Visitor Visitor { get; set; }
        public int UserId { get; set; }
        public User User { get; set; }

        public void SetVisitor()
        {
            SetIpAddress();
            Visitor visitor = new();
            var Context = _accessor.HttpContext;
            visitor.IpAddress = _accessor.HttpContext.Connection.RemoteIpAddress.ToString();
            visitor.RefererURL = string.Format("{0}://{1}{2}{3}{4}", Context.Request.Scheme, Context.Request.Host, Context.Request.PathBase, Context.Request.Path, Context.Request.QueryString);
            //visitor.UserAgent = Context.Request.Headers?.FirstOrDefault(s => s.Key.ToLower() == "user-agent").Value;
            visitor.User = User;
            visitor.Init = true;
            Visitor = visitor;
        }
        public void SetIpAddress()
        {
            var headers = _accessor.HttpContext.Request.Headers;
            if (headers.ContainsKey("X-Forwarded-For"))
            {
                _accessor.HttpContext.Connection.RemoteIpAddress = IPAddress.Parse(headers["X-Forwarded-For"].ToString().Split(',', StringSplitOptions.RemoveEmptyEntries)[0]);
            }
        }

    }
}
