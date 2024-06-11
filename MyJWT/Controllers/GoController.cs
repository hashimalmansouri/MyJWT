using Microsoft.AspNetCore.Mvc;

namespace MyJWT.Controllers
{
    public class GoController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
