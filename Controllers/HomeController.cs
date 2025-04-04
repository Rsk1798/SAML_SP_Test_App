using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using SAML_SP_Test_App.Models;

namespace SAML_SP_Test_App.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;

        private readonly IConfiguration _configuration;

        public HomeController(ILogger<HomeController> logger, IConfiguration configuration)
        {
            _logger = logger;
            _configuration = configuration;
        }

        public IActionResult Index()
        {
            // Get SAML configuration for display
            var samlConfig = _configuration.GetSection("SAML").Get<SamlConfig>();

            // Pass the configuration to the view
            ViewBag.ServiceProviderEntityId = samlConfig?.ServiceProviderEntityId;
            ViewBag.IdpEntityId = samlConfig?.IdpEntityId;

            return View();
        }

        public IActionResult Privacy()
        {
            return View();
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}
