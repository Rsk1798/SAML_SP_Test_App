using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore;
using ITfoxtec.Identity.Saml2.Schemas;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using SAML_SP_Test_App.Models;
using System.Security.Claims;

namespace SAML_SP_Test_App.Controllers
{
    [Route("Auth")]
    public class AuthController : Controller
    {

        private readonly Saml2Configuration _saml2Configuration;
        private readonly IConfiguration _configuration;

        public AuthController(IOptions<Saml2Configuration> saml2ConfigurationOptions, IConfiguration configuration)
        {
            _saml2Configuration = saml2ConfigurationOptions.Value;
            _configuration = configuration;
        }


        [HttpGet]
        [Route("Login")]
        public IActionResult Login()
        {
            var samlConfig = _configuration.GetSection("SAML").Get<SamlConfig>();

            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string>
            {
                { "returnUrl", Url.Action("Index", "Home") }
            });

            return binding.Bind(new Saml2AuthnRequest(_saml2Configuration)
            {
                ForceAuthn = samlConfig?.ForceAuthn ?? false,
                NameIdPolicy = new NameIdPolicy
                {
                    AllowCreate = true,
                    Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                }
            }).ToActionResult();
        }


        [HttpPost]
        [Route("AssertionConsumerService")]
        public async Task<IActionResult> AssertionConsumerService()
        {
            var binding = new Saml2PostBinding();
            var saml2AuthnResponse = new Saml2AuthnResponse(_saml2Configuration);

            binding.ReadSamlResponse(Request.ToGenericHttpRequest(), saml2AuthnResponse);
            if (saml2AuthnResponse.Status != Saml2StatusCodes.Success)
            {
                return BadRequest($"SAML Response status: {saml2AuthnResponse.Status}");
            }

            await saml2AuthnResponse.CreateSession(HttpContext, claimsTransform: (claimsPrincipal) => ClaimsTransform(claimsPrincipal));

            var relayStateQuery = binding.GetRelayStateQuery();
            var returnUrl = relayStateQuery.ContainsKey("returnUrl") ? relayStateQuery["returnUrl"] : Url.Action("Index", "Home");

            return Redirect(returnUrl);
        }



        [HttpGet]
        [Route("Logout")]
        public IActionResult Logout()
        {
            if (!User.Identity.IsAuthenticated)
            {
                return Redirect(Url.Action("Index", "Home"));
            }

            var binding = new Saml2PostBinding();
            var saml2LogoutRequest = new Saml2LogoutRequest(_saml2Configuration);

            return binding.Bind(saml2LogoutRequest).ToActionResult();
        }



        [HttpPost]
        [Route("LoggedOut")]
        public IActionResult LoggedOut()
        {
            var binding = new Saml2PostBinding();
            binding.Unbind(Request.ToGenericHttpRequest(), new Saml2LogoutResponse(_saml2Configuration));

            return Redirect(Url.Action("Index", "Home"));
        }



        [HttpGet]
        [Route("Metadata")]
        public IActionResult Metadata()
        {
            // Simple XML metadata generation
            var samlConfig = _configuration.GetSection("SAML").Get<SamlConfig>();

            // Create XML document
            var xmlDoc = new System.Xml.XmlDocument();

            // Create the EntityDescriptor element
            var entityDescriptor = xmlDoc.CreateElement("md", "EntityDescriptor", "urn:oasis:names:tc:SAML:2.0:metadata");
            entityDescriptor.SetAttribute("entityID", samlConfig.ServiceProviderEntityId);
            xmlDoc.AppendChild(entityDescriptor);

            // Create the SPSSODescriptor element
            var spSsoDescriptor = xmlDoc.CreateElement("md", "SPSSODescriptor", "urn:oasis:names:tc:SAML:2.0:metadata");
            spSsoDescriptor.SetAttribute("AuthnRequestsSigned", "true");
            spSsoDescriptor.SetAttribute("WantAssertionsSigned", "true");
            spSsoDescriptor.SetAttribute("protocolSupportEnumeration", "urn:oasis:names:tc:SAML:2.0:protocol");
            entityDescriptor.AppendChild(spSsoDescriptor);

            // Add certificate information
            if (_saml2Configuration.SigningCertificate != null)
            {
                var keyDescriptor = xmlDoc.CreateElement("md", "KeyDescriptor", "urn:oasis:names:tc:SAML:2.0:metadata");
                keyDescriptor.SetAttribute("use", "signing");
                spSsoDescriptor.AppendChild(keyDescriptor);

                var keyInfo = xmlDoc.CreateElement("ds", "KeyInfo", "http://www.w3.org/2000/09/xmldsig#");
                keyDescriptor.AppendChild(keyInfo);

                var x509Data = xmlDoc.CreateElement("ds", "X509Data", "http://www.w3.org/2000/09/xmldsig#");
                keyInfo.AppendChild(x509Data);

                var x509Certificate = xmlDoc.CreateElement("ds", "X509Certificate", "http://www.w3.org/2000/09/xmldsig#");
                x509Certificate.InnerText = Convert.ToBase64String(_saml2Configuration.SigningCertificate.GetRawCertData());
                x509Data.AppendChild(x509Certificate);
            }

            // Add NameIDFormat
            var nameIdFormat = xmlDoc.CreateElement("md", "NameIDFormat", "urn:oasis:names:tc:SAML:2.0:metadata");
            nameIdFormat.InnerText = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
            spSsoDescriptor.AppendChild(nameIdFormat);

            // Add AssertionConsumerService
            var assertionConsumerService = xmlDoc.CreateElement("md", "AssertionConsumerService", "urn:oasis:names:tc:SAML:2.0:metadata");
            assertionConsumerService.SetAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
            assertionConsumerService.SetAttribute("Location", $"{samlConfig.ServiceProviderRootUrl}/Auth/AssertionConsumerService");
            assertionConsumerService.SetAttribute("index", "0");
            assertionConsumerService.SetAttribute("isDefault", "true");
            spSsoDescriptor.AppendChild(assertionConsumerService);

            // Add SingleLogoutService
            var singleLogoutService = xmlDoc.CreateElement("md", "SingleLogoutService", "urn:oasis:names:tc:SAML:2.0:metadata");
            singleLogoutService.SetAttribute("Binding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST");
            singleLogoutService.SetAttribute("Location", $"{samlConfig.ServiceProviderRootUrl}/Auth/LoggedOut");
            spSsoDescriptor.AppendChild(singleLogoutService);

            // Return the XML
            return Content(xmlDoc.OuterXml, "application/xml");
        }



        [HttpGet]
        [Route("Claims")]
        public IActionResult Claims()
        {
            var claims = User.Claims.Select(c => new ClaimViewModel
            {
                Type = c.Type,
                Value = c.Value
            }).ToList();

            return View(claims);
        }



        private ClaimsPrincipal ClaimsTransform(ClaimsPrincipal claimsPrincipal)
        {
            if (!claimsPrincipal.Identity.IsAuthenticated)
            {
                return claimsPrincipal;
            }

            var claims = new List<Claim>();

            // Copy existing claims
            claims.AddRange(claimsPrincipal.Claims);

            // Add custom claims if needed
            // claims.Add(new Claim("CustomClaim", "CustomValue"));

            return new ClaimsPrincipal(new ClaimsIdentity(claims, claimsPrincipal.Identity.AuthenticationType));
        }


        //public IActionResult Index()
        //{
        //    return View();
        //}



    }
}
