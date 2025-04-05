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




            // Optionally, you can check the relay state or other attributes to determine the next action
            // Handle different policies based on the relay state or other attributes
            // You can detect which policy was used by examining the Issuer or other attributes
            // var issuer = saml2AuthnResponse.Issuer;
            // if (issuer.Contains("profile_edit"))
            // {
            //     // Handle profile edit response
            //     return RedirectToAction("ProfileUpdated", "Home");
            // }


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



        //[HttpGet]
        //public IActionResult LoginWithAzureAD()
        //{

        //    // Use Azure AD configuration
        //    return InitiateSamlRequest("AzureAD");

        //}



        //[HttpGet]
        //public IActionResult LoginWithOkta()
        //{

        //    // Use Okta configuration
        //    return InitiateSamlRequest("Okta");

        //}




        //private IActionResult InitiateSamlRequest(string idpProvider)
        //{
        //    var samlConfig = _configuration.GetSection("SAML").Get<SamlConfig>();
        //    var binding = new Saml2RedirectBinding();
        //    binding.SetRelayStateQuery(new Dictionary<string, string>
        //    {
        //        {"returnUrl", Url.Action("Index", "Home") },
        //        {"idpProvider", idpProvider } // Pass the provider as a query parameter
        //    });

        //    // Select the appropriate configuration based on the provider
        //    var policyUrl = idpProvider switch
        //    {
        //        "AzureAD" => samlConfig.SignUpSignInPolicyUrl, // Use the sign-up/sign-in policy URL for Azure AD
        //        // AzureADSignInPolicyUrl,

        //        // "Okta" => samlConfig.OktaSignInPolicyUrl, // Use the sign-in policy URL for Okta
        //        //"Okta" => samlConfig.OktaSignInPolicyUrl,
        //        //_ => throw new ArgumentException("Invalid provider")
        //    };

        //    var policyConfig = CreatePolicySpecificConfiguration(policyUrl);

        //    // Create a new Saml2AuthnRequest with the selected policy URL
        //    // return binding.Bind(new Saml2AuthnRequest(CreatePolicySpecificConfiguration(policyUrl))
        //    return binding.Bind(new Saml2AuthnRequest(policyConfig)
        //    {
        //        ForceAuthn = false, // Set to true if you want to force authentication
        //        // true,
        //        NameIdPolicy = new NameIdPolicy
        //        {
        //            AllowCreate = true,
        //            Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        //            // "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        //        }
        //    }).ToActionResult();
        //}



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


            // Check for policy-specific claims
            // Example: Check if the user is authenticated with a specific policy
            var issuerClaim = claimsPrincipal.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier");
            if (issuerClaim != null)
            {
                // Add a custom claim based on the issuer
                // You can add policy-specific logic here
                // For example, add a claim indicating which policy was used

                var issuer = claimsPrincipal.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/issuer")?.Value??"";
                // claims.Add(new Claim("Policy", "SignUpSignIn"));
                //claims.Add(new Claim("Issuer", issuerClaim.Value));

                if (issuer.Contains("profile_edit"))
                {
                    claims.Add(new Claim("PolicyUsed", "ProfileEdit"));
                }
                else if (issuer.Contains("password_reset"))
                {
                    claims.Add(new Claim("PolicyUsed", "PasswordReset"));
                }
                else if (issuer.Contains("signup_signin"))
                {
                    claims.Add(new Claim("PolicyUsed", "SignUpSignIn"));
                }
                else 
                {
                    claims.Add(new Claim("PolicyUsed", "SignUpSignIn"));
                }
            }

            return new ClaimsPrincipal(new ClaimsIdentity(claims, claimsPrincipal.Identity.AuthenticationType));
        }


        private Saml2Configuration CreatePolicySpecificConfiguration(string policyUrl)
        {
            // Create a new configuration based on the existing one
            var policyConfig = new Saml2Configuration
            {
                Issuer = _saml2Configuration.Issuer,
                SigningCertificate = _saml2Configuration.SigningCertificate,
                DecryptionCertificate = _saml2Configuration.DecryptionCertificate,
                SignatureAlgorithm = _saml2Configuration.SignatureAlgorithm,
                // AllowedAudienceUris = _saml2Configuration.AllowedAudienceUris
            };

            // Add allowed audience URIs
            foreach (var uri in _saml2Configuration.AllowedAudienceUris)
            {
                policyConfig.AllowedAudienceUris.Add(uri);
            }


            // Set the policy-specific URL
            policyConfig.SingleSignOnDestination = new Uri(policyUrl);
            return policyConfig;
        }


        [HttpGet]
        public IActionResult SignUp()
        {
            var samlConfig = _configuration.GetSection("SAML").Get<SamlConfig>();
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string>
            {
                {"returnUrl", Url.Action("Index", "Home") }
            });


            // Use the sign-up/sign-in policy URL
            var policyConfig = CreatePolicySpecificConfiguration(samlConfig.SignUpSignInPolicyUrl);
            return binding.Bind(new Saml2AuthnRequest(policyConfig)
            {
                // Use the sign-up/sign-in policy URL
                //SingleSignOnDestination = new Uri("https://your-b2c-tenant.b2clogin.com/your-b2c-tenant.onmicrosoft.com/B2C_1A_SAML_sign_up_sign_in/samlp/sso/login"),
                //SigningCertificate = _saml2Configuration.SigningCertificate,
                // Other properties from _saml2Configuration

                ForceAuthn = true,  // Force authentication to ensure the sign-up experience
                //samlConfig?.ForceAuthn ?? false,
                
                NameIdPolicy = new NameIdPolicy
                {
                    AllowCreate = true,  // Allow creating new accounts
                    Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                }
            }).ToActionResult();
        }


        [HttpGet]
        public IActionResult ProfileEdit()
        {

            var samlConfig = _configuration.GetSection("SAML").Get<SamlConfig>();


            // Ensure the user is authenticated before profile editing
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }


            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string>
            {
                {"returnUrl", Url.Action("Index", "Home") }
            });


            // Override the default endpoints with profile edit policy endpoints
            // Use the profile edit policy URL

            var profileEditConfig = CreatePolicySpecificConfiguration(samlConfig.ProfileEditSsoUrl);


            //var profileEditConfig = new Saml2Configuration
            //{
            //    Issuer = _saml2Configuration.Issuer,
            //    SingleSignOnDestination = new Uri("https://your-b2c-tenant.b2clogin.com/your-b2c-tenant.onmicrosoft.com/B2C_1A_SAML_profile_edit/samlp/sso/login"),
            //    SigningCertificate = _saml2Configuration.SigningCertificate,

            //    // Other properties from _saml2Configuration
            //};

            return binding.Bind(new Saml2AuthnRequest(profileEditConfig)
            {
                ForceAuthn = true, // Force authentication for profile edit
                NameIdPolicy = new NameIdPolicy
                {
                    AllowCreate = false,  // Do not allow creating new accounts during profile edit
                    //true,
                    Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                    // "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                }
            }).ToActionResult();

        }

        // Similar methods for PasswordReset and other policies
        [HttpGet]
        public IActionResult PasswordReset()
        {

            var samlConfig = _configuration.GetSection("SAML").Get<SamlConfig>();
            // Ensure the user is authenticated before password reset
            if (!User.Identity.IsAuthenticated)
            {
                return RedirectToAction("Login");
            }
            var binding = new Saml2RedirectBinding();
            binding.SetRelayStateQuery(new Dictionary<string, string>
            {
                {"returnUrl", Url.Action("Index", "Home") }
            });

            // Override the default endpoints with password reset policy endpoints
            // Use the password reset policy URL
            var passwordResetConfig = CreatePolicySpecificConfiguration(samlConfig.PasswordResetSsoUrl);
            return binding.Bind(new Saml2AuthnRequest(passwordResetConfig)
            {
                ForceAuthn = true, // Force authentication for password reset
                NameIdPolicy = new NameIdPolicy
                {
                    AllowCreate = false,  // Do not allow creating new accounts during password reset
                    //true,
                    Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                    // "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
                }
            }).ToActionResult();

        }



        //public IActionResult Index()
        //{
        //    return View();
        //}



    }
}
