namespace SAML_SP_Test_App.Models
{
    /// <summary>
    /// Configuration model for SAML settings
    /// </summary>
    
    public class SamlConfig
    {

        /// <summary>
        /// The entity ID of the service provider (this application)
        /// </summary>
        public string ServiceProviderEntityId { get; set; } = string.Empty;

        /// <summary>
        /// The root URL of the service provider (this application)
        /// </summary>
        public string ServiceProviderRootUrl { get; set; } = string.Empty;

        /// <summary>
        /// The path to the service provider's certificate file
        /// </summary>
        public string CertificatePath { get; set; } = string.Empty;

        /// <summary>
        /// The password for the service provider's certificate
        /// </summary>
        public string CertificatePassword { get; set; } = string.Empty;

        /// <summary>
        /// The entity ID of the identity provider
        /// </summary>
        public string IdpEntityId { get; set; } = string.Empty;

        /// <summary>
        /// The URL of the identity provider's single sign-on service
        /// </summary>
        public string IdpSingleSignOnServiceUrl { get; set; } = string.Empty;

        /// <summary>
        /// The URL of the identity provider's single logout service
        /// </summary>
        public string IdpSingleLogoutServiceUrl { get; set; } = string.Empty;

        /// <summary>
        /// The base64-encoded certificate of the identity provider
        /// </summary>
        public string IdpCertificateBase64 { get; set; } = string.Empty;

        /// <summary>
        /// Whether to force authentication on each request
        /// </summary>
        public bool ForceAuthn { get; set; } = false;

        /// <summary>
        /// The comparison method for the requested authentication context
        /// </summary>
        public string AuthnContextComparisonType { get; set; } = "Exact";

        /// <summary>
        /// The list of authentication contexts to request
        /// </summary>
        public List<string> AuthnContexts { get; set; } = new List<string>();

    }
}
