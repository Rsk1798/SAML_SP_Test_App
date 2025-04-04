namespace SAML_SP_Test_App.Models
{
    /// <summary>
    /// View model for displaying claims
    /// </summary>
    public class ClaimViewModel
    {

        /// <summary>
        /// The type of the claim
        /// </summary>
        public string Type { get; set; } = string.Empty;

        /// <summary>
        /// The value of the claim
        /// </summary>
        public string Value { get; set; } = string.Empty;

    }
}
