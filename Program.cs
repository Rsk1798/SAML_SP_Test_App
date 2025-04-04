using ITfoxtec.Identity.Saml2;
using ITfoxtec.Identity.Saml2.MvcCore.Configuration;
using SAML_SP_Test_App.Models;
using System.Security.Cryptography.X509Certificates;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();


// Configure SAML settings from appsettings.json
var samlConfig = builder.Configuration.GetSection("SAML").Get<SamlConfig>();
if (samlConfig == null)
{
    throw new InvalidOperationException("SAML configuration is missing in appsettings.json");
}


// Load certificate
X509Certificate2 certificate = null;
if (!string.IsNullOrEmpty(samlConfig.CertificatePath))
{
    certificate = new X509Certificate2(
        samlConfig.CertificatePath,
        samlConfig.CertificatePassword,
        X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable
    );
}
else
{
    // For development, create a self-signed certificate
    // Note: In a real application, you should always use a proper certificate
    throw new InvalidOperationException("Certificate path is required. Please specify a valid certificate in the SAML configuration.");
}

// Configure SAML service
builder.Services.Configure<Saml2Configuration>(saml2Configuration =>
{
    saml2Configuration.Issuer = samlConfig.ServiceProviderEntityId;
    saml2Configuration.SingleSignOnDestination = new Uri(samlConfig.IdpSingleSignOnServiceUrl);
    saml2Configuration.SingleLogoutDestination = new Uri(samlConfig.IdpSingleLogoutServiceUrl);
    saml2Configuration.SigningCertificate = certificate;

    // Set the certificate for decrypting SAML assertions if encryption is used
    saml2Configuration.DecryptionCertificate = certificate;

    // Add the identity provider's certificate for signature validation
    if (!string.IsNullOrEmpty(samlConfig.IdpCertificateBase64))
    {
        saml2Configuration.SignatureValidationCertificates.Add(
            new X509Certificate2(Convert.FromBase64String(samlConfig.IdpCertificateBase64))
        );
    }

    // Configure allowed audience URIs
    saml2Configuration.AllowedAudienceUris.Add(samlConfig.ServiceProviderEntityId);
});

// Add SAML authentication services
builder.Services.AddSaml2();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}
else
{
    app.UseDeveloperExceptionPage();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
