# SAML Test Application Certificates

This directory is used to store certificates for SAML authentication. The application expects a certificate file named `samlcert.pfx` in this directory.

## Generating a Self-Signed Certificate for Testing

For testing purposes, you can generate a self-signed certificate using one of the following methods:

### Using PowerShell (Windows)

```powershell
$cert = New-SelfSignedCertificate -Subject "CN=SamlTestApp" -CertStoreLocation "cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256

$pwd = ConvertTo-SecureString -String "password" -Force -AsPlainText

$certPath = "cert:\CurrentUser\My\$($cert.Thumbprint)"
Export-PfxCertificate -Cert $certPath -FilePath "samlcert.pfx" -Password $pwd
```

### Using OpenSSL (Cross-Platform)

1. Generate a private key:
```bash
openssl genrsa -out samlcert.key 2048
```

2. Generate a certificate signing request (CSR):
```bash
openssl req -new -key samlcert.key -out samlcert.csr -subj "/CN=SamlTestApp"
```

3. Generate a self-signed certificate:
```bash
openssl x509 -req -days 365 -in samlcert.csr -signkey samlcert.key -out samlcert.crt
```

4. Create a PFX file:
```bash
openssl pkcs12 -export -out samlcert.pfx -inkey samlcert.key -in samlcert.crt -passout pass:password
```

## Certificate Configuration

After generating the certificate, update the `appsettings.json` file with the correct certificate path and password:

```json
"SAML": {
  "CertificatePath": "Certificates/samlcert.pfx",
  "CertificatePassword": "password"
}
```

## Security Considerations

- For production environments, use a certificate issued by a trusted certificate authority (CA).
- Store the certificate password securely, preferably using a secret manager or key vault.
- Ensure that the certificate has the appropriate key usage extensions for SAML signing and encryption.
- Regularly rotate certificates according to your organization's security policies.
