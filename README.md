# CertificateViewer

`CertificateViewer` is a simple utility to inspect the SSL context of a domain. Given a domain name it will make a connection and record the provided certificate chain. The context is returned as a `ContextSummary` which contains a collection of `CertificateSummary`. Each `CertificateSummary` contains brief information on an X509Certificate including the dates, the issuer, subject, serial number, and version.

### Packages

- Current Version: `1.0.0`
- Target Framework: `.NET Standard 2.0`

### Example Usage

Use `SslClient.GetCertificateAsync()` to get the SSL context for a domain.

        var contextSummary = await GetCertificateAsync("example.com", 443, ConnectionProtocol.Https);

`ContextSummary` will have the primary domain certificate in the `Certificate` property and the full chain will be in `CertificateChain`.

        var expired = contextSummary.CertificateChain.Any(x => x.IsExpired);

