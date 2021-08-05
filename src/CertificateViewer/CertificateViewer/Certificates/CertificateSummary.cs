using System;
using System.Security.Cryptography.X509Certificates;

namespace CertificateViewer.Certificates
{
    /// <summary>
    /// Represents a summary of a SSL certificate.
    /// </summary>
    public sealed class CertificateSummary
    {
        /// <summary>
        /// Create summary from <see cref="X509Certificate"/>
        /// </summary>
        /// <param name="certificate">X509Certificate</param>
        private CertificateSummary(X509Certificate certificate)
            : this(new X509Certificate2(certificate.Export(X509ContentType.Cert)))
        {
        }

        /// <summary>
        /// Create summary from <see cref="X509Certificate2"/>
        /// </summary>
        /// <param name="certificate">X509Certificate2</param>
        private CertificateSummary(X509Certificate2 certificate)
        {
            Issuer = certificate.Issuer;
            NotAfterUtc = certificate.NotAfter.ToUniversalTime();
            NotBeforeUtc = certificate.NotBefore.ToUniversalTime();
            SerialNumber = certificate.SerialNumber;
            Subject = certificate.Subject;
            Version = certificate.Version;
        }

        /// <summary>
        /// Indicates if the certificate has expired.
        /// </summary>
        public bool IsExpired => DateTime.UtcNow > NotAfterUtc;

        /// <summary>
        /// Certificate issuer.
        /// </summary>
        public string Issuer { get; }

        /// <summary>
        /// Expiration date.
        /// </summary>
        public DateTime NotAfterUtc { get; }

        /// <summary>
        /// Start date.
        /// </summary>
        public DateTime NotBeforeUtc { get; }

        /// <summary>
        /// Certificate serial number.
        /// </summary>
        public string SerialNumber { get; }

        /// <summary>
        /// Certificate subject.
        /// </summary>
        public string Subject { get; }

        /// <summary>
        /// Certificate version.
        /// </summary>
        public int Version { get; }
        
        /// <summary>
        /// Create a new certificate summary.
        /// </summary>
        /// <param name="certificate"><see cref="X509Certificate"/></param>
        /// <returns><see cref="CertificateSummary"/></returns>
        public static CertificateSummary Create(X509Certificate certificate)
        {
            return new CertificateSummary(certificate);
        }

        /// <summary>
        /// Create a new certificate summary.
        /// </summary>
        /// <param name="certificate"><see cref="X509Certificate2"/></param>
        /// <returns><see cref="X509Certificate2"/></returns>
        public static CertificateSummary Create(X509Certificate2 certificate)
        {
            return new CertificateSummary(certificate);
        }

    }
}