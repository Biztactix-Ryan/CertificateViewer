using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Authentication;
using CertificateViewer.Certificates;

namespace CertificateViewer.Contexts
{
    /// <summary>
    /// Represents a SSL context.
    /// </summary>
    public sealed class ContextSummary
    {
        
        /// <summary>
        /// Create a context summary from the given parameters.
        /// </summary>
        /// <param name="cipherAlgorithm">The context cipher algorithm.</param>
        /// <param name="cipherStrength">The context cipher strength.</param>
        /// <param name="sslPolicyErrors">SSL policy result.</param>
        /// <param name="sslProtocol">The SSL protocol used in the context.</param>
        private ContextSummary(CipherAlgorithmType cipherAlgorithm, int cipherStrength, SslPolicyErrors sslPolicyErrors,
            SslProtocols sslProtocol)
        {
            Certificate = null;
            CertificateChain = new List<CertificateSummary>();
            CipherAlgorithm = cipherAlgorithm;
            CipherStrength = cipherStrength;
            SslPolicyErrors = sslPolicyErrors;
            SslProtocol = sslProtocol;
        }

        /// <summary>
        /// Create a context summary from an exception.
        /// </summary>
        /// <param name="exception">Context exception.</param>
        private ContextSummary(Exception exception)
        {
            Certificate = null;
            CertificateChain = new List<CertificateSummary>();
            Exception = exception;
        }

        /// <summary>
        /// Context exception.
        /// </summary>
        private Exception Exception { get; }

        /// <summary>
        /// The primary domain certificate.
        /// </summary>
        public CertificateSummary Certificate { get; private set; }

        /// <summary>
        /// The certificate chain. May or may not include the primary domain.
        /// </summary>
        public IList<CertificateSummary> CertificateChain { get; }

        /// <summary>
        /// The context cipher algorithm.
        /// </summary>
        public CipherAlgorithmType CipherAlgorithm { get; }

        /// <summary>
        /// The context cipher strength.
        /// </summary>
        public int CipherStrength { get; }

        /// <summary>
        /// Context policy errors, if any.
        /// </summary>
        public SslPolicyErrors SslPolicyErrors { get; }

        /// <summary>
        /// The SSL protocol used in the context.
        /// </summary>
        public SslProtocols SslProtocol { get; }

        /// <summary>
        /// Create a new context from the provided parameters.
        /// </summary>
        /// <param name="cipherAlgorithmType">The context cipher algorithm.</param>
        /// <param name="cipherStrength">The context cipher strength.</param>
        /// <param name="sslPolicyErrors">SSL policy result.</param>
        /// <param name="sslProtocols">The SSL protocol used in the context.</param>
        /// <returns>new ContextSummary</returns>
        public static ContextSummary Create(CipherAlgorithmType cipherAlgorithmType, int cipherStrength,
            SslPolicyErrors sslPolicyErrors, SslProtocols sslProtocols)
        {
            return new ContextSummary(cipherAlgorithmType, cipherStrength, sslPolicyErrors, sslProtocols);
        }

        /// <summary>
        /// Create a new context from an exception.
        /// </summary>
        /// <param name="exception">Context exception/</param>
        /// <returns></returns>
        public static ContextSummary CreateFromException(Exception exception)
        {
            return new ContextSummary(exception);
        }

        /// <summary>
        /// Context error message, if any.
        /// </summary>
        public string ErrorMessage => Exception?.Message;

        /// <summary>
        /// Indicates if the context is valid.
        /// </summary>
        public bool IsValid => SslPolicyErrors == SslPolicyErrors.None;

        /// <summary>
        /// Sets the primary certificate summary.
        /// </summary>
        /// <param name="certificateSummary"></param>
        public void SetCertificate(CertificateSummary certificateSummary)
        {
            Certificate = certificateSummary;
        }

        /// <summary>
        /// Sets the certificate chain/
        /// </summary>
        /// <param name="certificateSummaries"></param>
        public void SetCertificateChain(IEnumerable<CertificateSummary> certificateSummaries)
        {
            foreach (var certificate in certificateSummaries)
            {
                CertificateChain.Add(certificate);
            }
        }

    }
}