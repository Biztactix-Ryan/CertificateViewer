using System;
using System.Threading.Tasks;
using CertificateViewer.Certificates;
using CertificateViewer.Services;
using NUnit.Framework;

namespace CertificateViewer.Tests.Unit.Services
{
    [TestFixture]
    public class SslClientTests
    {
        [Test]
        public void should_throw_on_invalid_host([Values("", " ", null)] string host,
            [Values] ConnectionProtocol protocol)
        {
            Assert.ThrowsAsync<ArgumentException>(async () => await SslClient.GetCertificateAsync(host, 443, protocol));
        }

        [Test]
        public void should_throw_on_invalid_port([Values(-1, 70000)] int port, [Values] ConnectionProtocol protocol)
        {
            Assert.ThrowsAsync<ArgumentOutOfRangeException>(async () =>
                await SslClient.GetCertificateAsync("a@b.com", port, protocol));
        }

        [TestCase("dnielsen.dev", 443, ConnectionProtocol.Https)]
        [TestCase("mx.sdf.org", 587, ConnectionProtocol.SmtpStarttls)]
        public async Task should_get_certificate_summary(string host, int port, ConnectionProtocol connectionProtocol)
        {
            var summary = await SslClient.GetCertificateAsync(host, port, connectionProtocol);

            Assert.IsNotNull(summary);
            Assert.IsTrue(summary.IsValid);
            Assert.IsNotNull(summary.CipherAlgorithm);
            Assert.IsNotNull(summary.CipherStrength);
            Assert.IsNotNull(summary.SslProtocol);
            Assert.IsNull(summary.ErrorMessage);
            
            foreach (var certificateSummary in summary.CertificateChain)
            {
                should_have_expected_summary_information(certificateSummary);
            }
        }

        [TestCase("somefake-domain-1.dev", 443, ConnectionProtocol.Https)]
        public async Task should_have_error_on_invalid_host(string host, int port, ConnectionProtocol connectionProtocol)
        {
            var summary = await SslClient.GetCertificateAsync(host, port, connectionProtocol);
            Assert.AreEqual("Name or service not known", summary.ErrorMessage);
        }

        public void should_have_expected_summary_information(CertificateSummary certificateSummary)
        {
            Assert.IsFalse(certificateSummary.IsExpired);
            Assert.IsNotNull(certificateSummary.Issuer);
            Assert.LessOrEqual(DateTime.UtcNow, certificateSummary.NotAfterUtc);
            Assert.GreaterOrEqual(DateTime.UtcNow, certificateSummary.NotBeforeUtc);
            Assert.IsNotNull(certificateSummary.SerialNumber);
            Assert.IsNotNull(certificateSummary.Subject);
            Assert.IsNotNull(certificateSummary.Version);
        }
    }
}