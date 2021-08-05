using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using CertificateViewer.Certificates;
using CertificateViewer.Contexts;

namespace CertificateViewer.Services
{
    public static class SslClient
    {
        private static X509Certificate _certificate;
        private static SslPolicyErrors _sslPolicyErrors;
        
        private static readonly List<CertificateSummary> Chain = new();

        private static bool ValidationCallback(object sender, X509Certificate certificate, X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            _certificate = certificate;
            _sslPolicyErrors = sslPolicyErrors;

            foreach (var element in chain.ChainElements)
            {
                Chain.Add(CertificateSummary.Create(element.Certificate));
            }

            return sslPolicyErrors == SslPolicyErrors.None;
        }

        private static async Task<ContextSummary> GetCertificateAsync(string host, int port)
        {
            using (TcpClient tcpClient = new TcpClient())
            {
                tcpClient.NoDelay = true;
                tcpClient.ReceiveBufferSize = 4096;
                tcpClient.ReceiveTimeout = 60;
                tcpClient.SendBufferSize = 4096;
                tcpClient.SendTimeout = 60;

                try
                {
                    await tcpClient.ConnectAsync(host, port);
                }
                catch (Exception exception)
                {
                    return ContextSummary.CreateFromException(exception);
                }

                if (!tcpClient.Connected)
                {
                    var exception = new Exception($"Could not establish connection with {host}");
                    return ContextSummary.CreateFromException(exception);
                }

                using (SslStream sslStream = new SslStream(tcpClient.GetStream(), false,
                    ValidationCallback, null))
                {
                    await sslStream.AuthenticateAsClientAsync(host);

                    var summary = ContextSummary.Create(sslStream.CipherAlgorithm, sslStream.CipherStrength,
                        _sslPolicyErrors, sslStream.SslProtocol);
                    summary.SetCertificate(CertificateSummary.Create(_certificate));
                    summary.SetCertificateChain(Chain);

                    return summary;
                }
            }
        }

        private static async Task<ContextSummary> GetCertificateStartTlsAsync(string host, int port)
        {
            static Exception ProtocolError(string command)
            {
                return new Exception($"SMTP server did not respond to {command} command.");
            }

            using (TcpClient tcpClient = new TcpClient())
            {
                tcpClient.NoDelay = true;
                tcpClient.ReceiveBufferSize = 4096;
                tcpClient.ReceiveTimeout = 60;
                tcpClient.SendBufferSize = 4096;
                tcpClient.SendTimeout = 60;

                try
                {
                    await tcpClient.ConnectAsync(host, port);
                }
                catch (Exception exception)
                {
                    return ContextSummary.CreateFromException(exception);
                }

                if (!tcpClient.Connected)
                {
                    var exception = new Exception($"Could not establish connection with {host}");
                    return ContextSummary.CreateFromException(exception);
                }

                using (Stream stream = tcpClient.GetStream())
                using (StreamReader reader = new StreamReader(stream))
                using (StreamWriter writer = new StreamWriter(stream) { AutoFlush = true })
                using (SslStream sslStream = new SslStream(stream, false, ValidationCallback, null))
                {
                    var response = await reader.ReadLineAsync();

                    if (!response.StartsWith("220"))
                        return ContextSummary.CreateFromException(ProtocolError("CONNECT"));

                    await writer.WriteLineAsync("HELO there");
                    response = await reader.ReadLineAsync();

                    if (!response.StartsWith("250"))
                        return ContextSummary.CreateFromException(ProtocolError("HELO"));

                    await writer.WriteLineAsync("STARTTLS");
                    response = await reader.ReadLineAsync();

                    if (!response.StartsWith("220"))
                        return ContextSummary.CreateFromException(ProtocolError("STARTTLS"));

                    await sslStream.AuthenticateAsClientAsync(host);

                    var summary = ContextSummary.Create(sslStream.CipherAlgorithm, sslStream.CipherStrength,
                        _sslPolicyErrors, sslStream.SslProtocol);
                    summary.SetCertificate(CertificateSummary.Create(_certificate));
                    summary.SetCertificateChain(Chain);

                    using (StreamWriter sslWriter = new StreamWriter(sslStream))
                    {
                        await sslWriter.WriteLineAsync("QUIT");
                        return summary;
                    }
                }
            }
        }

        public static async Task<ContextSummary> GetCertificateAsync(string host, int port, ConnectionProtocol protocol)
        {
            if (string.IsNullOrEmpty(host) || string.IsNullOrWhiteSpace(host))
                throw new ArgumentException($"{nameof(host)} cannot be null or empty");

            if (port < IPEndPoint.MinPort || port > IPEndPoint.MaxPort)
                throw new ArgumentOutOfRangeException(
                    $"{nameof(port)} must be between {IPEndPoint.MinPort} and {IPEndPoint.MaxPort}");

            switch (protocol)
            {
                case ConnectionProtocol.Https:
                case ConnectionProtocol.Smtps:
                    return await GetCertificateAsync(host, port);
                case ConnectionProtocol.SmtpStarttls:
                    return await GetCertificateStartTlsAsync(host, port);
                default:
                    throw new ArgumentOutOfRangeException(nameof(protocol), protocol, null);
            }
        }
    }
}