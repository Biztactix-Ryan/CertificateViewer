using System;
using CertificateViewer.Contexts;
using NUnit.Framework;

namespace CertificateViewer.Tests.Unit.Contexts
{
    [TestFixture]
    public class ContextSummaryTests
    {
        [Test]
        public void should_create_context_summary_from_exception()
        {
            var exception = new Exception("ERROR");
            var summary = ContextSummary.CreateFromException(exception);
            
            Assert.AreEqual("ERROR", summary.ErrorMessage);
            Assert.IsNull(summary.Certificate);
            Assert.AreEqual(0, summary.CertificateChain.Count);
        }
    }
}