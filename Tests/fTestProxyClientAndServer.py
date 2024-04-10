from mConsole  import oConsole;
from mHTTPProxy import cHTTPClientSideProxyServer;
from mHTTPClient import cHTTPClientUsingProxyServer;

from fTestClient import fTestClient;

def fTestProxyClientAndServer(
  oProxyServerURL,
  o0CertificateStore,
  o0InterceptSSLConnectionsCertificateAuthority,
  nEndWaitTimeoutInSeconds,
  f0LogEvents
):
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Creating a client side HTTP proxy server... ", sPadding = "\u2500");
  oProxyServer = cHTTPClientSideProxyServer(
    sbzHost = oProxyServerURL.sbHost,
    uzPortNumber = oProxyServerURL.uPortNumber,
    o0ServerSSLContext = (
      o0CertificateStore.foGetServersideSSLContextForHost(oProxyServerURL.sbHost)
    ) if oProxyServerURL.bSecure else None,
    o0zCertificateStore = o0CertificateStore,
    o0InterceptSSLConnectionsCertificateAuthority = o0InterceptSSLConnectionsCertificateAuthority,
    # Make sure the proxy server times out waiting for the HTTP server
    # before the client times out waiting for the proxy.
    n0zConnectTimeoutInSeconds = 5,
    n0zTransactionTimeoutInSeconds = 6,
  );
  if f0LogEvents: f0LogEvents(oProxyServer, "oProxyServer");
  oConsole.fOutput("  oProxyServer = ", str(oProxyServer));
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Creating a HTTP client using this proxy... ", sPadding = "\u2500");
  oHTTPClient = cHTTPClientUsingProxyServer(
    oProxyServerURL = oProxyServerURL,
    bVerifyCertificates = False,
    o0zCertificateStore = o0CertificateStore,
    n0zConnectToProxyTimeoutInSeconds = 1, # Make sure connection attempts time out quickly to trigger a timeout exception.
  );
  oConsole.fOutput("  oHTTPClient = ", str(oHTTPClient));
  if f0LogEvents: f0LogEvents(oHTTPClient, "oHTTPClient");
  
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Running client tests through proxy server... ", sPadding = "\u2500");
  fTestClient(oHTTPClient, o0CertificateStore, nEndWaitTimeoutInSeconds);
  
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping HTTP client... ", sPadding = "\u2500");
  oHTTPClient.fStop();
  assert oHTTPClient.fbWait(nEndWaitTimeoutInSeconds), \
      "cHTTPClientUsingProxyServer instance did not stop in time";
  
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping HTTP proxy... ", sPadding = "\u2500");
  oProxyServer.fStop();
  assert oProxyServer.fbWait(nEndWaitTimeoutInSeconds), \
      "cHTTPClientSideProxyServer instance did not stop in time";
  