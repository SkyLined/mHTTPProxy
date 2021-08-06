from mHTTPProxy import cHTTPClientSideProxyServer;
from mHTTPClient import cHTTPClientUsingProxyServer;
from mConsole import oConsole;
from fTestClient import fTestClient;

def fTestProxyClientAndServer(
  oProxyServerURL,
  o0CertificateStore,
  o0InterceptSSLConnectionsCertificateAuthority,
  nEndWaitTimeoutInSeconds,
  f0LogEvents
):
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Creating a cHTTPClientSideProxyServer instance... ", sPadding = "\u2500");
  oProxyServer = cHTTPClientSideProxyServer(
    sbzHostname = oProxyServerURL.sbHostname,
    uzPortNumber = oProxyServerURL.uPortNumber,
    o0ServerSSLContext = (
      o0CertificateStore.foGetServersideSSLContextForHostname(oProxyServerURL.sbHostname)
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
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Creating a cHTTPClientUsingProxyServer instance... ", sPadding = "\u2500");
  oHTTPClient = cHTTPClientUsingProxyServer(
    oProxyServerURL = oProxyServerURL,
    bAllowUnverifiableCertificatesForProxy = True,
    o0zCertificateStore = o0CertificateStore,
    n0zConnectToProxyTimeoutInSeconds = 1, # Make sure connection attempts time out quickly to trigger a timeout exception.
  );
  if f0LogEvents: f0LogEvents(oHTTPClient, "oHTTPClient");
  
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Running client tests through proxy server... ", sPadding = "\u2500");
  fTestClient(oHTTPClient, o0CertificateStore, nEndWaitTimeoutInSeconds);
  
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping cHTTPClientUsingProxyServer instance... ", sPadding = "\u2500");
  oHTTPClient.fStop();
  assert oHTTPClient.fbWait(nEndWaitTimeoutInSeconds), \
      "cHTTPClientUsingProxyServer instance did not stop in time";
  
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping cHTTPClientSideProxyServer instance... ", sPadding = "\u2500");
  oProxyServer.fStop();
  assert oProxyServer.fbWait(nEndWaitTimeoutInSeconds), \
      "cHTTPClientSideProxyServer instance did not stop in time";
  