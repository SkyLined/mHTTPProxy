import socket, threading;

from mConsole  import oConsole;
from mHTTPConnection import \
    cHTTPConnection, \
    cURL;
from mMultiThreading import cThread;

NORMAL =            0x0F07; # Light grey
DIM  =              0x0F08; # Dark grey
INFO =              0x0F0F; # Bright white
OK =                0x0F0A; # Bright green
ERROR =             0x0F0C; # Bright red
WARNING =           0x0F0E; # Yellow

uServerPortNumber = 28080;
def foGetServerURL(sNote):
  global uServerPortNumber;
  uServerPortNumber += 1;
  return cURL.foFromBytesString(b"http://localhost:%d/%s" % (uServerPortNumber, sNote));

bTestHTTP = True;
oTestHTTPURL = cURL.foFromBytesString(b"http://example.com");

bTestHTTPS = True;
oTestHTTPSURL = cURL.foFromBytesString(b"https://example.com");

bTestRedirectToHTTPS = True;
oTestRedirectToHTTPSURL = cURL.foFromBytesString(b"http://skylined.nl");

bTestUnknownHostname = True;
oUnknownHostnameURL = cURL.foFromBytesString(b"http://does.not.exist.example.com/unknown-hostname");

bTestInvalidAddress = True;
oInvalidAddressURL = cURL.foFromBytesString(b"http://0.0.0.0/invalid-address");

bTestConnectTimeout = True;
oConnectTimeoutURL = foGetServerURL(b"connect-timeout");

bTestConnectionRefused = True;
oConnectionRefusedURL = foGetServerURL(b"refuse-connection");

bTestConnectionDisconnected = True;
oConnectionDisconnectedURL = foGetServerURL(b"disconnect");

bTestConnectionShutdown = True;
oConnectionShutdownURL = foGetServerURL(b"shutdown");

bTestResponseTimeout = True;
oResponseTimeoutURL = foGetServerURL(b"response-timeout");

bTestInvalidHTTPMessage = True;
oInvalidHTTPMessageURL = foGetServerURL(b"send-invalid-response");

def fTestClient(
  oHTTPClient,
  o0CertificateStore,
  nEndWaitTimeoutInSeconds,
):
  oServersShouldBeRunningLock = threading.Lock();
  oServersShouldBeRunningLock.acquire(); # Released once servers should stop running.
  if bTestHTTP:
    oConsole.fOutput(INFO, "\u2500\u2500\u2500\u2500 Making a first test request to %s " % oTestHTTPURL, sPadding = "\u2500");
    (oRequest, o0Response) = oHTTPClient.fto0GetRequestAndResponseForURL(oTestHTTPURL);
    assert o0Response, \
        "No response!?";
    oResponse = o0Response;
    oConsole.fOutput("  oRequest = %s" % oRequest.fsbSerialize());
    oConsole.fOutput("  oResponse = %s" % oResponse.fsbSerialize());
    oConsole.fOutput("\u2500\u2500\u2500\u2500 Making a second test request to %s " % oTestHTTPURL, sPadding = "\u2500");
    (oRequest, o0Response) = oHTTPClient.fto0GetRequestAndResponseForURL(oTestHTTPURL);
    assert o0Response, \
        "No response!?";
    oResponse = o0Response;
    oConsole.fOutput("  oRequest = %s" % oRequest);
    oConsole.fOutput("  oResponse = %s" % oResponse);
    if oHTTPClient.__class__.__name__ == "cHTTPClient": 
      # cHTTPClient specific checks
      asbConnectionPoolsProtocolHostPort = set(oHTTPClient._cHTTPClient__doConnectionsToServerPool_by_sbProtocolHostPort.keys());
      assert asbConnectionPoolsProtocolHostPort == set((oTestHTTPURL.sbBase,)), \
          "Expected a oHTTPClient instance to have one cConnectionsToServerPool instance for %s, but found %s" % \
          (oTestHTTPURL.sbBase, repr(asbConnectionPoolsProtocolHostPort));
      oConnectionsToServerPool = oHTTPClient._cHTTPClient__doConnectionsToServerPool_by_sbProtocolHostPort.get(oTestHTTPURL.sbBase);
      assert oConnectionsToServerPool, \
          "Expected a cConnectionsToServerPool instance for %s, but found none" % oTestHTTPURL;
      aoConnections = oConnectionsToServerPool._cHTTPConnectionsToServerPool__aoConnections;
      assert len(aoConnections) == 1, \
          "Expected a cConnectionsToServerPool instance with one connection for %s, but found %d connections" % \
          (oTestHTTPURL, len(aoConnections));
    if oHTTPClient.__class__.__name__ == "cHTTPClientUsingProxyServer": 
      # cHTTPClientUsingProxyServer specific checks
      aoConnectionsToProxyNotConnectedToAServer = oHTTPClient._cHTTPClientUsingProxyServer__aoConnectionsToProxyNotConnectedToAServer;
      assert len(aoConnectionsToProxyNotConnectedToAServer) == 1, \
          "Expected one connection to the proxy, but found %d connections" % len(aoConnectionsToProxyNotConnectedToAServer);
      doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort = oHTTPClient._cHTTPClientUsingProxyServer__doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort;
      asSecureConnectionTargets = list(doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort.keys());
      assert len(asSecureConnectionTargets) == 0, \
          "Expected no secure connections, but found %s" % repr(asSecureConnectionTargets);
  
  if bTestHTTPS:
    # Wrapping SSL secured sockets in SSL is not currently supported, so the
    # client cannot secure a connection to a server over a secure connection to a
    # proxy.
    oProxyServerURLForSecureTestURL = oHTTPClient.fo0GetProxyServerURLForURL(oTestHTTPSURL);
    # If we are not using a proxy, or the URL for the proxy server is not secure,
    # we can test a secure connection to the server, if we have a certificate store.
    if False: # oProxyServerURLForSecureTestURL and oProxyServerURLForSecureTestURL.bSecure:
      oConsole.fOutput(ERROR, "*** Cannot test secure connections through secure proxy at ", str(oProxyServerURLForSecureTestURL));
    elif not o0CertificateStore:
      oConsole.fOutput(ERROR, "*** Cannot test secure connections without a certificate store!");
    else:
      oConsole.fOutput(INFO, "\u2500\u2500\u2500\u2500 Making a first test request to %s " % oTestHTTPSURL, sPadding = "\u2500");
      (oRequest, o0Response) = oHTTPClient.fto0GetRequestAndResponseForURL(oTestHTTPSURL);
      assert o0Response, \
          "No response!?";
      oResponse = o0Response;
      oConsole.fOutput("  oRequest = %s" % oRequest);
      oConsole.fOutput("  oResponse = %s" % oResponse);
      oConsole.fOutput("\u2500\u2500\u2500\u2500 Making a second test request to %s " % oTestHTTPSURL, sPadding = "\u2500");
      (oRequest, o0Response) = oHTTPClient.fto0GetRequestAndResponseForURL(oTestHTTPSURL);
      assert o0Response, \
          "No response!?";
      oResponse = o0Response;
      oConsole.fOutput("  oRequest = %s" % oRequest);
      oConsole.fOutput("  oResponse = %s" % oResponse);
      if oHTTPClient.__class__.__name__ == "cHTTPClient": 
        # cHTTPClient specific checks
        asbConnectionPoolsProtocolHostPort = set(oHTTPClient._cHTTPClient__doConnectionsToServerPool_by_sbProtocolHostPort.keys());
        assert asbConnectionPoolsProtocolHostPort == set((oTestHTTPURL.sbBase, oTestHTTPSURL.sbBase)), \
            "Expected a oHTTPClient instance to have a cConnectionsToServerPool instance for %s and %s, but found %s" % \
            (oTestHTTPURL.sbBase, oTestHTTPSURL.sbBase, repr(asbConnectionPoolsProtocolHostPort));
        
        oConnectionsToServerPool = oHTTPClient._cHTTPClient__doConnectionsToServerPool_by_sbProtocolHostPort.get(oTestHTTPSURL.sbBase);
        assert oConnectionsToServerPool, \
            "Expected a cConnectionsToServerPool instance for %s, but found none" % oTestHTTPSURL;
        aoConnections = oConnectionsToServerPool._cHTTPConnectionsToServerPool__aoConnections;
        assert len(aoConnections) == 1, \
            "Expected a cConnectionsToServerPool instance with one connection for %s, but found %d connections" % \
            (oTestHTTPSURL, len(aoConnections));
      if oHTTPClient.__class__.__name__ == "cHTTPClientUsingProxyServer": 
        # cHTTPClientUsingProxyServer specific checks
        aoConnectionsToProxyNotConnectedToAServer = oHTTPClient._cHTTPClientUsingProxyServer__aoConnectionsToProxyNotConnectedToAServer;
        doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort = oHTTPClient._cHTTPClientUsingProxyServer__doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort;
        asbSecureConnectionTargets = list(doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort.keys());
        bFoundUnexpectedNonSecureConnections = len(aoConnectionsToProxyNotConnectedToAServer) != 0;
        bFoundUnexpectedSecureConnections = set(asbSecureConnectionTargets) != set((oTestHTTPSURL.sbBase,));
        if bFoundUnexpectedNonSecureConnections or bFoundUnexpectedSecureConnections:
          if bFoundUnexpectedNonSecureConnections:
            print("The HTTP client has unexpected non-secure connections!");
          if bFoundUnexpectedSecureConnections:
            print("The HTTP client has unexpected secure connections!");
          print("Non-secure connections:");
          for oNonSecureConnection in aoConnectionsToProxyNotConnectedToAServer:
            print("* %s" % repr(oNonSecureConnection));
          print("Secure connections:");
          for (sbProtocolHostPort, oSecureConnection) in doSecureConnectionToServerThroughProxy_by_sbProtocolHostPort.items():
            print("* %S => %s" % (sbProtocolHostPort, repr(oSecureConnection)));
          raise AssertionError();

  if bTestRedirectToHTTPS:
    ###
    ### Test redirecting
    ###
    oConsole.fOutput(INFO, "\u2500\u2500\u2500\u2500 Making a test request without following redirects to %s " % oTestRedirectToHTTPSURL, sPadding = "\u2500");
    (oRequest, o0Response) = oHTTPClient.fto0GetRequestAndResponseForURL(oTestRedirectToHTTPSURL);
    assert o0Response, \
        "No response!?";
    oResponse = o0Response;
    oConsole.fOutput("  oRequest = %s" % oRequest);
    oConsole.fOutput("  oResponse = %s" % oResponse);
    oConsole.fOutput("\u2500\u2500\u2500\u2500 Making a test request and follow redirects to %s " % oTestRedirectToHTTPSURL, sPadding = "\u2500");
    (oRequest, o0Response) = oHTTPClient.fto0GetRequestAndResponseForURL(
      oTestRedirectToHTTPSURL,
      uMaximumNumberOfRedirectsToFollow = 5,
    );
    assert o0Response, \
        "No response!?";
    oResponse = o0Response;
    oConsole.fOutput("  oRequest = %s" % oRequest);
    oConsole.fOutput("  oResponse = %s" % oResponse);
  
  atxTests = [];
  if bTestUnknownHostname:
    atxTests.append((
      1,
      oUnknownHostnameURL,
      cHTTPConnection.cTCPIPDNSNameCannotBeResolvedException,
      [],
      [400],
    ));
  
  if bTestInvalidAddress:
    atxTests.append((
      1,
      oInvalidAddressURL,
      cHTTPConnection.cTCPIPInvalidAddressException,
      [],
      [400],
    ));
  
  if bTestConnectTimeout:
    atxTests.append((
      1,
      oConnectTimeoutURL,
      cHTTPConnection.cTCPIPConnectTimeoutException,
      [],
      [502, 504],
    ));

  if bTestConnectionRefused:
    # Create a server on a socket but do not listen so connections are refused.
    oConnectionRefusedServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0);
    oConnectionRefusedServerSocket.bind((oConnectionRefusedURL.sbHost, oConnectionRefusedURL.uPortNumber));
    atxTests.append((
      1,
      oConnectionRefusedURL,
      cHTTPConnection.cTCPIPConnectionRefusedException,
      [cHTTPConnection.cTCPIPConnectTimeoutException],
      [502],
    ));

  if bTestConnectionDisconnected:
    # Create a server on a socket that immediately closes the connection.
    oConnectionDisconnectedServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0);
    oConnectionDisconnectedServerSocket.bind((oConnectionDisconnectedURL.sbHost, oConnectionDisconnectedURL.uPortNumber));
    oConnectionDisconnectedServerSocket.listen(1);
    def fConnectionDisconnectedServerThread():
      (oClientSocket, (sClientIP, uClientPortNumber)) = oConnectionDisconnectedServerSocket.accept();
      oConsole.fOutput(DIM, "  > Disconnect server is disconnecting the connection...");
      oClientSocket.close();
      oConsole.fOutput(DIM, "  > Disconnect server thread terminated.");
    oConnectionDisconnectedServerThread = cThread(fConnectionDisconnectedServerThread);
    oConnectionDisconnectedServerThread.fStart(bVital = False);
    atxTests.append((
      1,
      oConnectionDisconnectedURL,
      cHTTPConnection.cTCPIPConnectionDisconnectedException,
      [cHTTPConnection.cTCPIPConnectionShutdownException],
      [502],
    ));
  
  if bTestConnectionShutdown:
    # Create a server on a socket that immediately shuts down the connection.
    oConnectionShutdownServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0);
    oConnectionShutdownServerSocket.bind((oConnectionShutdownURL.sbHost, oConnectionShutdownURL.uPortNumber));
    oConnectionShutdownServerSocket.listen(1);
    def fConnectionShutdownServerThread():
      (oClientSocket, (sClientIP, uClientPortNumber)) = oConnectionShutdownServerSocket.accept();
      oConsole.fOutput(DIM, "  > Shutdown server is shutting down the connection for writing...");
      oClientSocket.shutdown(socket.SHUT_WR);
      oConsole.fOutput(DIM, "  > Shutdown server is sleeping to keep the connection open....");
      oServersShouldBeRunningLock.acquire();
      oServersShouldBeRunningLock.release();
      oConsole.fOutput(DIM, "  > Shutdown server is disconnecting the connection...");
      oClientSocket.close();
      oConsole.fOutput(DIM, "  > Shutdown server thread terminated.");
      
    oConnectionShutdownServerThread = cThread(fConnectionShutdownServerThread);
    oConnectionShutdownServerThread.fStart(bVital = False);
    atxTests.append((
      1,
      oConnectionShutdownURL,
      cHTTPConnection.cTCPIPConnectionShutdownException,
      [],
      [502],
    ));

  if bTestResponseTimeout:
    # Create a server on a socket that does not send a response.
    oResponseTimeoutServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0);
    oResponseTimeoutServerSocket.bind((oResponseTimeoutURL.sbHost, oResponseTimeoutURL.uPortNumber));
    oResponseTimeoutServerSocket.listen(1);
    def fResponseTimeoutServerThread():
      (oClientSocket, (sClientIP, uClientPortNumber)) = oResponseTimeoutServerSocket.accept();
      oConsole.fOutput(DIM, "  > Response timeout server receiving request...");
      oClientSocket.recv(0x1000);
      oConsole.fOutput(DIM, "  > Response timeout server is sleeping to avoid sending a response...");
      oServersShouldBeRunningLock.acquire();
      oServersShouldBeRunningLock.release();
      oConsole.fOutput(DIM, "  > Response timeout server is disconnecting the connection...");
      oClientSocket.close();
      oConsole.fOutput(DIM, "  > Response timeout thread terminated.");
      
    oResponseTimeoutServerThread = cThread(fResponseTimeoutServerThread);
    oResponseTimeoutServerThread.fStart(bVital = False);
    atxTests.append((
      1,
      oResponseTimeoutURL,
      cHTTPConnection.cTCPIPDataTimeoutException,
      [],
      [504],
    ));
  if bTestInvalidHTTPMessage:
    # Create a server on a socket that sends an invalid response.
    oInvalidHTTPMessageServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0);
    oInvalidHTTPMessageServerSocket.bind((oInvalidHTTPMessageURL.sbHost, oInvalidHTTPMessageURL.uPortNumber));
    oInvalidHTTPMessageServerSocket.listen(1);
    sbInvalidResponse = b"Hello, world!\r\n";
    def fInvalidHTTPMessageServerThread():
      (oClientSocket, (sClientIP, uClientPortNumber)) = oInvalidHTTPMessageServerSocket.accept();
      oConsole.fOutput(DIM, "  > Invalid HTTP Message server received request; sending invalid response...");
      oClientSocket.recv(0x1000); # This should cover the request, which we discard.
      oClientSocket.send(sbInvalidResponse);
      oConsole.fOutput(DIM, "  > Invalid HTTP Message server is disconnecting the connection...");
      oClientSocket.close();
      oConsole.fOutput(DIM, "  > Invalid HTTP Message server thread terminated.");
    
    oInvalidHTTPMessageServerThread = cThread(fInvalidHTTPMessageServerThread);
    oInvalidHTTPMessageServerThread.fStart(bVital = False);
    atxTests.append((
      1,
      oInvalidHTTPMessageURL,
      cHTTPConnection.cHTTPInvalidMessageException,
      [],
      [502],
    ));

  for (
    uNumberOfRequests,
    oURL,
    cExpectedExceptionClass,
    acAcceptableExceptionClasses,
    auAcceptableStatusCodes,
  ) in atxTests:
    for uRequestNumber in range(1, uNumberOfRequests + 1):
      oConsole.fOutput(INFO, "\u2500\u2500\u2500\u2500 Making a test request to %s " % oURL, sPadding = "\u2500");
      if oHTTPClient.__class__.__name__ == "cHTTPClient":
        oConsole.fStatus("  * Expecting %s exception..." % cExpectedExceptionClass.__name__);
        auAcceptableStatusCodes = None;
      elif oHTTPClient.__class__.__name__ == "cHTTPClientUsingProxyServer":
        if auAcceptableStatusCodes:
          oConsole.fStatus("  * Expecting a HTTP %s response..." % "/".join(["%03d" % uStatusCode for uStatusCode in auAcceptableStatusCodes]));
          cExpectedExceptionClass = None;
      if uRequestNumber < uNumberOfRequests:
        # We do not yet expect an exception, so we won't handle one.
        o0Response = oHTTPClient.fo0GetResponseForURL(oURL);
        assert o0Response, \
            "No response!?";
        oResponse = o0Response;
        oConsole.fOutput("  oResponse = %s" % oResponse);
      else:
        try:
          # Use a short connect timeout to speed things up: all connections should be created in about 1 second except the
          # one that purposefully times out and this way we do not have to wait for that to happen very long.
          o0Response = oHTTPClient.fo0GetResponseForURL(oURL);
          assert o0Response, \
              "No response!?";
          oResponse = o0Response;
          if auAcceptableStatusCodes:
            assert oResponse.uStatusCode in auAcceptableStatusCodes, \
                "Expected a HTTP %s response, got %s" % \
                ("/".join(["%03d" % uStatusCode for uStatusCode in auAcceptableStatusCodes]), oResponse.fsbGetStatusLine());
          oConsole.fOutput("  oResponse = %s" % oResponse);
        except Exception as oException:
          if oException.__class__ is cExpectedExceptionClass:
            oConsole.fOutput(OK, "  + Threw %s." % repr(oException));
          elif oException.__class__ in acAcceptableExceptionClasses:
            oConsole.fOutput(WARNING, "  ~ Threw %s." % repr(oException));
            oConsole.fOutput("    Expected %s." % cExpectedExceptionClass.__name__);
          else:
            oConsole.fOutput(ERROR, "  - Threw %s." % repr(oException));
            if cExpectedExceptionClass:
              oConsole.fOutput("    Expected %s." % cExpectedExceptionClass.__name__);
            else:
              oConsole.fOutput("    No exception expected.");
            raise;
        else:
          if cExpectedExceptionClass:
            oConsole.fOutput(ERROR, "  - Expected %s." % cExpectedExceptionClass.__name__);
            raise AssertionError("No exception");
  
  # Allow server threads to stop.
  oServersShouldBeRunningLock.release();
  oConsole.fOutput(INFO, "\u2500\u2500\u2500\u2500 Cleaning up ", sPadding = "\u2500");
  
  oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping HTTP Client ", sPadding = "\u2500");
  oHTTPClient.fStop();
  assert oHTTPClient.fbWait(nEndWaitTimeoutInSeconds), \
    "HTTP Client did not stop in time";
  
  if bTestConnectionRefused:
    oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping connection refused server ", sPadding = "\u2500");
    oConnectionRefusedServerSocket.close(); # Has no thread.
  
  if bTestConnectionDisconnected:
    oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping connection closed server ", sPadding = "\u2500");
    oConnectionDisconnectedServerSocket.close();
    assert oConnectionDisconnectedServerThread.fbWait(nEndWaitTimeoutInSeconds), \
        "Connection closed server thread (%d/0x%X) did not stop in time." % \
        (oConnectionDisconnectedServerThread.uId, oConnectionDisconnectedServerThread.uId);
  
  if bTestConnectionShutdown:
    oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping connection shutdown server ", sPadding = "\u2500");
    oConnectionShutdownServerSocket.close();
    assert oConnectionShutdownServerThread.fbWait(nEndWaitTimeoutInSeconds), \
        "Connection shutdown server thread (%d/0x%X) did not stop in time." % \
        (oConnectionShutdownServerThread.uId, oConnectionShutdownServerThread.uId);
  
  if bTestResponseTimeout:
    oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping response timeout server ", sPadding = "\u2500");
    oResponseTimeoutServerSocket.close();
    assert oResponseTimeoutServerThread.fbWait(nEndWaitTimeoutInSeconds), \
        "Connection shutdown server thread (%d/0x%X) did not stop in time." % \
        (oResponseTimeoutServerThread.uId, oResponseTimeoutServerThread.uId);
  
  if bTestInvalidHTTPMessage:
    oConsole.fOutput("\u2500\u2500\u2500\u2500 Stopping invalid http message server ", sPadding = "\u2500");
    oInvalidHTTPMessageServerSocket.close();
    assert oInvalidHTTPMessageServerThread.fbWait(nEndWaitTimeoutInSeconds), \
        "Invalid http message server thread (%d/0x%X) did not stop in time." % \
        (oInvalidHTTPMessageServerThread.uId, oInvalidHTTPMessageServerThread.uId);

