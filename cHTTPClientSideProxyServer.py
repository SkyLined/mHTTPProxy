import re, time;

try: # mDebugOutput use is Optional
  from mDebugOutput import ShowDebugOutput, fShowDebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  ShowDebugOutput = fShowDebugOutput = lambda x: x; # NOP

from mHTTPConnection import cHTTPConnection, cHTTPResponse, cHTTPHeaders, mExceptions, cURL;
from mHTTPServer import cHTTPServer;
from mHTTPClient import cHTTPClient, cHTTPClientUsingProxyServer, cHTTPClientUsingAutomaticProxyServer;
from mMultiThreading import cLock, cThread, cWithCallbacks;
from mNotProvided import *;
from mTCPIPConnection import cTransactionalBufferedTCPIPConnection;

# To turn access to data store in multiple variables into a single transaction, we will create locks.
# These locks should only ever be locked for a short time; if it is locked for too long, it is considered a "deadlock"
# bug, where "too long" is defined by the following value:
gnDeadlockTimeoutInSeconds = 1; # We're not doing anything time consuming, so this should suffice.

grbHostnamePort = re.compile(
  rb"^"                                     # {
  rb"(" + cURL.sbHostnameRegExp + rb")"     #   (hostname)
  rb"\:" rb"(\d+)"                          #   ":" (port)
  rb"$",                                    # }
  re.I
);

def foGetErrorResponse(sbVersion, uStatusCode, sbBody):
  fAssertType("sbVersion", sbVersion, bytes);
  fAssertType("uStatusCode", uStatusCode, int);
  fAssertType("sbBody", sbBody, bytes);
  return cHTTPResponse(
    sbzVersion = sbVersion,
    uzStatusCode = uStatusCode,
    o0zHeaders = cHTTPHeaders.foFromDict({
      b"Connection": b"Close",
      b"Content-Type": b"text/plain",
    }),
    sb0Body = sbBody,
    bAutomaticallyAddContentLengthHeader = True,
  );

def foGetResponseForException(oException, sbHTTPVersion):
  if isinstance(oException, (mExceptions.cDNSUnknownHostnameException, mExceptions.cTCPIPInvalidAddressException)):
    return foGetErrorResponse(sbHTTPVersion, 400, b"The server cannot be found.");
  if isinstance(oException, mExceptions.cTCPIPConnectTimeoutException):
    return foGetErrorResponse(sbHTTPVersion, 504, b"Connecting to the server timed out.");
  if isinstance(oException, mExceptions.cTCPIPDataTimeoutException):
    return foGetErrorResponse(sbHTTPVersion, 504, b"The server did not respond before the request timed out.");
  if isinstance(oException, mExceptions.cHTTPOutOfBandDataException):
    return foGetErrorResponse(sbHTTPVersion, 502, b"The server send out-of-band data.");
  if isinstance(oException, mExceptions.cTCPIPConnectionRefusedException):
    return foGetErrorResponse(sbHTTPVersion, 502, b"The server did not accept our connection.");
  if isinstance(oException, (mExceptions.cTCPIPConnectionShutdownException, mExceptions.cTCPIPConnectionDisconnectedException)):
    return foGetErrorResponse(sbHTTPVersion, 502, b"The server disconnected before sending a response.");
  if isinstance(oException, mExceptions.cHTTPInvalidMessageException):
    return foGetErrorResponse(sbHTTPVersion, 502, b"The server send an invalid HTTP response.");
  if mExceptions.cSSLException and isinstance(oException, mExceptions.cSSLSecureTimeoutException):
    return foGetErrorResponse(sbHTTPVersion, 504, b"The connection to the server could not be secured before the request timed out.");
  if mExceptions.cSSLException and isinstance(oException, (mExceptions.cSSLSecureHandshakeException, mExceptions.cSSLIncorrectHostnameException)):
    return foGetErrorResponse(sbHTTPVersion, 504, b"The connection to the server could not be secured.");
  raise;

class cHTTPClientSideProxyServer(cWithCallbacks):
  u0DefaultMaxNumberOfConnectionsToChainedProxy = 10;
  n0DefaultSecureConnectionToChainedProxyTimeoutInSeconds = 5;
  
  n0DefaultSecureTimeoutInSeconds = zNotProvided; # Let mHTTPConnection pick a default.
  n0DefaultTransactionTimeoutInSeconds = 10;
  n0DefaultSecureConnectionPipeTotalDurationTimeoutInSeconds = None;
  n0DefaultSecureConnectionPipeIdleTimeoutInSeconds = 20;
  n0DefaultConnectionTerminateTimeoutInSeconds = 10;
  
  @ShowDebugOutput
  def __init__(oSelf,
    sbzHostname = zNotProvided, uzPortNumber = zNotProvided,
    o0ServerSSLContext = None,
    o0zCertificateStore = zNotProvided,
    bUseChainedProxy = False,
    o0ChainedProxyURL = None,
    o0ChainedProxyHTTPClient = None,
    bAllowUnverifiableCertificatesForChainedProxy = False,
    bCheckChainedProxyHostname = True,
    u0zMaxNumberOfConnectionsToChainedProxy = zNotProvided,
    # Connections to proxy use nzConnectTimeoutInSeconds
    n0zSecureConnectionToChainedProxyTimeoutInSeconds = zNotProvided,
    # Connections to proxy use nzTransactionTimeoutInSeconds
    o0InterceptSSLConnectionsCertificateAuthority = None,
    n0zConnectTimeoutInSeconds = zNotProvided,
    n0zSecureTimeoutInSeconds = zNotProvided,
    n0zTransactionTimeoutInSeconds = zNotProvided,
    bAllowUnverifiableCertificates = False,
    bCheckHostname = True,
    n0zSecureConnectionPipeTotalDurationTimeoutInSeconds = zNotProvided,
    n0zSecureConnectionPipeIdleTimeoutInSeconds = zNotProvided,
    u0zMaxNumberOfConnectionsToServer = zNotProvided,
  ):
    oSelf.__o0InterceptSSLConnectionsCertificateAuthority = o0InterceptSSLConnectionsCertificateAuthority;
    oSelf.__n0zConnectTimeoutInSeconds = n0zConnectTimeoutInSeconds;
    oSelf.__n0zSecureTimeoutInSeconds = fxzGetFirstProvidedValueIfAny(n0zSecureTimeoutInSeconds, oSelf.n0DefaultSecureTimeoutInSeconds);
    oSelf.__n0zTransactionTimeoutInSeconds = fxzGetFirstProvidedValueIfAny(n0zTransactionTimeoutInSeconds, oSelf.n0DefaultTransactionTimeoutInSeconds);
    oSelf.__bAllowUnverifiableCertificates = bAllowUnverifiableCertificates;
    oSelf.__bCheckHostname = bCheckHostname;
    oSelf.__n0SecureConnectionPipeTotalDurationTimeoutInSeconds = fxGetFirstProvidedValue( \
        n0zSecureConnectionPipeTotalDurationTimeoutInSeconds, oSelf.n0DefaultSecureConnectionPipeTotalDurationTimeoutInSeconds);
    oSelf.__n0SecureConnectionPipeIdleTimeoutInSeconds = fxGetFirstProvidedValue( \
        n0zSecureConnectionPipeIdleTimeoutInSeconds, oSelf.n0DefaultSecureConnectionPipeIdleTimeoutInSeconds);
    
    oSelf.__oPropertyAccessTransactionLock = cLock(
      "%s.__oPropertyAccessTransactionLock" % oSelf.__class__.__name__,
      n0DeadlockTimeoutInSeconds = gnDeadlockTimeoutInSeconds
    );
    oSelf.__aoSecureConnectionsFromClient = [];
    oSelf.__aoSecureConnectionThreads = [];
    
    oSelf.__bStopping = False;
    oSelf.__oTerminatedLock = cLock(
      "%s.__oTerminatedLock" % oSelf.__class__.__name__,
      bLocked = True
    );
    
    oSelf.fAddEvents(
      "new connection from client",
      "connect to server failed", "new connection to server",
      "request received from client", "request sent to server",
      "connection piped between client and server",  "connection intercepted between client and server", 
      "response received from server", "response sent to client",
      "request sent to and response received from server",  "request received from and response sent to client", 
      "connection to server terminated", "connection from client terminated", 
      "client terminated", "server terminated",
      "terminated"
    );
    
    # Create client
    oSelf.__bUsingChainedProxy = bUseChainedProxy;
    if bUseChainedProxy:
      if o0ChainedProxyHTTPClient is not None:
        assert o0ChainedProxyURL is None, \
            "Cannot provide both a chained proxy URL (%s) and HTTP client (%s)" % \
            (o0ChainedProxyURL, o0ChainedProxyHTTPClient);
        # Ideally, we want to check the caller did not provide any unapplicable arguments here, but that's a lot of
        # work, so I've pushed this out until it makes sense to add these checks
        oSelf.__oHTTPClient = o0ChainedProxyHTTPClient;
      elif o0ChainedProxyURL is not None:
        # Ideally, we want to check the caller did not provide any unapplicable arguments here, but that's a lot of
        # work, so I've pushed this out until it makes sense to add these checks
        oSelf.__oHTTPClient = cHTTPClientUsingProxyServer(
          oProxyServerURL = o0ChainedProxyURL,
          bAllowUnverifiableCertificatesForProxy = bAllowUnverifiableCertificatesForChainedProxy,
          bCheckProxyHostname = bCheckChainedProxyHostname,
          o0zCertificateStore = o0zCertificateStore,
          u0zMaxNumberOfConnectionsToProxy = fxGetFirstProvidedValue( \
              u0zMaxNumberOfConnectionsToChainedProxy, oSelf.u0DefaultMaxNumberOfConnectionsToChainedProxy),
          n0zConnectToProxyTimeoutInSeconds = n0zConnectTimeoutInSeconds,
          n0zSecureConnectionToProxyTimeoutInSeconds = fxGetFirstProvidedValue( \
              n0zSecureConnectionToChainedProxyTimeoutInSeconds, oSelf.n0DefaultSecureConnectionToChainedProxyTimeoutInSeconds),
          n0zSecureConnectionToServerTimeoutInSeconds = oSelf.__n0zSecureTimeoutInSeconds,
          n0zTransactionTimeoutInSeconds = oSelf.__n0zTransactionTimeoutInSeconds,
          bAllowUnverifiableCertificates = bAllowUnverifiableCertificates,
          bCheckHostname = bCheckHostname,
        );
      else:
        oSelf.__oHTTPClient = cHTTPClientUsingAutomaticProxyServer(
          o0zCertificateStore = o0zCertificateStore, 
          bAllowUnverifiableCertificatesForProxy = bAllowUnverifiableCertificatesForChainedProxy,
          bCheckProxyHostname = bCheckChainedProxyHostname,
          u0zMaxNumberOfConnectionsToServerWithoutProxy = u0zMaxNumberOfConnectionsToServer,
          u0zMaxNumberOfConnectionsToProxy = fxGetFirstProvidedValue( \
              u0zMaxNumberOfConnectionsToChainedProxy, oSelf.u0DefaultMaxNumberOfConnectionsToChainedProxy),
          n0zConnectTimeoutInSeconds = n0zConnectTimeoutInSeconds,
          n0zSecureTimeoutInSeconds = oSelf.__n0zSecureTimeoutInSeconds,
          n0zTransactionTimeoutInSeconds = oSelf.__n0zTransactionTimeoutInSeconds,
          n0zConnectToProxyTimeoutInSeconds = n0zConnectTimeoutInSeconds,
          n0zSecureConnectionToProxyTimeoutInSeconds = fxGetFirstProvidedValue( \
              n0zSecureConnectionToChainedProxyTimeoutInSeconds, oSelf.n0DefaultSecureConnectionToChainedProxyTimeoutInSeconds),
          n0zSecureConnectionToServerTimeoutInSeconds = oSelf.__n0zSecureTimeoutInSeconds,
          bAllowUnverifiableCertificates = bAllowUnverifiableCertificates,
          bCheckHostname = bCheckHostname,
        );
    else:
      assert o0ChainedProxyURL is None, \
          "bUseChainedProxy is False by o0ChainedProxyURL is %s!?" % repr(o0ChainedProxyURL);
      assert o0ChainedProxyHTTPClient is None, \
          "bUseChainedProxy is False by o0ChainedProxyHTTPClient is %s!?" % repr(o0ChainedProxyHTTPClient);
      oSelf.__oHTTPClient = cHTTPClient(
        o0zCertificateStore = o0zCertificateStore,
        u0zMaxNumberOfConnectionsToServer = u0zMaxNumberOfConnectionsToServer,
        n0zConnectTimeoutInSeconds = n0zConnectTimeoutInSeconds,
        n0zSecureTimeoutInSeconds = oSelf.__n0zSecureTimeoutInSeconds,
        n0zTransactionTimeoutInSeconds = oSelf.__n0zTransactionTimeoutInSeconds,
        bAllowUnverifiableCertificates = bAllowUnverifiableCertificates,
        bCheckHostname = bCheckHostname,
      );
    # Create server
    oSelf.__oHTTPServer = cHTTPServer(
      ftxRequestHandler = oSelf.__ftxRequestHandler,
      sbzHostname = sbzHostname,
      uzPortNumber = uzPortNumber,
      o0SSLContext = o0ServerSSLContext,
    );
    
    # Forward events from client
    oSelf.__oHTTPClient.fAddCallback("connect failed", lambda oHTTPServer, sHostname, uPortNumber, oException:
        oSelf.fFireCallbacks("connect to server failed", sHostname, uPortNumber, oException));
    oSelf.__oHTTPClient.fAddCallback("new connection", lambda oHTTPServer, oConnection:
        oSelf.fFireCallbacks("new connection to server", oConnection));
    oSelf.__oHTTPClient.fAddCallback("request sent", lambda oHTTPServer, oConnection, oRequest:
        oSelf.fFireCallbacks("request sent to server", oConnection, oRequest));
    oSelf.__oHTTPClient.fAddCallback("response received", lambda oHTTPServer, oConnection, oResponse:
        oSelf.fFireCallbacks("response received from server", oConnection, oResponse));
    oSelf.__oHTTPClient.fAddCallback("request sent and response received", lambda oHTTPServer, oConnection, oRequest, oResponse:
        oSelf.fFireCallbacks("request sent to and response received from server", oConnection, oRequest, oResponse));
    oSelf.__oHTTPClient.fAddCallback("connection terminated", lambda oHTTPServer, oConnection:
        oSelf.fFireCallbacks("connection to server terminated", oConnection));
    oSelf.__oHTTPClient.fAddCallback("terminated",
        oSelf.__fHandleTerminatedCallbackFromClient);
    
    # Forward events from server
    oSelf.__oHTTPServer.fAddCallback("new connection",
        lambda oHTTPServer, oConnection: oSelf.fFireCallbacks("new connection from client", oConnection));
    oSelf.__oHTTPServer.fAddCallback("request received",
        lambda oHTTPServer, oConnection, oRequest: oSelf.fFireCallbacks("request received from client", oConnection, oRequest));
    oSelf.__oHTTPServer.fAddCallback("response sent",
        lambda oHTTPServer, oConnection, oResponse: oSelf.fFireCallbacks("response sent to client", oConnection, oResponse));
    oSelf.__oHTTPServer.fAddCallback("request received and response sent",
        lambda oHTTPServer, oConnection, oRequest, oResponse: oSelf.fFireCallbacks("request received from and response sent to client", oConnection, oRequest, oResponse));
    oSelf.__oHTTPServer.fAddCallback("connection terminated",
        lambda oHTTPServer, oConnection: oSelf.fFireCallbacks("connection from client terminated", oConnection));
    oSelf.__oHTTPServer.fAddCallback("terminated",
        oSelf.__fHandleTerminatedCallbackFromServer);
  
  @ShowDebugOutput
  def __fHandleTerminatedCallbackFromServer(oSelf, oHTTPServer):
    assert oSelf.__bStopping, \
        "HTTP server terminated unexpectedly";
    oSelf.fFireCallbacks("server terminated", oHTTPServer);
    oSelf.__fCheckForTermination();
  
  @ShowDebugOutput
  def __fHandleTerminatedCallbackFromClient(oSelf, oHTTPClient):
    assert oSelf.__bStopping, \
        "HTTP client terminated unexpectedly";
    oSelf.fFireCallbacks("client terminated", oHTTPClient);
    oSelf.__fCheckForTermination();
  
  @ShowDebugOutput
  def __fCheckForTermination(oSelf):
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      if oSelf.bTerminated:
        return fShowDebugOutput("Already terminated.");
      if not oSelf.__oHTTPServer.bTerminated:
        return fShowDebugOutput("Not terminated: server still running.");
      if not oSelf.__oHTTPClient.bTerminated:
        return fShowDebugOutput("Not terminated: client still running.");
      if oSelf.__aoSecureConnectionsFromClient:
        return fShowDebugOutput("Not terminated: %d open connections." % len(oSelf.__aoSecureConnectionsFromClient));
      if oSelf.__aoSecureConnectionThreads:
        return fShowDebugOutput("Not terminated: %d running thread." % len(oSelf.__aoSecureConnectionThreads));
      oSelf.__oTerminatedLock.fRelease();
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    fShowDebugOutput("%s terminating." % oSelf.__class__.__name__);
    oSelf.fFireCallbacks("terminated");
  
  # These features are passed to the server part of a proxy
  @property
  def bTerminated(oSelf):
    return not oSelf.__oTerminatedLock.bLocked;
  @property
  def sbAddress(oSelf):
    return oSelf.__oHTTPServer.sbAddress;
  @property
  def bSecure(oSelf):
    return oSelf.__oHTTPServer.bSecure;
  @property
  def oURL(oSelf):
    return oSelf.__oHTTPServer.oURL;
  
  @ShowDebugOutput
  def fStop(oSelf):
    oSelf.__bStopping = True;
    fShowDebugOutput("Stopping HTTP server...");
    oSelf.__oHTTPServer.fStop();
    fShowDebugOutput("Stopping HTTP client...");
    oSelf.__oHTTPClient.fStop();
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      aoSecureConnections = oSelf.__aoSecureConnectionsFromClient[:];
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    for oSecureConnection in aoSecureConnections:
      fShowDebugOutput("Stopping secure connection %s..." % oSecureConnection);
      oSecureConnection.fStop();
  
  @ShowDebugOutput
  def fTerminate(oSelf):
    if oSelf.bTerminated:
      fShowDebugOutput("Already terminated.");
      return True;
    # Prevent any new connections from being accepted.
    oSelf.__bStopping = True;
    fShowDebugOutput("Terminating HTTP server...");
    oSelf.__oHTTPServer.fTerminate();
    fShowDebugOutput("Terminating HTTP client...");
    oSelf.__oHTTPClient.fTerminate();
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      aoSecureConnections = oSelf.__aoSecureConnectionsFromClient[:];
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    for oSecureConnection in aoSecureConnections:
      fShowDebugOutput("Terminating secure connection %s..." % oSecureConnection);
      oSecureConnection.fTerminate();
  
  @ShowDebugOutput
  def fWait(oSelf):
    # We could just wait for the termined lock, but while debugging, we may want
    # to know exactly what it is we're waiting for:
    if oSelf.__oTerminatedLock.bLocked:
      fShowDebugOutput("Waiting for HTTP server...");
      oSelf.__oHTTPServer.fWait();
      fShowDebugOutput("Waiting for HTTP client...");
      oSelf.__oHTTPClient.fWait();
      oSelf.__oPropertyAccessTransactionLock.fAcquire();
      try:
        aoSecureConnectionThreads = oSelf.__aoSecureConnectionThreads[:];
      finally:
        oSelf.__oPropertyAccessTransactionLock.fRelease();
      for oSecureConnectionThread in aoSecureConnectionThreads:
        fShowDebugOutput("Waiting for secure connection thread %s..." % oSecureConnectionThread);
        oSecureConnectionThread.fWait();
  
  @ShowDebugOutput
  def fbWait(oSelf, nTimeoutInSeconds):
    # We could just wait for the termined lock, but while debugging, we may want
    # to know exactly what it is we're waiting for:
    if oSelf.__oTerminatedLock.bLocked:
      nEndTime = time.time() + nTimeoutInSeconds;
      fShowDebugOutput("Waiting for HTTP server...");
      if not oSelf.__oHTTPServer.fbWait(nTimeoutInSeconds):
        fShowDebugOutput("Timeout.");
        return False;
      
      fShowDebugOutput("Waiting for HTTP client...");
      nRemainingTimeoutInSeconds = nEndTime - time.time();
      if not oSelf.__oHTTPClient.fbWait(nRemainingTimeoutInSeconds):
        fShowDebugOutput("Timeout.");
        return False;
      
      oSelf.__oPropertyAccessTransactionLock.fAcquire();
      try:
        aoSecureConnectionThreads = oSelf.__aoSecureConnectionThreads[:];
      finally:
        oSelf.__oPropertyAccessTransactionLock.fRelease();
      for oSecureConnectionThread in aoSecureConnectionThreads:
        fShowDebugOutput("Waiting for secure connection thread %s..." % oSecureConnectionThread);
        nRemainingTimeoutInSeconds = nEndTime - time.time();
        if not oSecureConnectionThread.fbWait(nRemainingTimeoutInSeconds):
          fShowDebugOutput("Timeout.");
          return False;
    return True;
  
  @ShowDebugOutput
  def __ftxRequestHandler(oSelf, oHTTPServer, oConnection, oRequest, o0SecureConnectionInterceptedForServerURL = None):
    ### Sanity checks ##########################################################
    oResponse = oSelf.__foResponseForConnectRequest(oConnection, oRequest);
    if oResponse:
      if oResponse.uStatusCode == 200:
        fShowDebugOutput("HTTP CONNECT request handled; started forwarding data.");
        return (oResponse, False);
      fShowDebugOutput("HTTP CONNECT request failed.");
      return (oResponse, True);
    elif oRequest.sbMethod.upper() not in [b"CONNECT", b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"OPTIONS", b"TRACE", b"PATCH"]:
      fShowDebugOutput("HTTP request method (%s) is not valid." % repr(oRequest.sbMethod));
      oResponse = foGetErrorResponse(oRequest.sbVersion, 400, b"The request method was not valid.");
      return (oResponse, True);
    elif o0SecureConnectionInterceptedForServerURL is not None:
      # This request was made to a connection we are intercepting after the client send a HTTP CONNECT request.
      # The URL should be relative:
      if oRequest.sbURL[:1] != b"/":
        fShowDebugOutput("HTTP request URL (%s) does not start with '/'." % repr(oRequest.sbURL));
        oResponse = foGetErrorResponse(oRequest.sbVersion, 400, b"The requested URL was not valid.");
        return (oResponse, True);
      oURL = o0SecureConnectionInterceptedForServerURL.foFromRelativeBytesString(oRequest.sbURL, bMustBeRelative = True);
    else:
      # This request was made to the proxy; the URL should be absolute:
      try:
        oURL = cURL.foFromBytesString(oRequest.sbURL);
      except mExceptions.cInvalidURLException:
        if oRequest.sbURL.split("://")[0] not in ["http", "https"]:
          fShowDebugOutput("HTTP request URL (%s) suggest request was meant for a server, not a proxy." % repr(oRequest.sbURL));
          sReason = "This is a HTTP proxy, not a HTTP server.";
        else:
          fShowDebugOutput("HTTP request URL (%s) is not valid." % repr(oRequest.sbURL));
          sReason = "The requested URL was not valid.",
        oResponse = foGetErrorResponse(oRequest.sbVersion, 400, sbReason);
        return (oResponse, True);
    oResponse = oSelf.__foResponseForInvalidProxyHeaderInRequest(oRequest)
    if oResponse:
      fShowDebugOutput("Invalid proxy header.");
      return (oResponse, True);
    oHeaders = oRequest.oHeaders.foClone();
    # This client does not decide how we handle our connection to the server, so we will overwrite any "Connection"
    # header copied from the request to the proxy with the value we want for the request to the server:
    oHeaders.fbReplaceHeadersForName(b"Connection", b"Keep-Alive");
    # We will not allow the client to request a compression that we cannot decode so we will remove any
    # "Accept-Encoding" value copied from the request to the proxy that we cannot decode:
    for oAcceptEncodingHeader in oHeaders.faoGetHeadersForName(b"Accept-Encoding"):
      sbFilteredValue = b",".join([
        sbCompressionType
        for sbCompressionType in oAcceptEncodingHeader.sbValue.split(b",")
        if sbCompressionType.strip().lower() in oRequest.asbSupportedCompressionTypes
      ]);
      if sbFilteredValue.strip():
        oAcceptEncodingHeader.sbValue = sbFilteredValue;
      else:
        oHeaders.fbRemoveHeader(oAcceptEncodingHeader);
    # When we are intercepting HTTPS traffice, HTTP Strict Transport Security (HSTS) headers must be stripped to allow
    # the user to ignore certificate warnings.
    if oSelf.__o0InterceptSSLConnectionsCertificateAuthority and oHeaders.fbRemoveHeadersForName(b"Strict-Transport-Security"):
      fShowDebugOutput("Filtered HSTS header.");
    try:
      oResponse = oSelf.__oHTTPClient.fo0GetResponseForURL(
        oURL = oURL,
        sbzMethod = oRequest.sbMethod,
        o0zHeaders = oHeaders,
        sb0Body = oRequest.sb0Body, # oRequest.sb0Body is the raw data, so this also handles Chunked requests.
      );
    except Exception as oException:
      oResponse = foGetResponseForException(oException, oRequest.sbVersion);
    else:
      if oSelf.__bStopping:
        fShowDebugOutput("Stopping.");
        return None;
      assert oResponse, \
          "Expected a response but got %s" % repr(oResponse);
    return (oResponse, True);
  
  @ShowDebugOutput
  def __foResponseForInvalidProxyHeaderInRequest(oSelf, oRequest):
    if oRequest.oHeaders.fo0GetUniqueHeaderForName(b"Proxy-Authenticate"):
      oResponse = foGetErrorResponse(oRequest.sbVersion, 400, b"This proxy does not require authentication.");
      return oResponse;
    if oRequest.oHeaders.fo0GetUniqueHeaderForName(b"Proxy-Authorization"):
      oResponse = foGetErrorResponse(oRequest.sbVersion, 400, b"This proxy does not require authorization.");
      return oResponse;
    fShowDebugOutput("Request does not have an invalid proxy header");
    return None;
  
  @ShowDebugOutput
  def __foResponseForConnectRequest(oSelf, oConnectionFromClient, oRequest):
    if oRequest.sbMethod.upper() != b"CONNECT":
      return None;
    
    # Check the sanity of the request.
    aoHostHeaders = oRequest.oHeaders.faoGetHeadersForName(b"Host");
    if len(aoHostHeaders) == 0:
      fShowDebugOutput("The request has no host header");
      return foGetErrorResponse(oRequest.sbVersion, 400, b"The request has no host header.");
    
    sbLowerHostHeader = aoHostHeaders[0].sbLowerValue;
    for oAdditionalHeader in aoHostHeaders[1:]:
      if oAdditionalHeader.sbLowerValue != sbLowerHostHeader:
        fShowDebugOutput("The request has multiple contradicting host headers");
        return foGetErrorResponse(oRequest.sbVersion, 400, b"The request has multiple contradicting host headers.");
    
    oHostnamePortMatch = grbHostnamePort.match(oRequest.sbURL);
    if not oHostnamePortMatch:
      fShowDebugOutput("HTTP request URL (%s) does not match 'hostname:port'." % repr(oRequest.sbURL));
      return foGetErrorResponse(oRequest.sbVersion, 400, b"The request does not provide a valid hostname:port.");
    
    sbHostname, sbPortNumber = oHostnamePortMatch.groups();
    uPortNumber = int(sbPortNumber);
    
    sbHostHeaderHostname, sb0HostHeaderPortNumber = (sbLowerHostHeader.split(b":", 1) + [None])[:2];
    u0HostHeaderPortNumber = int(sb0HostHeaderPortNumber) if sb0HostHeaderPortNumber is not None else None;
    if (
      sbHostHeaderHostname.lower() != sbHostname.lower()
      or u0HostHeaderPortNumber not in (None, uPortNumber)
    ):
      fShowDebugOutput("HTTP request URL (%s) does not match the Host header (%s)." % (repr(oRequest.sbURL), repr(aoHostHeaders[0])));
      return foGetErrorResponse(oRequest.sbVersion, 400, b"The requested URL did not match the 'Host' header.");
    
    oServerURL = cURL.foFromBytesString(b"https://%s:%d" % (sbHostname, uPortNumber));
    if oSelf.__o0InterceptSSLConnectionsCertificateAuthority:
      # We will be intercepting the requests, so we won't make a connection to the server immediately. We will
      # send a "200 Ok" response and start a thread that will handle the connection, but we will not simply pipe
      # the data in this thread. Instead the thread will negotiate SSL with the client using a wildcard certificate
      # and then wait for requests, forward them to the server, receive the response and forward it to the client.
      fConnectionHandler = oSelf.__fInterceptAndPipeConnection;
      txConnectionHandlerArguments = (oConnectionFromClient, oServerURL);
    else:
      # If we are not intercepting SSL connections, we will try to connect to the server. If this succeeds we will
      # send a "200 OK" response to the client and start a thread that will pipe data back and forth between the
      # client and server. We will ask our HTTP client to set up the connection, because the client may be using
      # a proxy, so we cannot connect directly.
      try:
        o0ConnectionToServer = oSelf.__oHTTPClient.fo0GetConnectionAndStartTransactionForURL(oServerURL, bSecure = False);
      except Exception as oException:
        return foGetResponseForException(oException, oRequest.sbVersion);
      if o0ConnectionToServer is None:
        # This is probably because we are stopping.
        return foGetErrorResponse(oRequest.sbVersion, 500, b"Could not connect to server.");
      oConnectionToServer = o0ConnectionToServer;
      oSelf.fFireCallbacks("new connection to server", oConnectionToServer);
      oConnectionToServer.fEndTransaction(); # We do not need a transaction yet
      oConnectionToServer.fAddCallback("terminated",
        lambda oConnectionToServer: oSelf.fFireCallbacks("connection to server terminated", oConnectionToServer)
      );
      # Create a thread that will pipe data back and forth between the client and server
      fConnectionHandler = oSelf.__fPipeConnection;
      # oConnectionFromClient is NOT in a transaction, oConnectionToServer is!!!
      txConnectionHandlerArguments = (oConnectionFromClient, oConnectionToServer, oServerURL);
    def fStartConnectionHandlerThread(oConnectionFromClient, oResponse):
      oThread = cThread(fConnectionHandler, *txConnectionHandlerArguments);
      oSelf.__oPropertyAccessTransactionLock.fAcquire();
      try:
        oSelf.__aoSecureConnectionsFromClient.append(oConnectionFromClient);
        oSelf.__aoSecureConnectionThreads.append(oThread);
      finally:
        oSelf.__oPropertyAccessTransactionLock.fRelease();
      oThread.fStart(bVital = False);
    # After our response is sent to the client, we start handling the connection, i.e. piping (intercepted) data
    # between them.
    oConnectionFromClient.fAddCallback("response sent", fStartConnectionHandlerThread, bFireOnce = True);
    # Send a reponse to the client.
    oResponse = cHTTPResponse(
      sbzVersion = oRequest.sbVersion,
      uzStatusCode = 200,
      sbzReasonPhrase = b"Ok",
      o0zHeaders = cHTTPHeaders.foFromDict({
        b"Connection": b"Keep-Alive",
        b"Content-type": b"text/plain",
      }),
      sb0Body = b"Connected to remote server.",
      bAutomaticallyAddContentLengthHeader = True,
    );
    return oResponse;
  
  @ShowDebugOutput
  def __fInterceptAndPipeConnection(oSelf, oConnectionFromClient, oServerURL):
    n0TotalDurationEndTime = (
      time.time() + oSelf.__n0zSecureConnectionPipeTotalDurationTimeoutInSeconds
      if fbProvided(oSelf.__n0zSecureConnectionPipeTotalDurationTimeoutInSeconds)
      else None
    );
    # When intercepting a supposedly secure connection, we will wait for the client to make requests through the
    # connection, forward it to the server to get a response using the same code as the normal proxy, and then
    # send the response back to the client.
    fShowDebugOutput("Intercepting secure connection for client %s to server %s." % (oConnectionFromClient, repr(oServerURL.sbBase)));
    fShowDebugOutput("Generating SSL certificate for %s..." % repr(oServerURL.sbHostname));
    oSSLContext = oSelf.__o0InterceptSSLConnectionsCertificateAuthority.foGenerateserverSideSSLContextForHostname(
      oServerURL.sbHostname,
    );
    bEndTransaction = False;
    try:
      fShowDebugOutput("Negotiating security for %s..." % oConnectionFromClient);
      sWhile = "Negotiating security for %s" % oConnectionFromClient;
      oConnectionFromClient.fSecure(
        oSSLContext,
        bCheckHostname = oSelf.__bCheckHostname,
        n0zTimeoutInSeconds = oSelf.__n0zSecureConnectionPipeTotalDurationTimeoutInSeconds,
      );
      while not oSelf.__bStopping and oConnectionFromClient.bConnected:
        if n0TotalDurationEndTime is not None:
          n0TotalDurationRemainingTimeoutInSeconds = max(0, n0TotalDurationEndTime - time.time());
          if n0TotalDurationRemainingTimeoutInSeconds == 0:
            fShowDebugOutput("Max secure connection piping time reached; disconnecting..." % oConnectionFromClient);
            break;
        else:
          n0TotalDurationRemainingTimeoutInSeconds = None;
        fShowDebugOutput("Reading request from %s..." % oConnectionFromClient);
        sWhile = "reading request from %s" % oConnectionFromClient;
        anProvidedTimeoutsInSeconds = [
            n0TimeoutInSeconds
            for n0TimeoutInSeconds in (n0TotalDurationRemainingTimeoutInSeconds, oSelf.__n0SecureConnectionPipeIdleTimeoutInSeconds)
            if n0TimeoutInSeconds is not None
        ];
        oRequest = oConnectionFromClient.foReceiveRequest(
          n0TransactionTimeoutInSeconds = min(anProvidedTimeoutsInSeconds) if len(anProvidedTimeoutsInSeconds) > 0 else None,
        );
        bEndTransaction = True;
        if oSelf.__bStopping:
          fShowDebugOutput("Stopping...");
          break;
        assert oRequest, \
            "No request!?";
        sWhile = None;
        (oResponse, bContinueHandlingRequests) = oSelf.__ftxRequestHandler(
          oHTTPServer = None, # Intercepted requests were not received by our HTTP server.
          oConnection = oConnectionFromClient,
          oRequest = oRequest,
          o0SecureConnectionInterceptedForServerURL = oServerURL
        );
        if oSelf.__bStopping:
          fShowDebugOutput("Stopping...");
          break;
        assert oResponse, \
            "No response!?";
        sWhile = "sending response to %s" % oConnectionFromClient;
        # Send the response to the client
        fShowDebugOutput("Sending response (%s) to %s..." % (oResponse, oConnectionFromClient));
        oConnectionFromClient.fSendResponse(oResponse);
        bEndTransaction = False;
        oSelf.fFireCallbacks("response sent to client", oRequest, oResponse);
        if not bContinueHandlingRequests:
          break;
    except Exception as oException:
      if sWhile is None: raise; # Exception thrown during __ftxRequestHandler call!?
      if mExceptions.cSSLException and isinstance(oException, mExceptions.cSSLException):
        fShowDebugOutput("Secure connection exception while %s: %s." % (sWhile, oException));
      elif isinstance(oException, mExceptions.cTCPIPConnectionShutdownException):
        fShowDebugOutput("Shutdown while %s." % sWhile);
      elif isinstance(oException, mExceptions.cTCPIPConnectionDisconnectedException):
        fShowDebugOutput("Disconnected while %s." % sWhile);
      else:
        raise;
    finally:
      if bEndTransaction: oConnectionFromClient.fEndTransaction();
      fShowDebugOutput("Stopped intercepting secure connection for client %s to server %s." % (oConnectionFromClient, repr(oServerURL.sbBase)));
      if oConnectionFromClient.bConnected:
        try:
          assert oConnectionFromClient.fbStartTransaction(), \
              "Cannot start a transaction on the connection from the client (%s)" % repr(oConnectionFromClient);
          try:
            oConnectionFromClient.fDisconnect();
          finally:
            oConnectionFromClient.fEndTransaction();
        except mExceptions.cTCPIPConnectionDisconnectedException as oException:
          pass;
      oSelf.__oPropertyAccessTransactionLock.fAcquire();
      try:
        oSelf.__aoSecureConnectionsFromClient.remove(oConnectionFromClient);
        oSelf.__aoSecureConnectionThreads.remove(cThread.foGetCurrent());
      finally:
        oSelf.__oPropertyAccessTransactionLock.fRelease();
      oSelf.__fCheckForTermination();
  
  @ShowDebugOutput
  def __fPipeConnection(oSelf, oConnectionFromClient, oConnectionToServer, oServerURL):
    n0TotalDurationEndTime = (
      time.time() + oSelf.__n0SecureConnectionPipeTotalDurationTimeoutInSeconds \
      if oSelf.__n0SecureConnectionPipeTotalDurationTimeoutInSeconds is not None
      else None
    );
    fShowDebugOutput("Piping secure connection for client (%s) to server (%s, url = %s)." % \
        (oConnectionFromClient, oConnectionToServer, str(oServerURL.sbBase, "ascii", "strict")));
    bClientInTransactions = False;
    bServerInTransactions = False;
    try:
      while not oSelf.__bStopping and oConnectionToServer.bConnected and oConnectionFromClient.bConnected:
        s0HandleExceptionsWhile = None; # Do not handle exceptions.
        if n0TotalDurationEndTime is not None:
          n0TotalDurationRemainingTimeoutInSeconds = max(0, n0TotalDurationEndTime - time.time());
          if n0TotalDurationRemainingTimeoutInSeconds == 0:
            fShowDebugOutput("Max secure connection piping time reached; disconnecting..." % oConnectionFromClient);
            break;
        else:
          n0TotalDurationRemainingTimeoutInSeconds = None;
        fShowDebugOutput("%s %s=waiting for data=%s %s." % (
          oConnectionFromClient,
          "<" if (oConnectionFromClient.bShouldAllowWriting and oConnectionToServer.bShouldAllowReading) else "",
          ">" if (oConnectionToServer.bShouldAllowWriting and oConnectionFromClient.bShouldAllowReading) else "",
          oConnectionToServer,
        ));
        anProvidedTimeoutsInSeconds = [
          n0TimeoutInSeconds
          for n0TimeoutInSeconds in (n0TotalDurationRemainingTimeoutInSeconds, oSelf.__n0SecureConnectionPipeIdleTimeoutInSeconds)
          if n0TimeoutInSeconds is not None
        ];
        s0HandleExceptionsWhile = "waiting for readable bytes from client or server";
        aoConnectionsWithDataToPipe = oConnectionFromClient.__class__.faoWaitUntilBytesAreAvailableForReadingAndStartTransactions(
          [oConnection for oConnection in [oConnectionFromClient, oConnectionToServer] if oConnection.bShouldAllowReading], 
          n0WaitTimeoutInSeconds = min(anProvidedTimeoutsInSeconds) if len(anProvidedTimeoutsInSeconds) > 0 else None,
        );
        s0HandleExceptionsWhile = None;
        if len(aoConnectionsWithDataToPipe) == 0:
          break;
        if n0TotalDurationEndTime is not None:
          n0TotalDurationRemainingTimeoutInSeconds = max(0, n0TotalDurationEndTime - time.time());
          if n0TotalDurationRemainingTimeoutInSeconds == 0:
            fShowDebugOutput("Max secure connection piping time reached; disconnecting..." % oConnectionFromClient);
            break;
        else:
          n0TotalDurationRemainingTimeoutInSeconds = None;
        # We need to start transactions on both connections, not just the ones with readable data.
        # We also need to reset the transaction timeout.
        bClientInTransactions = oConnectionFromClient in aoConnectionsWithDataToPipe;
        if bClientInTransactions:
          assert oConnectionFromClient.fbRestartTransaction(n0TimeoutInSeconds = n0TotalDurationRemainingTimeoutInSeconds), \
              "Cannot restart transaction!?";
        else:
          assert oConnectionFromClient.fbStartTransaction(n0TimeoutInSeconds = n0TotalDurationRemainingTimeoutInSeconds), \
              "Cannot start transaction!?";
          bClientInTransactions = True;
        bServerInTransactions = oConnectionToServer in aoConnectionsWithDataToPipe;
        if bServerInTransactions:
          assert oConnectionToServer.fbRestartTransaction(n0TimeoutInSeconds = n0TotalDurationRemainingTimeoutInSeconds), \
              "Cannot restart transaction!?";
        else:
          assert oConnectionToServer.fbStartTransaction(n0TimeoutInSeconds = n0TotalDurationRemainingTimeoutInSeconds), \
              "Cannot start transaction!?";
          bServerInTransactions = True;
        for oFromConnection in aoConnectionsWithDataToPipe:
          s0HandleExceptionsWhile = "reading bytes from %s" % ("client" if oFromConnection is oConnectionFromClient else "server");
          sBytes = oFromConnection.fsReadAvailableBytes();
          s0HandleExceptionsWhile = None;
          fShowDebugOutput("%s %s=%d bytes=%s %s." % (
            oConnectionFromClient,
            "<" if oFromConnection is oConnectionToServer else "",
            len(sBytes),
            ">" if oFromConnection is oConnectionFromClient else "",
            oConnectionToServer,
          ));
          oToConnection = oConnectionFromClient if oFromConnection is oConnectionToServer else oConnectionToServer;
          s0HandleExceptionsWhile = "writing bytes to %s" % ("client" if oToConnection is oConnectionFromClient else "server");
          oToConnection.fWriteBytes(sBytes);
          s0HandleExceptionsWhile = None;
        if bClientInTransactions:
          oConnectionFromClient.fEndTransaction();
          bClientInTransactions = False;
        if bServerInTransactions:
          oConnectionToServer.fEndTransaction();
          bServerInTransactions = False;
    except mExceptions.cTCPIPDataTimeoutException:
      if s0HandleExceptionsWhile is None: raise; # Exception thrown during __ftxRequestHandler call!?
      fShowDebugOutput("Transaction timeout while %s." % s0HandleExceptionsWhile);
    except mExceptions.cTCPIPConnectionShutdownException:
      if s0HandleExceptionsWhile is None: raise; # Exception thrown during __ftxRequestHandler call!?
      fShowDebugOutput("Shutdown while %s." % s0HandleExceptionsWhile);
    except mExceptions.cTCPIPConnectionDisconnectedException:
      if s0HandleExceptionsWhile is None: raise; # Exception thrown during __ftxRequestHandler call!?
      fShowDebugOutput("Disconnected while %s." % s0HandleExceptionsWhile);
    fShowDebugOutput("Stopped piping secure connection for client %s to server %s." % (oConnectionFromClient, repr(oServerURL.sbBase)));
    if oConnectionFromClient.bConnected:
      try:
        assert bClientInTransactions or oConnectionFromClient.fbStartTransaction(), \
            "Cannot start a transaction on the connection from the client (%s)" % repr(oConnectionFromClient);
        try:
          oConnectionFromClient.fDisconnect();
        finally:
          oConnectionFromClient.fEndTransaction();
      except mExceptions.cTCPIPConnectionDisconnectedException as oException:
        pass;
    elif bClientInTransactions:
      oConnectionFromClient.fEndTransaction();
    if oConnectionToServer.bConnected:
      try:
        assert bServerInTransactions or oConnectionToServer.fbStartTransaction(), \
            "Cannot start a transaction on the connection to the server (%s)" % repr(oConnectionToServer);
        try:
          oConnectionToServer.fDisconnect();
        finally:
          oConnectionToServer.fEndTransaction();
      except mExceptions.cTCPIPConnectionDisconnectedException as oException:
        pass;
    elif bServerInTransactions:
      oConnectionToServer.fEndTransaction();
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      oSelf.__aoSecureConnectionsFromClient.remove(oConnectionFromClient);
      oSelf.__aoSecureConnectionThreads.remove(cThread.foGetCurrent());
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    oSelf.__fCheckForTermination();
  
  def fasGetDetails(oSelf):
    # This is done without a property lock, so race-conditions exist and it
    # approximates the real values.
    if oSelf.bTerminated:
      return ["terminated"];
    uSecureConnections = len(oSelf.__aoSecureConnectionsFromClient);
    uSecureConnectionThreads = len(oSelf.__aoSecureConnectionThreads);
    return [s for s in [
      "%s => %s" % (oSelf.__oHTTPServer, oSelf.__oHTTPClient),
      "%s secure connections" % (uSecureConnections or "no"),
      "%s threads" % (uSecureConnectionThreads or "no"),
      "terminated" if oSelf.bTerminated else \
          "stopping" if oSelf.__bStopping else None,
    ] if s];
  
  def __repr__(oSelf):
    sModuleName = ".".join(oSelf.__class__.__module__.split(".")[:-1]);
    return "<%s.%s#%X|%s>" % (sModuleName, oSelf.__class__.__name__, id(oSelf), "|".join(oSelf.fasGetDetails()));
  
  def __str__(oSelf):
    return "%s#%X{%s}" % (oSelf.__class__.__name__, id(oSelf), ", ".join(oSelf.fasGetDetails()));
