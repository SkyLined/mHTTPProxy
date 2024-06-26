import re, time;

try: # mDebugOutput use is Optional
  from mDebugOutput import ShowDebugOutput, fShowDebugOutput;
except ModuleNotFoundError as oException:
  if oException.args[0] != "No module named 'mDebugOutput'":
    raise;
  ShowDebugOutput = lambda fx: fx; # NOP
  fShowDebugOutput = lambda x, s0 = None: x; # NOP

from mHTTPConnection import cHTTPResponse, cHTTPHeaders, cURL;
from mHTTPServer import cHTTPServer;
from mHTTPClient import cHTTPClient, cHTTPClientUsingProxyServer, cHTTPClientUsingAutomaticProxyServer;
from mMultiThreading import cLock, cWithCallbacks;
from mNotProvided import \
    fAssertType, \
    fbIsProvided, \
    fxGetFirstProvidedValue, \
    fxzGetFirstProvidedValueIfAny, \
    zNotProvided;
from .mExceptions import *;

# To turn access to data store in multiple variables into a single transaction, we will create locks.
# These locks should only ever be locked for a short time; if it is locked for too long, it is considered a "deadlock"
# bug, where "too long" is defined by the following value:
gnDeadlockTimeoutInSeconds = 1; # We're not doing anything time consuming, so this should suffice.
guDefaultPortNumber = 8080; # Default proxy port number

grbHostAndPortNumber = re.compile(
  rb"\A"
  rb"(" + cURL.sbHostRegExp + rb")"         # (host)
  rb"\:"                                    # ":"
  rb"(" + cURL.sbPortNumberRegExp + rb")"   # (port number)
  rb"\Z"                                    # end of string
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
  );

class cHTTPClientSideProxyServer(cWithCallbacks):
  bSSLIsSupported = cHTTPServer.bSSLIsSupported;
  u0DefaultMaxNumberOfConnectionsToChainedProxy = 10;
  n0DefaultSecureConnectionToChainedProxyTimeoutInSeconds = 5;
  
  n0DefaultSecureTimeoutInSeconds = zNotProvided; # Let mHTTPConnection pick a default.
  n0DefaultTransactionTimeoutInSeconds = 10;
  n0DefaultSecureConnectionPipeTotalDurationTimeoutInSeconds = None;
  n0DefaultSecureConnectionPipeIdleTimeoutInSeconds = 20;
  n0DefaultConnectionTerminateTimeoutInSeconds = 10;
  
  @ShowDebugOutput
  def __init__(oSelf,
    sbzHost = zNotProvided, uzPortNumber = zNotProvided,
    o0ServerSSLContext = None,
    o0zCertificateStore = zNotProvided,
    bUseChainedProxy = False,
    o0ChainedProxyURL = None,
    o0ChainedProxyHTTPClient = None,
    bVerifyCertificatesForChainedProxy = True,
    bCheckChainedProxyHost = True,
    u0zMaxNumberOfConnectionsToChainedProxy = zNotProvided,
    # Connections to proxy use nzConnectTimeoutInSeconds
    n0zSecureConnectionToChainedProxyTimeoutInSeconds = zNotProvided,
    # Connections to proxy use nzTransactionTimeoutInSeconds
    o0InterceptSSLConnectionsCertificateAuthority = None,
    n0zConnectTimeoutInSeconds = zNotProvided,
    n0zSecureTimeoutInSeconds = zNotProvided,
    n0zTransactionTimeoutInSeconds = zNotProvided,
    bVerifyCertificates = True,
    bzCheckHost = zNotProvided,
    n0zSecureConnectionPipeTotalDurationTimeoutInSeconds = zNotProvided,
    n0zSecureConnectionPipeIdleTimeoutInSeconds = zNotProvided,
    u0zMaxNumberOfConnectionsToServer = zNotProvided,
    fztxDirectRequestHandler = zNotProvided,
  ):
    oSelf.__o0InterceptSSLConnectionsCertificateAuthority = o0InterceptSSLConnectionsCertificateAuthority;
    oSelf.__n0zConnectTimeoutInSeconds = n0zConnectTimeoutInSeconds;
    oSelf.__n0zSecureTimeoutInSeconds = fxzGetFirstProvidedValueIfAny(n0zSecureTimeoutInSeconds, oSelf.n0DefaultSecureTimeoutInSeconds);
    oSelf.__n0zTransactionTimeoutInSeconds = fxzGetFirstProvidedValueIfAny(n0zTransactionTimeoutInSeconds, oSelf.n0DefaultTransactionTimeoutInSeconds);
    oSelf.__bVerifyCertificates = bVerifyCertificates;
    oSelf.__bzCheckHost = bzCheckHost;
    oSelf.__n0SecureConnectionPipeTotalDurationTimeoutInSeconds = fxGetFirstProvidedValue( \
        n0zSecureConnectionPipeTotalDurationTimeoutInSeconds, oSelf.n0DefaultSecureConnectionPipeTotalDurationTimeoutInSeconds);
    oSelf.__n0SecureConnectionPipeIdleTimeoutInSeconds = fxGetFirstProvidedValue( \
        n0zSecureConnectionPipeIdleTimeoutInSeconds, oSelf.n0DefaultSecureConnectionPipeIdleTimeoutInSeconds);
    oSelf.__fztxDirectRequestHandler = fztxDirectRequestHandler;
    
    oSelf.__oPropertyAccessTransactionLock = cLock(
      "%s.__oPropertyAccessTransactionLock" % oSelf.__class__.__name__,
      n0DeadlockTimeoutInSeconds = gnDeadlockTimeoutInSeconds
    );
    oSelf.__aoConnectionsBeingPipedFromClient = [];
    oSelf.__aoConnectionsBeingPipedToServer = [];
    
    oSelf.__bStopping = False;
    oSelf.__oTerminatedLock = cLock(
      "%s.__oTerminatedLock" % oSelf.__class__.__name__,
      bLocked = True
    );
    
    oSelf.fAddEvents(
      "connection from client received", "connection from client terminated",
      
      "direct request received from client", "direct request received and response sent to client",
      
      "server host or ip address invalid",
      
      "resolving server hostname", "resolving server hostname failed", "server hostname resolved to ip address",
      
      "connecting to server ip address", "connecting to server ip address failed",
      "connecting to server failed", "connection to server created", "connection to server terminated",
      
      "request received from client", "response sent to client",
      "request received from and response sent to client",
      
      "request sent to server", "response received from server",
      "request sent to and response received from server",
      
      "piping connection between client and server",  "intercepting and piping connection between client and server",
      
      "client terminated",
      "server terminated",
      
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
        oSelf.__oClient = o0ChainedProxyHTTPClient;
      elif o0ChainedProxyURL is not None:
        # Ideally, we want to check the caller did not provide any unapplicable arguments here, but that's a lot of
        # work, so I've pushed this out until it makes sense to add these checks
        oSelf.__oClient = cHTTPClientUsingProxyServer(
          oProxyServerURL = o0ChainedProxyURL,
          bVerifyCertificatesForProxy = bVerifyCertificatesForChainedProxy,
          bCheckProxyHost = bCheckChainedProxyHost,
          o0zCertificateStore = o0zCertificateStore,
          u0zMaxNumberOfConnectionsToProxy = fxGetFirstProvidedValue( \
              u0zMaxNumberOfConnectionsToChainedProxy, oSelf.u0DefaultMaxNumberOfConnectionsToChainedProxy),
          n0zConnectToProxyTimeoutInSeconds = n0zConnectTimeoutInSeconds,
          n0zSecureConnectionToProxyTimeoutInSeconds = fxGetFirstProvidedValue( \
              n0zSecureConnectionToChainedProxyTimeoutInSeconds, oSelf.n0DefaultSecureConnectionToChainedProxyTimeoutInSeconds),
          n0zSecureConnectionToServerTimeoutInSeconds = oSelf.__n0zSecureTimeoutInSeconds,
          n0zTransactionTimeoutInSeconds = oSelf.__n0zTransactionTimeoutInSeconds,
          bVerifyCertificates = bVerifyCertificates,
          bzCheckHost = bzCheckHost,
        );
      else:
        oSelf.__oClient = cHTTPClientUsingAutomaticProxyServer(
          o0zCertificateStore = o0zCertificateStore, 
          bVerifyCertificatesForProxy = bVerifyCertificatesForChainedProxy,
          bCheckProxyHost = bCheckChainedProxyHost,
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
          bVerifyCertificates = bVerifyCertificates,
          bzCheckHost = bzCheckHost,
        );
    else:
      assert o0ChainedProxyURL is None, \
          "bUseChainedProxy is False by o0ChainedProxyURL is %s!?" % repr(o0ChainedProxyURL);
      assert o0ChainedProxyHTTPClient is None, \
          "bUseChainedProxy is False by o0ChainedProxyHTTPClient is %s!?" % repr(o0ChainedProxyHTTPClient);
      oSelf.__oClient = cHTTPClient(
        o0zCertificateStore = o0zCertificateStore,
        u0zMaxNumberOfConnectionsToServer = u0zMaxNumberOfConnectionsToServer,
        n0zConnectTimeoutInSeconds = n0zConnectTimeoutInSeconds,
        n0zSecureTimeoutInSeconds = oSelf.__n0zSecureTimeoutInSeconds,
        n0zTransactionTimeoutInSeconds = oSelf.__n0zTransactionTimeoutInSeconds,
        bVerifyCertificates = bVerifyCertificates,
        bzCheckHost = bzCheckHost,
      );
    oSelf.__oServer = cHTTPServer(
      ftxRequestHandler = oSelf.__ftxRequestHandler,
      sbzHost = sbzHost,
      uzPortNumber = fxGetFirstProvidedValue(uzPortNumber, guDefaultPortNumber),
      o0SSLContext = o0ServerSSLContext,
    );
    
    # Forward events from client
    if isinstance(oSelf.__oClient, (cHTTPClient, cHTTPClientUsingAutomaticProxyServer)):
      # Events produced by clients that can connect directly to a HTTP server"
      oSelf.__oClient.fAddCallbacks({
        "server host invalid": lambda oClient, sbHost: oSelf.fFireCallbacks(
          "server host invalid",
          sbHost = sbHost,
        ),
        "resolving server hostname": lambda oClient, sbHostname: oSelf.fFireCallbacks(
          "resolving server hostname",
          sbHostname = sbHostname,
        ),
        "resolving server hostname failed": lambda oClient, sbHostname: oSelf.fFireCallbacks(
          "resolving server hostname failed",
          sbHostname = sbHostname,
        ),
        "server hostname resolved to ip address": lambda oClient, sbHostname, sbIPAddress, sCanonicalName: oSelf.fFireCallbacks(
          "server hostname resolved to ip address",
          sbHostname = sbHostname,
          sbIPAddress = sbIPAddress,
          sCanonicalName = sCanonicalName,
        ),
        "connecting to server ip address": lambda oClient, sbHost, sbIPAddress, uPortNumber: oSelf.fFireCallbacks(
          "connecting to server ip address",
          sbHost = sbHost,
          sbIPAddress = sbIPAddress,
          uPortNumber = uPortNumber,
        ),
        "connecting to server ip address failed": lambda oClient, oException, sbHost, sbIPAddress, uPortNumber: oSelf.fFireCallbacks(
          "connecting to server ip address failed",
          oException = oException,
          sbHost = sbHost,
          sbIPAddress = sbIPAddress,
          uPortNumber = uPortNumber,
        ),
        "connecting to server failed": lambda oClient, sbHost, uPortNumber, oException: oSelf.fFireCallbacks(
          "connecting to server failed",
          sbHost = sbHost,
          uPortNumber = uPortNumber,
          oException = oException,
        ),
        "connection to server created": lambda oClient, oConnection, sbHost: oSelf.fFireCallbacks(
          "connection to server created",
          oConnection = oConnection,
          sbHost = sbHost,
        ),
        "connection to server terminated": lambda oClient, oConnection, sbHost: oSelf.fFireCallbacks(
          "connection to server terminated",
          oConnection = oConnection,
          sbHost = sbHost,
        ),
      });
    if isinstance(oSelf.__oClient, (cHTTPClientUsingProxyServer, cHTTPClientUsingAutomaticProxyServer)):
      # Events produced by clients that can connect through a HTTP proxy:
      oSelf.__oClient.fAddCallbacks({
        "proxy host invalid": lambda oClient, sbHost: oSelf.fFireCallbacks(
          "proxy host invalid",
          sbHost = sbHost,
        ),
        "resolving proxy hostname": lambda oClient, sbHostname: oSelf.fFireCallbacks(
          "resolving proxy hostname",
          sbHostname = sbHostname,
        ),
        "resolving proxy hostname failed": lambda oClient, sbHostname: oSelf.fFireCallbacks(
          "resolving proxy hostname failed",
          sbHostname = sbHostname,
        ),
        "proxy hostname resolved to ip address": lambda oClient, sbHostname, sbIPAddress, sCanonicalName: oSelf.fFireCallbacks(
          "proxy hostname resolved to ip address",
          sbHostname = sbHostname,
          sbIPAddress = sbIPAddress,
          sCanonicalName = sCanonicalName,
        ),
        "connecting to proxy ip address": lambda oClient, oProxyServerURL, sbIPAddress: oSelf.fFireCallbacks(
          "connecting to proxy ip address",
          oProxyServerURL = oProxyServerURL,
          sbIPAddress = sbIPAddress,
        ),
        "connecting to proxy ip address failed": lambda oClient, oException, oProxyServerURL, sbIPAddress: oSelf.fFireCallbacks(
          "connecting to proxy ip address failed",
          oException = oException,
          oProxyServerURL = oProxyServerURL,
          sbIPAddress = sbIPAddress,
        ),
        "connecting to proxy failed": lambda oClient, oConnection, oProxyServerURL: oSelf.fFireCallbacks(
          "connecting to proxy failed",
          oConnection = oConnection,
          oProxyServerURL = oProxyServerURL,
        ),
        "connection to proxy created": lambda oClient, oConnection, oProxyServerURL: oSelf.fFireCallbacks(
          "connection to proxy created",
          oClient = oClient,
          oConnection = oConnection,
          oProxyServerURL = oProxyServerURL,
        ),
        "secure connection to server through proxy created": lambda oClient, oConnection, oProxyServerURL, oServerURL: oSelf.fFireCallbacks(
          "secure connection to server through proxy created",
          oConnection = oConnection,
          oProxyServerURL = oProxyServerURL,
          oServerURL = oServerURL,
        ),
        "secure connection to server through proxy terminated": lambda oClient, oConnection, oProxyServerURL, oServerURL: oSelf.fFireCallbacks(
          "secure connection to server through proxy terminated",
          oConnection = oConnection,
          oProxyServerURL = oProxyServerURL,
          oServerURL = oServerURL,
        ),
        "connection to proxy terminated": lambda oClient, oConnection, oProxyServerURL: oSelf.fFireCallbacks(
          "connection to proxy terminated",
          oConnection = oConnection,
          oProxyServerURL = oProxyServerURL,
        ),
      });
    # Events produced by both direct and proxy clients:
    oSelf.__oClient.fAddCallbacks({
      "request sent": lambda oServer, oConnection, oRequest: oSelf.fFireCallbacks(
        "request sent to server",
        oConnection = oConnection,
        oRequest = oRequest,
      ),
      "response received": lambda oServer, oConnection, oResponse: oSelf.fFireCallbacks(
        "response received from server",
        oConnection = oConnection,
        oResponse = oResponse,
      ),
      "request sent and response received": lambda oServer, oConnection, oRequest, oResponse: oSelf.fFireCallbacks(
        "request sent to and response received from server",
        oConnection = oConnection,
        oRequest = oRequest,
        oResponse = oResponse,
      ),
      "terminated": oSelf.__fHandleTerminatedCallbackFromClient,
    });
    # Forward events from server
    oSelf.__oServer.fAddCallbacks({
      "connection from client received": lambda oServer, oConnection: oSelf.fFireCallbacks(
        "connection from client received",
        oConnection = oConnection,
      ),
      "request received": lambda oServer, oConnection, oRequest: oSelf.fFireCallbacks(
        "request received from client",
        oConnection = oConnection,
        oRequest = oRequest,
      ),
      "response sent": lambda oServer, oConnection, oResponse: oSelf.fFireCallbacks(
        "response sent to client",
        oConnection = oConnection,
        oResponse = oResponse,
      ),
      "request received and response sent": lambda oServer, oConnection, oRequest, oResponse: oSelf.fFireCallbacks(
        "request received from and response sent to client",
        oConnection = oConnection,
        oRequest = oRequest,
        oResponse = oResponse,
      ),
      "connection from client terminated": lambda oServer, oConnection: oSelf.fFireCallbacks(
        "connection from client terminated",
        oConnection = oConnection
      ),
      "terminated": oSelf.__fHandleTerminatedCallbackFromServer,
    });
  
  def foGetResponseForException(oSelf, oException, sbHTTPVersion):
    if isinstance(oException, (oSelf.cTCPIPDNSNameCannotBeResolvedException, oSelf.cTCPIPInvalidAddressException)):
      return foGetErrorResponse(sbHTTPVersion, 400, b"The server cannot be found.");
    if isinstance(oException, oSelf.cTCPIPConnectTimeoutException):
      return foGetErrorResponse(sbHTTPVersion, 504, b"Connecting to the server timed out.");
    if isinstance(oException, oSelf.cTCPIPDataTimeoutException):
      return foGetErrorResponse(sbHTTPVersion, 504, b"The server did not respond before the request timed out.");
    if isinstance(oException, oSelf.cTCPIPConnectionRefusedException):
      return foGetErrorResponse(sbHTTPVersion, 502, b"The server did not accept our connection.");
    if isinstance(oException, (oSelf.cTCPIPConnectionShutdownException, oSelf.cTCPIPConnectionDisconnectedException)):
      return foGetErrorResponse(sbHTTPVersion, 502, b"The server disconnected before sending a response.");
    if isinstance(oException, oSelf.cHTTPInvalidMessageException):
      return foGetErrorResponse(sbHTTPVersion, 502, b"The server send an invalid HTTP response.");
    if oSelf.bSSLIsSupported and isinstance(oException, oSelf.cSSLSecureTimeoutException):
      return foGetErrorResponse(sbHTTPVersion, 504, b"The connection to the server could not be secured before the request timed out.");
    if oSelf.bSSLIsSupported and isinstance(oException, (oSelf.cSSLSecureHandshakeException, oSelf.cSSLIncorrectHostException)):
      return foGetErrorResponse(sbHTTPVersion, 504, b"The connection to the server could not be secured.");
    raise;
  
  @ShowDebugOutput
  def __fHandleTerminatedCallbackFromServer(oSelf, oServer):
    assert oSelf.__bStopping, \
        "HTTP server terminated unexpectedly";
    oSelf.fFireCallbacks("server terminated", oServer);
    oSelf.__fCheckForTermination();
  
  @ShowDebugOutput
  def __fHandleTerminatedCallbackFromClient(oSelf, oClient):
    assert oSelf.__bStopping, \
        "HTTP client terminated unexpectedly";
    oSelf.fFireCallbacks("client terminated", oClient);
    oSelf.__fCheckForTermination();
  
  @ShowDebugOutput
  def __fCheckForTermination(oSelf):
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      if oSelf.bTerminated:
        return fShowDebugOutput("Already terminated.");
      if not oSelf.__oServer.bTerminated:
        return fShowDebugOutput("Not terminated: server still running.");
      if not oSelf.__oClient.bTerminated:
        return fShowDebugOutput("Not terminated: client still running.");
      if oSelf.__aoConnectionsBeingPipedFromClient:
        return fShowDebugOutput("Not terminated: %d open secure connections from clients." % len(oSelf.__aoConnectionsBeingPipedFromClient));
      if oSelf.__aoConnectionsBeingPipedToServer:
        return fShowDebugOutput("Not terminated: %d open secure connections to servers." % len(oSelf.__aoConnectionsBeingPipedToServer));
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
    return oSelf.__oServer.sbAddress;
  @property
  def bSecure(oSelf):
    return oSelf.__oServer.bSecure;
  @property
  def oURL(oSelf):
    return oSelf.__oServer.oURL;
  
  @ShowDebugOutput
  def fStop(oSelf):
    oSelf.__bStopping = True;
    # Stop accepting new connections
    fShowDebugOutput("Stopping HTTP server...");
    oSelf.__oServer.fStop();
    
    # Stop all piped secure connections. This must be done before stopping the client
    # as these connections were created by the client and it won't stop until all of
    # these connections are stopped. If we want the client to stop these connections
    # must be stopped first.
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      aoConnectionsBeingPiped = oSelf.__aoConnectionsBeingPipedFromClient + oSelf.__aoConnectionsBeingPipedToServer;
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    for oSecureConnection in aoConnectionsBeingPiped:
      fShowDebugOutput("Stopping secure connection %s..." % oSecureConnection);
      oSecureConnection.fStop();
    
    # Stop the client
    fShowDebugOutput("Stopping HTTP client...");
    oSelf.__oClient.fStop();
  
  @ShowDebugOutput
  def fTerminate(oSelf):
    if oSelf.bTerminated:
      fShowDebugOutput("Already terminated.");
      return True;
    # Prevent any new connections from being accepted.
    oSelf.__bStopping = True;
    fShowDebugOutput("Terminating HTTP server...");
    oSelf.__oServer.fTerminate();

    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      aoConnectionsBeingPiped = oSelf.__aoConnectionsBeingPipedFromClient + oSelf.__aoConnectionsBeingPipedToServer;
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    for oSecureConnection in aoConnectionsBeingPiped:
      fShowDebugOutput("Terminating secure connection %s..." % oSecureConnection);
      oSecureConnection.fTerminate();

    fShowDebugOutput("Terminating HTTP client...");
    oSelf.__oClient.fTerminate();
  
  @ShowDebugOutput
  def fWait(oSelf):
    # We could just wait for the termined lock, but while debugging, we may want
    # to know exactly what it is we're waiting for:
    if oSelf.__oTerminatedLock.bLocked:
      fShowDebugOutput("Waiting for HTTP server...");
      oSelf.__oServer.fWait();
      
      oSelf.__oPropertyAccessTransactionLock.fAcquire();
      try:
        aoConnectionsBeingPiped = oSelf.__aoConnectionsBeingPipedFromClient + oSelf.__aoConnectionsBeingPipedToServer;
      finally:
        oSelf.__oPropertyAccessTransactionLock.fRelease();
      for oSecureConnection in aoConnectionsBeingPiped:
        fShowDebugOutput("Waiting for secure connection %s..." % oSecureConnection);
        oSecureConnection.fWait();

      fShowDebugOutput("Waiting for HTTP client...");
      oSelf.__oClient.fWait();

  @ShowDebugOutput
  def fbWait(oSelf, nTimeoutInSeconds):
    # We could just wait for the termined lock, but while debugging, we may want
    # to know exactly what it is we're waiting for:
    if oSelf.__oTerminatedLock.bLocked:
      nEndTime = time.time() + nTimeoutInSeconds;
      fShowDebugOutput("Waiting for HTTP server...");
      if not oSelf.__oServer.fbWait(nTimeoutInSeconds):
        fShowDebugOutput("Timeout.");
        return False;
      
      oSelf.__oPropertyAccessTransactionLock.fAcquire();
      try:
        aoConnectionsBeingPiped = oSelf.__aoConnectionsBeingPipedFromClient + oSelf.__aoConnectionsBeingPipedToServer;
      finally:
        oSelf.__oPropertyAccessTransactionLock.fRelease();
      for oSecureConnection in aoConnectionsBeingPiped:
        fShowDebugOutput("Waiting for secure connection %s..." % oSecureConnection);
        nRemainingTimeoutInSeconds = max(0, nEndTime - time.time());
        if not oSecureConnection.fbWait(nRemainingTimeoutInSeconds):
          fShowDebugOutput("Timeout.");
          return False;

      fShowDebugOutput("Waiting for HTTP client...");
      nRemainingTimeoutInSeconds = max(0, nEndTime - time.time());
      if not oSelf.__oClient.fbWait(nRemainingTimeoutInSeconds):
        fShowDebugOutput("Timeout.");
        return False;
      
    return True;
  
  @ShowDebugOutput
  def __ftxRequestHandler(oSelf, oServer, oConnection, oRequest, o0SecureConnectionInterceptedForServerURL = None):
    # Return (o0Respone, bCloseConnection, f0NextConnectionHandler)
    
    # Detect and handle CONNECT requests:
    t0xResult = oSelf.__f0txHandleConnectRequest(oConnection, oRequest);
    if t0xResult:
      return t0xResult;
    # Detect and handle direct requests from a browser, as if this is a server:
    try:
      oURL = cURL.foFromBytesString(oRequest.sbURL);
    except cURL.cHTTPInvalidURLException:
      if oRequest.sbURL.split(b"://")[0] in [b"http", b"https"]:
        fShowDebugOutput("HTTP request URL (%s) is not valid." % repr(oRequest.sbURL));
        oResponse = foGetErrorResponse(oRequest.sbVersion, 400, b"The requested URL was not valid.");
        return (
          oResponse,
          oRequest.bIndicatesConnectionShouldBeClosed,
          None, # No next connection handler
        );
      oSelf.fFireCallbacks("direct request received from client", oConnection, oRequest);
      if fbIsProvided(oSelf.__fztxDirectRequestHandler):
        (oResponse, f0NextConnectionHandler) = oSelf.__fztxDirectRequestHandler(oSelf, oConnection, oRequest);
      else:
        fShowDebugOutput("HTTP request URL (%s) suggest request was meant for a server, not a proxy." % repr(oRequest.sbURL));
        oResponse = foGetErrorResponse(oRequest.sbVersion, 400, b"This is a HTTP proxy, not a HTTP server.");
        f0NextConnectionHandler = None;
      oSelf.fFireCallbacks("direct request received and response sent to client", oConnection, oRequest, oResponse);
      return (
        oResponse,
        oRequest.bIndicatesConnectionShouldBeClosed,
        f0NextConnectionHandler,
      );
    ### Sanity checks ##########################################################
    if oRequest.sbMethod.upper() not in [b"CONNECT", b"GET", b"HEAD", b"POST", b"PUT", b"DELETE", b"OPTIONS", b"TRACE", b"PATCH"]:
      fShowDebugOutput("HTTP request method (%s) is not valid." % repr(oRequest.sbMethod));
      oResponse = foGetErrorResponse(oRequest.sbVersion, 400, b"The request method was not valid.");
      return (
        oResponse,
        oRequest.bIndicatesConnectionShouldBeClosed,
        None, # No next connection handler
      );
    if o0SecureConnectionInterceptedForServerURL is not None:
      # This request was made to a connection we are intercepting after the client send a HTTP CONNECT request.
      # The URL should be relative:
      if oRequest.sbURL[:1] != b"/":
        fShowDebugOutput("HTTP request URL (%s) does not start with '/'." % repr(oRequest.sbURL));
        oResponse = foGetErrorResponse(oRequest.sbVersion, 400, b"The requested URL was not valid.");
        return (
          oResponse,
          oRequest.bIndicatesConnectionShouldBeClosed,
          None, # No next connection handler
        );
      oURL = o0SecureConnectionInterceptedForServerURL.foFromRelativeBytesString(oRequest.sbURL);
    o0Response = oSelf.__fo0GetResponseForInvalidProxyHeaderInRequest(oRequest)
    if o0Response:
      fShowDebugOutput("Invalid proxy header.");
      return (
        o0Response,
        oRequest.bIndicatesConnectionShouldBeClosed,
        None, # No next connection handler
      );
    oHeaders = oRequest.oHeaders.foClone();
    # This client does not decide how we handle our connection to the server, so we will overwrite any "Connection"
    # header copied from the request to the proxy with the value we want for the request to the server:
    oHeaders.fbReplaceHeadersForNameAndValue(b"Connection", b"Keep-Alive");
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
      o0Response = oSelf.__oClient.fo0GetResponseForURL(
        oURL = oURL,
        sbzMethod = oRequest.sbMethod,
        o0zHeaders = oHeaders,
        sb0Body = oRequest.sb0Body, # oRequest.sb0Body is the raw data, so this also handles Chunked requests.
      );
    except Exception as oException:
      oResponse = oSelf.foGetResponseForException(oException, oRequest.sbVersion);
    else:
      if oSelf.__bStopping:
        fShowDebugOutput("Stopping.");
        return (
          None, # No response
          True, # Close connection
          None, # No next connection handler
        );
      assert o0Response, \
          "Expected a response but got %s" % repr(o0Response);
      oResponse = o0Response;
    return (
      oResponse,
      oRequest.bIndicatesConnectionShouldBeClosed,
      None, # No next connection handler
    );
  
  @ShowDebugOutput
  def __fo0GetResponseForInvalidProxyHeaderInRequest(oSelf, oRequest):
    if oRequest.oHeaders.fo0GetUniqueHeaderForName(b"Proxy-Authenticate"):
      oResponse = foGetErrorResponse(oRequest.sbVersion, 400, b"This proxy does not require authentication.");
      return oResponse;
    if oRequest.oHeaders.fo0GetUniqueHeaderForName(b"Proxy-Authorization"):
      oResponse = foGetErrorResponse(oRequest.sbVersion, 400, b"This proxy does not require authorization.");
      return oResponse;
    fShowDebugOutput("Request does not have an invalid proxy header");
    return None;
  
  @ShowDebugOutput
  def __f0txHandleConnectRequest(oSelf, oConnectionFromClient, oRequest):
    if oRequest.sbMethod.upper() != b"CONNECT":
      return None;
    
    oHostAndPortNumberMatch = grbHostAndPortNumber.match(oRequest.sbURL);
    if not oHostAndPortNumberMatch:
      fShowDebugOutput("HTTP request URL (%s) does not match 'host:port'." % repr(oRequest.sbURL));
      return (
        foGetErrorResponse(oRequest.sbVersion, 400, b"The request does not provide a valid host:port."),
        oRequest.bIndicatesConnectionShouldBeClosed,
        None, # Allow the server to continue handling requests.
      );
    
    (sbHost, sbPortNumber) = oHostAndPortNumberMatch.groups();
    uPortNumber = int(sbPortNumber);

    oServerURL = cURL.foFromBytesString(b"https://%s:%d" % (sbHost, uPortNumber));
    bInterceptTraffic = oSelf.__o0InterceptSSLConnectionsCertificateAuthority;
    fShowDebugOutput("Connecting to server %s on behalf of the client." % repr(oServerURL));
    try:
      o0ConnectionToServer = oSelf.__oClient.fo0GetConnectionAndStartTransactionForURL(
        oServerURL,
        bSecureConnection = bInterceptTraffic,
      );
    except Exception as oException:
      return (
        oSelf.foGetResponseForException(oException, oRequest.sbVersion),
        oRequest.bIndicatesConnectionShouldBeClosed,
        None, # Allow the server to continue handling requests.
      );
    if o0ConnectionToServer is None:
      # This is probably because we are stopping.
      return (
        foGetErrorResponse(oRequest.sbVersion, 500, b"Could not connect to server."),
        oRequest.bIndicatesConnectionShouldBeClosed,
        None, # Allow the server to continue handling requests.
      );
    oConnectionToServer = o0ConnectionToServer;
    oConnectionToServer.fEndTransaction(); # We do not need a transaction yet
    oSelf.__oPropertyAccessTransactionLock.fAcquire();
    try:
      oSelf.__aoConnectionsBeingPipedFromClient.append(oConnectionFromClient);
      oSelf.__aoConnectionsBeingPipedToServer.append(o0ConnectionToServer);
    finally:
      oSelf.__oPropertyAccessTransactionLock.fRelease();
    # Once we are done piping requests, we can forget about the connections:
    def fCleanupAfterPipingConnection():
      fShowDebugOutput("Cleanup after piping connection to server %s." % repr(oServerURL));
      # Disconnect once we're done piping connections.
      for oConnection in (oConnectionToServer, oConnectionFromClient):
        try:
          oConnection.fStartTransaction();
          try:
            oConnection.fDisconnect();
          finally:
            oConnection.fEndTransaction();
        except oSelf.cTCPIPConnectionDisconnectedException:
          pass;
      # Remove these connections from the list of 
      oSelf.__oPropertyAccessTransactionLock.fAcquire();
      try:
        oSelf.__aoConnectionsBeingPipedToServer.remove(oConnectionToServer);
        oSelf.__aoConnectionsBeingPipedFromClient.remove(oConnectionFromClient);
      finally:
        oSelf.__oPropertyAccessTransactionLock.fRelease();
      oSelf.__fCheckForTermination();
    if bInterceptTraffic:
      # We will be intercepting the requests, so we won't make a connection to the server immediately. We will
      # return a "200 Ok" response and a function that will handle the connection, but we will not simply pipe
      # the data between client and server. Instead we will negotiate SSL with the client using a wildcard
      # certificate and create a secure connection to the server ourselves. We will then wait for requests,
      # which we receive decrypted and forward them re-encrypted to the server, then receive the decrypted
      # response and forward it encrypted to the client.
      fNextConnectionHandler = lambda oConnectionFromClient: (
        oSelf.__fInterceptAndPipeConnection(
          oConnectionFromClient,
          oConnectionToServer,
          oServerURL,
        ),
        fCleanupAfterPipingConnection(),
      );
    else:
      # If we are not intercepting SSL connections, we will try to connect to the server. If this succeeds we will
      # return a "200 OK" response and a function that that will pipe data back and forth between the client and
      # server. This traffic is encrypted, and we cannot decode it. We will ask our HTTP client to set up this
      # connection, because the client may be using a proxy, so we cannot connect directly ourselves.
      # Create a thread that will pipe data back and forth between the client and server
      fNextConnectionHandler = lambda oConnectionFromClient: (
        oSelf.__fPipeConnection(
          oConnectionFromClient,
          oConnectionToServer,
          oServerURL
        ),
        fCleanupAfterPipingConnection(),
      );
    fShowDebugOutput("Creating HTTP 200 Ok response for CONNECT %s request." % repr(oServerURL));
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
    );
    return (
      oResponse,
      False, # don't close connection
      fNextConnectionHandler,
    );
  
  @ShowDebugOutput
  def __fInterceptAndPipeConnection(oSelf, oConnectionFromClient, oConnectionToServer, oServerURL):
    n0TotalDurationEndTime = (
      time.time() + oSelf.__n0SecureConnectionPipeTotalDurationTimeoutInSeconds
      if oSelf.__n0SecureConnectionPipeTotalDurationTimeoutInSeconds is not None
      else None
    );
    # When intercepting a supposedly secure connection, we will wait for the client to make requests through the
    # connection, forward it to the server to get a response using the same code as the normal proxy, and then
    # send the response back to the client.
    fShowDebugOutput("Intercepting secure connection for client %s to server %s." % (oConnectionFromClient, repr(oServerURL.sbBase)));
    fShowDebugOutput("Generating SSL certificate for %s..." % repr(oServerURL.sbHost));
    oSSLContext = oSelf.__o0InterceptSSLConnectionsCertificateAuthority.foGenerateServersideSSLContextForHost(
      oServerURL.sbHost,
    );
    try:
      fShowDebugOutput("Negotiating security for %s..." % oConnectionFromClient);
      sWhile = "Negotiating security for %s" % oConnectionFromClient;
      oConnectionFromClient.fSecure(
        oSSLContext,
        bzCheckHost = oSelf.__bzCheckHost,
        n0zTimeoutInSeconds = oSelf.__n0SecureConnectionPipeTotalDurationTimeoutInSeconds,
      );
      oSelf.fFireCallbacks(
        "intercepting and piping connection between client and server",
        oConnectionFromClient = oConnectionFromClient,
        oServerURL = oServerURL,
      );
      while not oSelf.__bStopping and oConnectionFromClient.bConnected:
        if n0TotalDurationEndTime is not None:
          n0TotalDurationRemainingTimeoutInSeconds = max(0, n0TotalDurationEndTime - time.time());
          if n0TotalDurationRemainingTimeoutInSeconds == 0:
            fShowDebugOutput("Max secure connection piping time reached; disconnecting..." % oConnectionFromClient);
            break;
        else:
          n0TotalDurationRemainingTimeoutInSeconds = None;
        # Receive the request from the client
        fShowDebugOutput("Receive request from %s..." % oConnectionFromClient);
        anProvidedTimeoutsInSeconds = [
            n0TimeoutInSeconds
            for n0TimeoutInSeconds in (n0TotalDurationRemainingTimeoutInSeconds, oSelf.__n0SecureConnectionPipeIdleTimeoutInSeconds)
            if n0TimeoutInSeconds is not None
        ];
        oConnectionFromClient.fStartTransaction(
          n0TimeoutInSeconds = max(0, min(anProvidedTimeoutsInSeconds)) if len(anProvidedTimeoutsInSeconds) > 0 else None,
        );
        try:
          try:
            oRequest = oConnectionFromClient.foReceiveRequest();
          except oConnectionFromClient.cTCPIPDataTimeoutException:
            break;
          if oSelf.__bStopping:
            fShowDebugOutput("Stopping...");
            break;
          # Send the request to the server - no timeout: we want to behave exactly like
          # the server.
          oConnectionToServer.fStartTransaction();
          try:
            fShowDebugOutput("Sending request (%s) to %s..." % (oRequest, oConnectionToServer));
            oConnectionToServer.fSendRequest(oRequest);
            if oSelf.__bStopping:
              fShowDebugOutput("Stopping...");
              break;
            # Receive the response from the client
            fShowDebugOutput("Receive response from %s..." % oConnectionToServer);
            oResponse = oConnectionToServer.foReceiveResponse();
            if oSelf.__bStopping:
              fShowDebugOutput("Stopping...");
              break;
          finally:
            oConnectionToServer.fEndTransaction();
          # Send the response to the client
          fShowDebugOutput("Sending response (%s) to %s..." % (oResponse, oConnectionFromClient));
          oConnectionFromClient.fSendResponse(oResponse);
        finally:
          oConnectionFromClient.fEndTransaction();
        oSelf.fFireCallbacks("response sent to client", oRequest, oResponse);
    except Exception as oException:
      if sWhile is None: raise; # Exception thrown during __ftxRequestHandler call!?
      if oSelf.bSSLIsSupported and isinstance(oException, oSelf.cSSLException):
        fShowDebugOutput("Secure connection exception while %s: %s." % (sWhile, oException));
      elif isinstance(oException, oSelf.cTCPIPConnectionShutdownException):
        fShowDebugOutput("Shutdown while %s." % sWhile);
      elif isinstance(oException, oSelf.cTCPIPConnectionDisconnectedException):
        fShowDebugOutput("Disconnected while %s." % sWhile);
      else:
        raise;
    finally:
      fShowDebugOutput("Stopped intercepting secure connection for client %s to server %s." % (oConnectionFromClient, repr(oServerURL.sbBase)));
  
  @ShowDebugOutput
  def __fPipeConnection(oSelf, oConnectionFromClient, oConnectionToServer, oServerURL):
    assert not oConnectionFromClient.bInTransaction, \
        "oConnectionFromClient is in a transaction";
    assert not oConnectionToServer.bInTransaction, \
        "oConnectionToServer is in a transaction";
    oSelf.fFireCallbacks(
      "piping connection between client and server",
      oConnectionFromClient = oConnectionFromClient,
      oConnectionToServer = oConnectionToServer,
      oServerURL = oServerURL,
    );
    n0TotalDurationEndTime = (
      time.time() + oSelf.__n0SecureConnectionPipeTotalDurationTimeoutInSeconds \
      if oSelf.__n0SecureConnectionPipeTotalDurationTimeoutInSeconds is not None
      else None
    );
    fShowDebugOutput("Piping secure connection for client (%s) to server (%s, url = %s)." % \
        (oConnectionFromClient, oConnectionToServer, str(oServerURL.sbBase, "ascii", "strict")));
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
          n0WaitTimeoutInSeconds = max(0, min(anProvidedTimeoutsInSeconds)) if len(anProvidedTimeoutsInSeconds) > 0 else None,
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
        s0HandleExceptionsWhile = "starting a transaction on the connection from the client";
        if oConnectionFromClient in aoConnectionsWithDataToPipe:
          oConnectionFromClient.fRestartTransaction(n0TimeoutInSeconds = n0TotalDurationRemainingTimeoutInSeconds);
        else:
          oConnectionFromClient.fStartTransaction(n0TimeoutInSeconds = n0TotalDurationRemainingTimeoutInSeconds);
        s0HandleExceptionsWhile = None;
        try:
          s0HandleExceptionsWhile = "starting a transaction on the connection to the server";
          if oConnectionToServer in aoConnectionsWithDataToPipe:
            oConnectionToServer.fRestartTransaction(n0TimeoutInSeconds = n0TotalDurationRemainingTimeoutInSeconds);
          else:
            oConnectionToServer.fStartTransaction(n0TimeoutInSeconds = n0TotalDurationRemainingTimeoutInSeconds);
          s0HandleExceptionsWhile = None;
          try:
            for oFromConnection in aoConnectionsWithDataToPipe:
              s0HandleExceptionsWhile = "reading bytes from %s" % ("client" if oFromConnection is oConnectionFromClient else "server");
              sbBytes = oFromConnection.fsbReadAvailableBytes();
              s0HandleExceptionsWhile = None;
              fShowDebugOutput("%s %s=%d bytes=%s %s." % (
                oConnectionFromClient,
                "<" if oFromConnection is oConnectionToServer else "",
                len(sbBytes),
                ">" if oFromConnection is oConnectionFromClient else "",
                oConnectionToServer,
              ));
              oToConnection = oConnectionFromClient if oFromConnection is oConnectionToServer else oConnectionToServer;
              s0HandleExceptionsWhile = "writing bytes to %s" % ("client" if oToConnection is oConnectionFromClient else "server");
              oToConnection.fWriteBytes(sbBytes);
              s0HandleExceptionsWhile = None;
          finally:
            oConnectionToServer.fEndTransaction();
        finally:
          oConnectionFromClient.fEndTransaction();
    except oSelf.cTCPIPDataTimeoutException:
      if s0HandleExceptionsWhile is None: raise; # Exception thrown during __ftxRequestHandler call!?
      fShowDebugOutput("Transaction timeout while %s." % s0HandleExceptionsWhile);
    except oSelf.cTCPIPConnectionShutdownException:
      if s0HandleExceptionsWhile is None: raise; # Exception thrown during __ftxRequestHandler call!?
      fShowDebugOutput("Shutdown while %s." % s0HandleExceptionsWhile);
    except oSelf.cTCPIPConnectionDisconnectedException:
      if s0HandleExceptionsWhile is None: raise; # Exception thrown during __ftxRequestHandler call!?
      fShowDebugOutput("Disconnected while %s." % s0HandleExceptionsWhile);
    finally:
      fShowDebugOutput("Stopped piping secure connection for client %s to server %s." % (oConnectionFromClient, repr(oServerURL.sbBase)));
  
  def fasGetDetails(oSelf):
    # This is done without a property lock, so race-conditions exist and it
    # approximates the real values.
    if oSelf.bTerminated:
      return ["terminated"];
    uConnectionsBeingPiped = len(oSelf.__aoConnectionsBeingPipedFromClient);
    return [s for s in [
      "%s => %s" % (oSelf.__oServer, oSelf.__oClient),
      "%s piped secure connections" % (uConnectionsBeingPiped or "no"),
      "terminated" if oSelf.bTerminated else \
          "stopping" if oSelf.__bStopping else None,
    ] if s];
  
  def __repr__(oSelf):
    sModuleName = ".".join(oSelf.__class__.__module__.split(".")[:-1]);
    return "<%s.%s#%X|%s>" % (sModuleName, oSelf.__class__.__name__, id(oSelf), "|".join(oSelf.fasGetDetails()));
  
  def __str__(oSelf):
    return "%s#%X{%s}" % (oSelf.__class__.__name__, id(oSelf), ", ".join(oSelf.fasGetDetails()));

for cException in acExceptions:
  setattr(cHTTPClientSideProxyServer, cException.__name__, cException);
