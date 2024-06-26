import os, sys;

# Augment the search path to make cBugId a package and have access to its modules folder.
sMainFolderPath = os.path.dirname(os.path.abspath(__file__));
sParentFolderPath = os.path.dirname(sMainFolderPath);
sModulesFolderPath = os.path.join(sMainFolderPath, "modules");
asOriginalSysPath = sys.path[:];
sys.path = [sParentFolderPath, sModulesFolderPath] + asOriginalSysPath;

from .cCertificateStore import cCertificateStore;
from .cHTTPClientProxyServer import cHTTPClientProxyServer;
from .cURL import cURL;

oProxyServerSSLContext = None;
oProxyServerURL = cURL.foFromBytesString(b"http://localhost:8080");
oCertificateStore = cCertificateStore();
oProxyServer = cHTTPClientProxyServer(
  oProxyServerURL.sbHostname, oProxyServerURL.uPortNumber, oProxyServerSSLContext,
  oCertificateStore,
  bInterceptSSLConnections = True,
);
oProxyServer.fStart();
oProxyServer.fWait();
