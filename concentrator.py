"""
The MIT License (MIT)
Copyright © 2018 Jean-Christophe Bos & HC² (www.hc2.fr)
"""


from   XAsyncSockets      import XAsyncSocketsPool,    \
                                 XAsyncTCPServer,      \
                                 XBufferSlots,         \
                                 XAsyncUDPDatagram

from   iotSocketStruct    import IoTSocketStruct
from   iotSocketRouter    import IoTSocketRouter
from   iotSocketSession   import IoTSocketSession
from   centralHTTPRequest import CentralHTTPRequest
from   centralHTTPWebHook import CentralHTTPWebHook
from   urlUtils           import UrlUtils

from   config             import Config
from   binascii           import unhexlify
from   os                 import path
from   time               import sleep

ACL_FILENAME = 'acl.json'

def OnTCPSrvClientAccepted(xAsyncTCPServer, xAsyncTCPClient) :
    IoTSocketSession( xAsyncTCPClient = xAsyncTCPClient,
                      router          = router,
                      sslKeyFilename  = tcpSSLKeyFilename,
                      sslCrtFilename  = tcpSSLCrtFilename,
                      reqTimeout      = tcpReqTimeoutSec )

def OnTCPSrvClosed(xAsyncTCPServer, closedReason) :
    pass
 
def OnHTTPSrvClientAccepted(xAsyncTCPServer, xAsyncTCPClient) :
    CentralHTTPRequest( xAsyncTCPClient    = xAsyncTCPClient,
                        router             = router,
                        sslKeyFilename     = httpSSLKeyFilename,
                        sslCrtFilename     = httpSSLCrtFilename,
                        maxContentLength   = httpMaxContentLength,
                        maxSecWaitResponse = httpMaxSecWaitResponse )

def OnHTTPSrvClosed(xAsyncTCPServer, closedReason) :
    pass

def OnUDPSrvDataRecv(xAsyncUDPDatagram, remoteAddr, datagram) :
    token, dataFormat, formatOpt, data = IoTSocketStruct.DecodeTelemetryPacket(datagram.tobytes())
    router.RouteTelemetry(token, dataFormat, formatOpt, data)

def OnRouterGetWebHookRequest(iotSocketRouter) :
    try :
        return CentralHTTPWebHook( url                = webHookRequestUrl,
                                   pool               = xasPool,
                                   httpBufferSize     = webHookHTTPBufferSize,
                                   maxContentLength   = webHookMaxContentLength,
                                   maxSecWaitResponse = webHookMaxSecWaitResponse )
    except :
        return None

def OnRouterGetWebHookTelemetry(iotSocketRouter) :
    try :
        return CentralHTTPWebHook( url                = webHookTelemetryUrl,
                                   pool               = xasPool,
                                   httpBufferSize     = webHookHTTPBufferSize,
                                   maxContentLength   = webHookMaxContentLength,
                                   maxSecWaitResponse = webHookMaxSecWaitResponse )
    except :
        return None

def Start() :

    global cfg
    global tcpSSLKeyFilename
    global tcpSSLCrtFilename
    global tcpReqTimeoutSec
    global httpSSLKeyFilename
    global httpSSLCrtFilename
    global httpMaxContentLength
    global httpMaxSecWaitResponse
    global tcpBindAddr
    global xasTCPSrv
    global httpBindAddr
    global xasHTTPSrv
    global udpBindAddr
    global xasUDPSrv
    global webHookRequestUrl
    global webHookTelemetryUrl
    global webHookHTTPBufferSize
    global webHookMaxContentLength
    global webHookMaxSecWaitResponse
    global router
    global xasPool

    cfg = Config('config')
    if cfg.isEmpty() :
        print("Error when reading configuration file.")
        return False

    tcpSrvAddr = cfg.get('TCPServer.Addr')
    tcpSrvPort = cfg.get('TCPServer.Port')
    if not tcpSrvAddr or not tcpSrvPort :
        print("Error when reading 'TCPServer.Addr' or 'TCPServer.Port' in configuration.")
        return False
    tcpSlotsCount = cfg.get('TCPServer.SlotsCount')
    if type(tcpSlotsCount) is not int or tcpSlotsCount <= 0 :
        print("Error when reading 'TCPServer.SlotsCount' in configuration.")
        return False
    tcpSlotsSize = cfg.get('TCPServer.SlotsSize')
    if type(tcpSlotsSize) is not int or tcpSlotsSize <= 0 :
        print("Error when reading 'TCPServer.SlotsSize' in configuration.")
        return False
    tcpBacklog = cfg.get('TCPServer.Backlog')
    if type(tcpBacklog) is not int or tcpBacklog <= 0 :
        print("Error when reading 'TCPServer.Backlog' in configuration.")
        return False
    tcpSSLKeyFilename = cfg.get('TCPServer.SSLKeyFilename')
    if type(tcpSSLKeyFilename) is not str :
        print("Error when reading 'TCPServer.SSLKeyFilename' in configuration.")
        return False
    tcpSSLCrtFilename = cfg.get('TCPServer.SSLCrtFilename')
    if type(tcpSSLCrtFilename) is not str :
        print("Error when reading 'TCPServer.SSLCrtFilename' in configuration.")
        return False
    tcpReqTimeoutSec = cfg.get('TCPServer.ReqTimeoutSec')
    if type(tcpReqTimeoutSec) is not int or tcpReqTimeoutSec <= 0 :
        print("Error when reading 'TCPServer.ReqTimeoutSec' in configuration.")
        return False

    httpSrvAddr = cfg.get('HTTPServer.Addr')
    httpSrvPort = cfg.get('HTTPServer.Port')
    if not httpSrvAddr or not httpSrvPort :
        print("Error when reading 'HTTPServer.Addr' or 'HTTPServer.Port' in configuration.")
        return False
    httpSlotsCount = cfg.get('HTTPServer.SlotsCount')
    if type(httpSlotsCount) is not int or httpSlotsCount <= 0 :
        print("Error when reading 'HTTPServer.SlotsCount' in configuration.")
        return False
    httpSlotsSize = cfg.get('HTTPServer.SlotsSize')
    if type(httpSlotsSize) is not int or httpSlotsSize <= 0 :
        print("Error when reading 'HTTPServer.SlotsSize' in configuration.")
        return False
    httpBacklog = cfg.get('HTTPServer.Backlog')
    if type(httpBacklog) is not int or httpBacklog <= 0 :
        print("Error when reading 'HTTPServer.Backlog' in configuration.")
        return False
    httpSSLKeyFilename = cfg.get('HTTPServer.SSLKeyFilename')
    if type(httpSSLKeyFilename) is not str :
        print("Error when reading 'HTTPServer.SSLKeyFilename' in configuration.")
        return False
    httpSSLCrtFilename = cfg.get('HTTPServer.SSLCrtFilename')
    if type(httpSSLCrtFilename) is not str :
        print("Error when reading 'HTTPServer.SSLCrtFilename' in configuration.")
        return False
    httpMaxContentLength = cfg.get('HTTPServer.MaxContentLength')
    if type(httpMaxContentLength) is not int or httpMaxContentLength <= 0 :
        print("Error when reading 'HTTPServer.MaxContentLength' in configuration.")
        return False
    httpMaxSecWaitResponse = cfg.get('HTTPServer.MaxSecWaitResponse')
    if type(httpMaxSecWaitResponse) is not int or httpMaxSecWaitResponse <= 0 :
        print("Error when reading 'HTTPServer.MaxSecWaitResponse' in configuration.")
        return False

    udpSrvAddr = cfg.get('UDPServer.Addr')
    udpSrvPort = cfg.get('UDPServer.Port')
    if not udpSrvAddr or not udpSrvPort :
        print("Error when reading 'UDPServer.Addr' or 'UDPServer.Port' in configuration.")
        return False
    udpDatagramMaxSize = cfg.get('UDPServer.DatagramMaxSize')
    if type(udpDatagramMaxSize) is not int or udpDatagramMaxSize <= 0 :
        print("Error when reading 'UDPServer.DatagramMaxSize' in configuration.")
        return False

    poolThreadsCount = cfg.get('PoolThreadsCount')
    if type(poolThreadsCount) is not int or poolThreadsCount <= 0 :
        print("Error when reading 'PoolThreadsCount' in configuration.")
        return False

    keepSessionSec = cfg.get('KeepSessionSec')
    if type(keepSessionSec) is not int or keepSessionSec <= 0 :
        print("Error when reading 'KeepSessionSec' in configuration.")
        return False

    try :
        centralAuthKey = unhexlify(cfg.get('Central.AuthKey'))
    except :
        centralAuthKey = None
    if not centralAuthKey :
        print("Error when reading 'Central.AuthKey' in configuration.")
        return False
    if len(centralAuthKey) != 16 :
        print("Incorrect 'Central.AuthKey' in configuration.")
        return False
    webHookRequestUrl = cfg.get('Central.WebHooks.Request')
    if webHookRequestUrl is not None :
        try :
            webHookRequestUrl = UrlUtils.Url(webHookRequestUrl)
        except :
            print("Incorrect 'Central.WebHooks.Request' URL in configuration.")
            return False
    webHookTelemetryUrl = cfg.get('Central.WebHooks.Telemetry')
    if webHookTelemetryUrl is not None :
        try :
            webHookTelemetryUrl = UrlUtils.Url(webHookTelemetryUrl)
        except :
            print("Incorrect 'Central.WebHooks.Telemetry' URL in configuration.")
            return False
    webHookHTTPBufferSize = cfg.get('Central.WebHooks.HTTPBufferSize')
    if type(webHookHTTPBufferSize) is not int or webHookHTTPBufferSize <= 0 :
        print("Error when reading 'Central.WebHooks.HTTPBufferSize' in configuration.")
        return False
    webHookMaxContentLength = cfg.get('Central.WebHooks.MaxContentLength')
    if type(webHookMaxContentLength) is not int or webHookMaxContentLength <= 0 :
        print("Error when reading 'Central.WebHooks.MaxContentLength' in configuration.")
        return False
    webHookMaxSecWaitResponse = cfg.get('Central.WebHooks.MaxSecWaitResponse')
    if type(webHookMaxSecWaitResponse) is not int or webHookMaxSecWaitResponse <= 0 :
        print("Error when reading 'Central.WebHooks.MaxSecWaitResponse' in configuration.")
        return False

    xasPool = XAsyncSocketsPool()

    router  = IoTSocketRouter( aclFilename    = ACL_FILENAME,
                               centralAuthKey = centralAuthKey,
                               keepSessionSec = keepSessionSec )

    if webHookRequestUrl :
        router.OnGetWebHookRequest = OnRouterGetWebHookRequest

    if webHookTelemetryUrl :
        router.OnGetWebHookTelemetry = OnRouterGetWebHookTelemetry

    groups = cfg.get('Groups')
    if type(groups) is not dict :
        print("Error when reading 'Groups' in configuration.")
        return False
    for groupName in groups :
        if not router.AddGroup(groupName, groups[groupName]) :
            print("Error when reading group '%s' in configuration." % groupName)
            return False

    if not router.LoadACL() :
        print("Cannot read ACL file -> No ACL setted in concentrator.")

    tcpSrvBufSlots = XBufferSlots( slotsCount = tcpSlotsCount,
                                   slotsSize  = tcpSlotsSize,
                                   keepAlloc  = True )

    try :
        tcpBindAddr = (tcpSrvAddr, tcpSrvPort)
        xasTCPSrv   = XAsyncTCPServer.Create( asyncSocketsPool = xasPool,
                                              srvAddr          = tcpBindAddr,
                                              srvBacklog       = tcpBacklog,
                                              recvBufSlots     = tcpSrvBufSlots )
        xasTCPSrv.OnClientAccepted = OnTCPSrvClientAccepted
        xasTCPSrv.OnClosed         = OnTCPSrvClosed
    except :
        print("Error to bind TCP server on '%s:%s'." % tcpBindAddr)
        return False

    httpSrvBufSlots = XBufferSlots( slotsCount = httpSlotsCount,
                                    slotsSize  = httpSlotsSize,
                                    keepAlloc  = True )

    try :
        httpBindAddr = (httpSrvAddr, httpSrvPort)
        xasHTTPSrv   = XAsyncTCPServer.Create( asyncSocketsPool = xasPool,
                                               srvAddr          = httpBindAddr,
                                               srvBacklog       = httpBacklog,
                                               recvBufSlots     = httpSrvBufSlots )
        xasHTTPSrv.OnClientAccepted = OnHTTPSrvClientAccepted
        xasHTTPSrv.OnClosed         = OnHTTPSrvClosed
    except :
        print("Error to bind HTTP server on '%s:%s'." % httpBindAddr)
        return False

    try :
        udpBindAddr = (udpSrvAddr, udpSrvPort)
        xasUDPSrv   = XAsyncUDPDatagram.Create( asyncSocketsPool = xasPool,
                                                localAddr        = udpBindAddr,
                                                recvbufLen       = udpDatagramMaxSize )
        xasUDPSrv.OnDataRecv = OnUDPSrvDataRecv
    except :
        print("Error to bind UDP server on '%s:%s'." % udpBindAddr)
        return False

    xasPool.AsyncWaitEvents(threadsCount=poolThreadsCount)

    return True

print()
if Start() :
    print()
    print("IOTSOCKET CONCENTRATOR STARTED")
    print()
    try :
        aclFileTime = path.getmtime(ACL_FILENAME)
        while True :
            sleep(1)
            t = path.getmtime(ACL_FILENAME)
            if t != aclFileTime :
                aclFileTime = t
                if router.LoadACL() :
                    print("SUCCESS: NEW ACL FILE LOADED")
                else :
                    print("WARNING: CANNOT LOAD NEW ACL FILE...")
    except KeyboardInterrupt :
        print()
        print("IOTSOCKET CONCENTRATOR ENDING...")
        print()
        router.Stop()
        xasPool.StopWaitEvents()
