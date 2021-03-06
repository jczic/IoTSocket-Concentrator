"""
The MIT License (MIT)
Copyright © 2018 Jean-Christophe Bos & HC² (www.hc2.fr)
"""


from   iotSocketStruct import IoTSocketStruct
from   XAsyncSockets   import XClosedReason
from   struct          import unpack
from   secrets         import token_bytes
from   _thread         import allocate_lock
from   time            import time

class IoTSocketSession :

    IOTSOCKET_VER   = 0x01
    RECV_TIMEOUT    = 10

    def __init__(self, xAsyncTCPClient, router, sslContext, reqTimeout) :
        self._xasTCPCli            = xAsyncTCPClient
        self._router               = router
        self._sslContext           = sslContext
        self._reqTimeout           = reqTimeout
        self._uid                  = None
        self._telemetryToken       = None
        self._authenticated        = False
        self._isCentral            = False
        self._strUID               = None
        self._groupID              = None
        self._closedCode           = None
        self._requests             = { }
        self._requestsLock         = allocate_lock()
        self._xasTCPCli.OnClosed   = self._onTCPConnClosed
        self._waitInitiationReq()

    def Close(self) :
        self._xasTCPCli.Close()

    def Send(self, data, onDataSent=None, onDataSentArg=None) :
        return self._xasTCPCli.AsyncSendData(data, onDataSent, onDataSentArg)

    def _recv(self, size, onDataRecv, onDataRecvArg=None) :
        self._xasTCPCli.AsyncRecvData(size, onDataRecv, onDataRecvArg, self.RECV_TIMEOUT)

    def _onTCPConnClosed(self, xAsyncTCPClient, closedReason) :
        reason = {
            XClosedReason.ClosedByHost : 'BY HOST',
            XClosedReason.ClosedByPeer : 'BY PEER',
            XClosedReason.Timeout      : 'AFTER TIMEOUT'
        }.get(closedReason, '(ERROR)')
        if self._authenticated :
            keepSessionData = self._closedCode in [ None,
                                                    IoTSocketStruct.CLOSE_CODE_SLEEP_MODE,
                                                    IoTSocketStruct.CLOSE_CODE_FLUSH_RESS ]
            self._router.RemoveSession(self, keepSessionData)
            self._router.Log( 'SESSION %s CLOSED %s' %
                              (self._getSessionName(), reason) )
        else :
            self._router.Log( 'CONNECTION %s REFUSED (%s)' %
                              (self._xasTCPCli.CliAddr[0], reason) )

    def _waitInitiationReq(self) :
        self._recv(4, self._onInitiationReqRecv)

    def _onInitiationReqRecv(self, xAsyncTCPClient, data, arg) :
        tls, ver, opt, maxTrLen = IoTSocketStruct.DecodeInitiationReq(data)
        ok = ( ver == self.IOTSOCKET_VER and
               ( not tls or self._sslContext is not None ) )
        data = IoTSocketStruct.MakeInitiationResp( ok       = ok,
                                                   ruleType = IoTSocketStruct.INIT_NO_RULE )
        if ok :
            self.Send(data, self._onInitiationRespSent, tls)
        else :
            self.Send(data)
            self.Close()

    def _onInitiationRespSent(self, xAsyncTCPClient, arg) :
        if arg :
            try :
                self._xasTCPCli.StartSSLContext(self._sslContext, True)
            except :
                self.Close()
                return
        self._token128 = token_bytes(16)
        self.Send(self._token128)
        self._recv(48, self._onChallengeRecv)

    def _onChallengeRecv(self, xAsyncTCPClient, data, arg) :
        self._uid = data[:16].tobytes()
        hmac256   = data[16:].tobytes()
        if self._router.AuthenticateSession( self,
                                             self._token128,
                                             hmac256 ) :
            self._startSession()
        else :
            self.Close()

    def _startSession(self) :
        self._authenticated = True
        self._isCentral     = (self._uid == IoTSocketStruct.CENTRAL_EMPTY_UID)
        if not self._isCentral :
            self._strUID = IoTSocketStruct.UIDFromBin128(self._uid)
        self._router.Log( 'SESSION %s STARTED FROM %s' %
                          (self._getSessionName(), self._xasTCPCli.CliAddr[0]) )
        if not self._isCentral :
            self._groupID = self._router.GetACLAccess(self._uid)[0]
            if self._router.GetGroupOption(self._groupID, 'Telemetry') :
                expMin = self._router.GetGroupOption(self._groupID, 'TelemetryTokenExpMin')
                self._telemetryToken = self._router.GetNewTelemetryToken(self._uid, expMin)
                tr = IoTSocketStruct.MakeTelemetryTokenTR(self._telemetryToken)
                self.Send(tr)
        self._waitDataTransmission()

    def _waitDataTransmission(self) :
        self._xasTCPCli.AsyncRecvData(1, self._onDataTransmissionRecv)

    def _onDataTransmissionRecv(self, xAsyncTCPClient, data, arg) :
        if arg :
            tot = arg
            uid = data.tobytes()
        else :
            tot, rte = IoTSocketStruct.DecodeDataTRHdr(data)
            if rte :
                self._recv(16, self._onDataTransmissionRecv, tot)
                return
            uid = None
        if tot == IoTSocketStruct.TOT_ACL and self._isCentral :
            self._recv(4, self._onACLItemsCountRecv)
        elif tot == IoTSocketStruct.TOT_PING :
            self._router.Log('SESSION %s > PING RECEIVED' % self._getSessionName())
            self.Send(IoTSocketStruct.MakePongTR())
            self._waitDataTransmission()
        elif tot == IoTSocketStruct.TOT_PONG :
            self._router.Log('SESSION %s > PONG RECEIVED' % self._getSessionName())
            self._waitDataTransmission()
        elif tot == IoTSocketStruct.TOT_REQUEST :
            self._recv(5, self._onRequestRecv, (uid, ))
        elif tot == IoTSocketStruct.TOT_RESPONSE :
            self._recv(6, self._onResponseRecv, (uid, ))
        elif tot == IoTSocketStruct.TOT_CLOSE_CONN :
            self._recv(1, self._onCloseConnCodeRecv)
        else :
            self.Send(IoTSocketStruct.MakeCloseConnTR(IoTSocketStruct.CLOSE_CODE_PROTO_ERR))
            self.Close()

    def _onACLItemsCountRecv(self, xAsyncTCPClient, data, arg) :
        count = unpack('>I', data)[0]
        self._router.Log( 'SESSION %s > %s ACL SETUP RECEIVED' %
                          (self._getSessionName(), count) )
        self._router.ClearACL()
        if count > 0 :
            self._recv(48, self._onACLItemRecv, count)
        else :
            self._waitDataTransmission()

    def _onACLItemRecv(self, xAsyncTCPClient, data, arg) :
        groupID, uid, authKey = IoTSocketStruct.DecodeACLItem(data.tobytes())
        self._router.AddACLAccess(groupID, uid, authKey)
        if arg > 1 :
            self._recv(48, self._onACLItemRecv, arg-1)
        else :
            self._router.SaveACL()
            self._waitDataTransmission()

    def _onRequestRecv(self, xAsyncTCPClient, data, arg) :
        uid = arg[0]
        if len(arg) == 2 :
            trackingNbr, dataFormat, formatOpt, dataLen = arg[1]
            data = data.tobytes()
        else :
            hdr = IoTSocketStruct.DecodeRequestHdr(data.tobytes())
            trackingNbr, dataFormat, formatOpt, dataLen = hdr
            if dataLen > 0 :
                self._recv(dataLen, self._onRequestRecv, (uid, hdr))
                return
            data = b''
        if uid :
            strUID = ('{%s}' % IoTSocketStruct.UIDFromBin128(uid))
        else :
            strUID = 'CENTRAL'
        errCode = None
        with self._requestsLock :
            self._router.Log( 'SESSION %s > REQUEST TO %s RECEIVED (#%s)' %
                              (self._getSessionName(), strUID, trackingNbr) )
            if not trackingNbr in self._requests :
                if self._router.RouteRequest( fromUID     = None if self._isCentral else self._uid,
                                              toUID       = uid,
                                              trackingNbr = trackingNbr,
                                              dataFormat  = dataFormat,
                                              formatOpt   = formatOpt,
                                              data        = data ) :
                    exp = time() + self._reqTimeout
                    self._requests[trackingNbr] = (uid, exp)
                else :
                    errCode = IoTSocketStruct.RESP_CODE_ERR_NO_DEST
            else :
                self._router.Log( 'SESSION %s > TRACKING NUMBER #%s ALREADY EXISTS' %
                                  (self._getSessionName(), trackingNbr) )
                errCode = IoTSocketStruct.RESP_CODE_ERR_SAME_TRK_NBR
        if errCode :
            self.Send(IoTSocketStruct.MakeResponseErrTR(uid, trackingNbr, errCode))
        self._waitDataTransmission()

    def _onResponseRecv(self, xAsyncTCPClient, data, arg) :
        uid = arg[0]
        if len(arg) == 2 :
            trackingNbr, code, dataFormat, formatOpt, dataLen = arg[1]
            data = data.tobytes()
        else :
            hdr = IoTSocketStruct.DecodeResponseHdr(data.tobytes())
            trackingNbr, code, dataFormat, formatOpt, dataLen = hdr
            if dataLen > 0 :
                self._recv(dataLen, self._onResponseRecv, (uid, hdr))
                return
            data = b''
        if uid :
            strUID = ('{%s}' % IoTSocketStruct.UIDFromBin128(uid))
        else :
            strUID = 'CENTRAL'
        self._router.Log( 'SESSION %s > RESPONSE TO %s RECEIVED (#%s)' %
                          (self._getSessionName(), strUID, trackingNbr) )
        self._router.RouteResponse( fromUID     = None if self._isCentral else self._uid,
                                    toUID       = uid,
                                    trackingNbr = trackingNbr,
                                    code        = code,
                                    dataFormat  = dataFormat,
                                    formatOpt   = formatOpt,
                                    data        = data )
        self._waitDataTransmission()

    def _onCloseConnCodeRecv(self, xAsyncTCPClient, data, arg) :
        self._router.Log('SESSION %s > CLOSE CONNECTION CODE RECEIVED' % self._getSessionName())
        self._closedCode = data[0]
        self.Close()

    def _getSessionName(self) :
        if self._isCentral :
            return 'CENTRAL'
        else :
            return ('{%s}' % self._strUID)

    def EndTrackingRequest(self, trackingNbr) :
        with self._requestsLock :
            if trackingNbr in self._requests :
                del self._requests[trackingNbr]

    def CheckRequestsTimeout(self, nowSec) :
        if self._requests :
            with self._requestsLock :
                for trackingNbr in list(self._requests) :
                    uid, exp = self._requests[trackingNbr]
                    if nowSec >= exp :
                        del self._requests[trackingNbr]
                        self.Send( IoTSocketStruct.MakeResponseErrTR( uid,
                                                                      trackingNbr,
                                                                      IoTSocketStruct.RESP_CODE_ERR_TIMEOUT ) )
                        self._router.Log( 'SESSION %s > REQUEST TIMEOUT (#%s)' %
                                          (self._getSessionName(), trackingNbr) )

    @property
    def UID(self) :
        return self._uid

    @property
    def IsCentral(self) :
        return self._isCentral

    @property
    def TelemetryToken(self) :
        return self._telemetryToken
