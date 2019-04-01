
from   XAsyncSockets   import XAsyncSocketsPool,    \
                              XAsyncTCPClient,      \
                              XClosedReason,        \
                              XAsyncUDPDatagram

from   iotSocketStruct import IoTSocketStruct

from   struct          import pack, unpack
import hmac
import hashlib
import time

class IoTSocketSession :

    IOTSOCKET_VER   = 0x01
    MAX_TR_LEN      = 2*1024
    RECV_TIMEOUT    = 7

    def __init__(self, xAsyncTCPClient) :
        self._xasTCPCli = xAsyncTCPClient
        self._doInitiationReq()

    def Close(self) :
        self._xasTCPCli.Close()

    def _send(self, data) :
        self._xasTCPCli.AsyncSendData(data)

    def _recv(self, size, onDataRecv, onDataRecvArg=None) :
        self._xasTCPCli.AsyncRecvData(size, onDataRecv, onDataRecvArg, self.RECV_TIMEOUT)

    def _doInitiationReq(self) :
        data = IoTSocketStruct.MakeInitiationReq( tls      = True,
                                                  ver      = self.IOTSOCKET_VER,
                                                  opt      = 0x00,
                                                  maxTrLen = self.MAX_TR_LEN )
        self._send(data)
        self._recv(2, self._onInitiationRespRecv)

    def _onInitiationRespRecv(self, xAsyncTCPClient, data, arg) :
        ok, ruleType, ruleFlags = IoTSocketStruct.DecodeInitiationResp(data)
        if ok and ruleType == IoTSocketStruct.INIT_NO_RULE :
            if self._xasTCPCli.StartSSL() :
                self._recv(16, self._onChallengeRecv)
                return
        self.Close()

    def _onChallengeRecv(self, xAsyncTCPClient, data, arg) :
        #uid = IoTSocketStruct.CENTRAL_EMPTY_UID
        #key = b'\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF'
        uid     = IoTSocketStruct.UIDToBin128("ObjTest")
        authKey = b'CCCCCCCCDDDDDDDD'
        hmac256 = hmac.new(authKey, data, hashlib.sha256).digest()
        self._send(uid + hmac256)
        self._recv(1, self._onAuthValidationRecv)

    def _onAuthValidationRecv(self, xAsyncTCPClient, data, arg) :
        if IoTSocketStruct.DecodeAuthValidation(data) :
            print('Authentication ok')
            self._startSession()
        else :
            print('Authentication error')
            self.Close()

    def _startSession(self) :
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
        if tot == IoTSocketStruct.TOT_PING :
            self._send(IoTSocketStruct.MakePongTR())
            self._waitDataTransmission()
        elif tot == IoTSocketStruct.TOT_PONG :
            self._waitDataTransmission()
        elif tot == IoTSocketStruct.TOT_REQUEST :
            self._recv(5, self._onRequestRecv, (uid, ))
        elif tot == IoTSocketStruct.TOT_RESPONSE :
            self._recv(6, self._onResponseRecv, (uid, ))
        elif tot == IoTSocketStruct.TOT_TELTOKEN :
            self._recv(8, self._onTelemetryTokenRecv)
        elif tot == IoTSocketStruct.TOT_CLOSE_CONN :
            self._recv(1, self._onCloseConnCodeRecv)
        else :
            self._send(IoTSocketStruct.MakeCloseConnTR(IoTSocketStruct.CLOSE_CODE_PROTO_ERR))
            self.Close()

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
        print('ON REQUEST [%s] RECV' % trackingNbr)
        self._send(IoTSocketStruct.MakeResponseTRHdr(uid, trackingNbr, 0, dataFormat, 0, dataLen) + data)
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
        print('ON RESPONSE [%s] RECV (%s)' % (trackingNbr, code))
        self._waitDataTransmission()

    def _onTelemetryTokenRecv(self, xAsyncTCPClient, data, arg) :
        global telemetryToken
        telemetryToken = data.tobytes()
        print("ON TELEMETRY TOKEN RECV (%s)" % telemetryToken)
        SendTelemetryData(b'BONJOUR')
        SendBinaryRequest(b'BONJOUR')
        self._waitDataTransmission()

    def _onCloseConnCodeRecv(self, xAsyncTCPClient, data, arg) :
        closeCode = data[0]
        self.Close()

def OnTCPCliFailsToConnect(xAsyncTCPClient) :
    print("On TCP Client Fails To Connect")

def OnTCPCliConnected(xAsyncTCPClient) :
    print("On TCP Client Connected")
    xAsyncTCPClient.State = IoTSocketSession(xAsyncTCPClient)

def OnTCPCliClosed(xAsyncTCPClient, closedReason) :
    if closedReason == XClosedReason.Error :
        reason = "error"
    elif closedReason == XClosedReason.ClosedByHost :
        reason = "closed by host"
    elif closedReason == XClosedReason.ClosedByPeer :
        reason = "closed by peer"
    elif closedReason == XClosedReason.Timeout :
        reason = "timeout"
    else :
        reason = "???"
    print("On TCP Connection Closed (%s)" % reason)

def SendTelemetryData(data) :
    if telemetryToken and data :
        datagram = IoTSocketStruct.MakeTelemetryPacket( token      = telemetryToken,
                                                        dataFormat = IoTSocketStruct.PLDATA_FORMAT_BIN,
                                                        formatOpt  = IoTSocketStruct.PLDATA_FMT_OPT_NONE,
                                                        data       = data )
        return xasUDPCli.AsyncSendDatagram(datagram, udpSrvAddr)
    return False

def SendBinaryRequest(data) :
    if data :
        data = IoTSocketStruct.MakeRequestTRHdr( uid         = None,
                                                 trackingNbr = 30303,
                                                 dataFormat  = IoTSocketStruct.PLDATA_FORMAT_BIN,
                                                 formatOpt   = IoTSocketStruct.PLDATA_FMT_OPT_NONE,
                                                 dataLen     = len(data) ) \
             + data
        return xasTCPCli.AsyncSendData(data)
    return False

def Start() :

    global xasPool
    global tcpSrvAddr
    global xasTCPCli
    global udpSrvAddr
    global xasUDPCli
    global telemetryToken

    xasPool    = XAsyncSocketsPool()

    tcpSrvAddr = ('localhost', 50505)
    xasTCPCli  = XAsyncTCPClient.Create( asyncSocketsPool = xasPool,
                                         srvAddr          = tcpSrvAddr,
                                         connectTimeout   = 2,
                                         recvbufLen       = IoTSocketSession.MAX_TR_LEN )
    xasTCPCli.OnFailsToConnect = OnTCPCliFailsToConnect
    xasTCPCli.OnConnected      = OnTCPCliConnected
    xasTCPCli.OnClosed         = OnTCPCliClosed

    udpSrvAddr = ('localhost', 50505)
    xasUDPCli  = XAsyncUDPDatagram.Create(xasPool)

    telemetryToken = None

    xasPool.AsyncWaitEvents(threadsCount=1)

Start()
while True :
    time.sleep(1)

