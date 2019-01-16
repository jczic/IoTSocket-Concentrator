"""
The MIT License (MIT)
Copyright © 2018 Jean-Christophe Bos & HC² (www.hc2.fr)
"""


from   XAsyncSockets   import XAsyncTCPClient
from   iotSocketStruct import IoTSocketStruct
import json

class CentralHTTPWebHook :

    CONN_TIMEOUT = 3
    RECV_TIMEOUT = 2

    def __init__(self, url, pool, httpBufferSize, maxContentLength, maxSecWaitResponse) :
        self._url                = url
        self._maxContentLength   = maxContentLength
        self._maxSecWaitResponse = maxSecWaitResponse
        self._headers            = { }
        self._contentLength      = 0
        self._objRef             = None
        self._onResponseOk       = None
        self._onClosed           = None
        try :
            self._xasTCPCli = XAsyncTCPClient.Create( asyncSocketsPool = pool,
                                                      srvAddr          = (url.Host, url.Port),
                                                      connectTimeout   = CentralHTTPWebHook.CONN_TIMEOUT,
                                                      recvbufLen       = httpBufferSize,
                                                      connectAsync     = False )
        except :
            self._xasTCPCli = None
        if not self._xasTCPCli :
            raise Exception("Error to connect HTTP WebHook %s" % url)
        self._xasTCPCli.OnClosed = self._onTCPConnClosed
        if url.IsHttps() and not self._xasTCPCli.StartSSL() :
            raise Exception("SSL error on HTTP WebHook %s" % url) 

    def Close(self) :
        self._xasTCPCli.Close()

    def _send(self, data) :
        return self._xasTCPCli.AsyncSendData(data)

    def _sendLine(self, line='') :
        return self._send(line.encode('UTF-8') + b'\r\n')

    def _recv(self, size, onDataRecv, onDataRecvArg=None) :
        self._xasTCPCli.AsyncRecvData(size, onDataRecv, onDataRecvArg, self.RECV_TIMEOUT)

    def _recvLine(self, onDataRecv, onDataRecvArg=None) :
        self._xasTCPCli.AsyncRecvLine(onDataRecv, onDataRecvArg, self.RECV_TIMEOUT)

    def _recvResponseFirstLine(self, onDataRecv, onDataRecvArg=None) :
        self._xasTCPCli.AsyncRecvLine(onDataRecv, onDataRecvArg, self._maxSecWaitResponse)

    def _onTCPConnClosed(self, xAsyncTCPClient, closedReason) :
        if self._onClosed :
            self._onClosed(self)

    def Post(self, centralAuthKeyHex, uid, plObject, plFormat) :
        o = {
            "UID"     : IoTSocketStruct.UIDFromBin128(uid),
            "Payload" : plObject,
            "Format"  : plFormat
        }
        data = json.dumps(o).encode('UTF-8')
        self._sendLine('POST %s HTTP/1.0' % self._url.Path)
        self._sendLine('Host: %s' % self._url.Host)
        self._sendLine('Authorization: Bearer %s' % centralAuthKeyHex)
        self._sendLine('Content-Type: application/json; charset=UTF-8')
        self._sendLine('Content-Length: %s' % len(data))
        self._sendLine()
        self._send(data)
        self._recvResponseFirstLine(self._onFirstLineRecv)

    def _onFirstLineRecv(self, xAsyncTCPClient, line, arg) :
        try :
            ver, code, msg = line.strip().split(' ', 2)
            code = int(code)
            if code >= 200 and code < 300 :
                self._recvLine(self._onHeaderLineRecv)
            else :
                self.Close()
        except :
            self.Close()

    def _onHeaderLineRecv(self, xAsyncTCPClient, line, arg) :
        try :
            elements = line.strip().split(':', 1)
            if len(elements) == 2 :
                self._headers[elements[0].strip().lower()] = elements[1].strip()
                self._recvLine(self._onHeaderLineRecv)
            elif len(elements) == 1 and len(elements[0]) == 0 :
                self._contentLength = int(self._headers.get("content-length", 0))
                self._onAllHeadersReaded()
            else :
                self.Close()
        except :
            self.Close()

    def _onContentRecv(self, xAsyncTCPClient, data, arg) :
        content   = arg[0] + data.tobytes()
        remaining = arg[1] - len(data)
        if remaining > 0 :
            self._recv(None, self._onContentRecv, (content, remaining))
        else :
            if self._onResponseOk :
                try :
                    o = json.loads(content.decode('UTF-8'))
                except :
                    o = None
                self._onResponseOk(self, o)
            self.Close()

    def _onAllHeadersReaded(self) :
        if self._contentLength :
            if self._contentLength <= self._maxContentLength :
                self._recv(None, self._onContentRecv, (b'', self._contentLength))
            else :
                self.Close()
        else :
            if self._onResponseOk :
                self._onResponseOk(self, None)
            self.Close()

    @property
    def ObjRef(self) :
        return self._objRef
    @ObjRef.setter
    def ObjRef(self, value) :
        self._objRef = value

    @property
    def OnResponseOk(self) :
        return self._onResponseOk
    @OnResponseOk.setter
    def OnResponseOk(self, value) :
        self._onResponseOk = value

    @property
    def OnClosed(self) :
        return self._onClosed
    @OnClosed.setter
    def OnClosed(self, value) :
        self._onClosed = value


