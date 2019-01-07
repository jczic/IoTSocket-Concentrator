
from   iotSocketStruct import IoTSocketStruct
from   urlUtils        import UrlUtils
from   binascii        import unhexlify
from   time            import time
import json

class CentralHTTPRequest :

    RECV_TIMEOUT = 2

    def __init__(self, xAsyncTCPClient, router, sslKeyFilename, sslCrtFilename, maxContentLength) :
        self._xasTCPCli          = xAsyncTCPClient
        self._router             = router
        self._maxContentLength   = maxContentLength
        self._method             = None
        self._resPath            = None
        self._httpVer            = None
        self._resPath            = '/'
        self._queryString        = ''
        self._headers            = { }
        self._contentType        = None
        self._contentLength      = 0
        self._trackingNbr        = None
        self._resLocations       = {
            "/acl"     : ( 'POST', self._processPOSTACL     ),
            "/request" : ( 'POST', self._processPOSTRequest )
        }
        if self._xasTCPCli.StartSSL(sslKeyFilename, sslCrtFilename, True) :
            self._recvLine(self._onFirstLineRecv)
        else :
            self.Close()

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

    def _onFirstLineRecv(self, xAsyncTCPClient, line, arg) :
        try :
            elements = line.strip().split()
            if len(elements) == 3 :
                self._method  = elements[0].upper()
                self._path    = elements[1]
                self._httpVer = elements[2].upper()
                elements      = self._path.split('?', 1)
                if len(elements) > 0 :
                    self._resPath = UrlUtils.UnquotePlus(elements[0])
                    if len(elements) > 1 :
                        self._queryString = elements[1]
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
                if self._method == 'POST' or self._method == 'PUT' :
                    self._contentType   = self._headers.get("content-type", None)
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
            self._resLocations[self._resPath][1](content)

    def _onAllHeadersReaded(self) :
        if self._checkAuthentication() :
            self._resPath = self._resPath.lower()
            if self._resPath in self._resLocations :
                if self._method == self._resLocations[self._resPath][0] :
                    if self._contentLength :
                        if self._contentLength <= self._maxContentLength :
                            self._recv(None, self._onContentRecv, (b'', self._contentLength))
                        else :
                            self._sendHTTPResponse(413, '413 : Request Entity Too Large')
                    else :
                        self._resLocations[self._resPath][1](None)
                else :
                    self._sendHTTPResponse(405, '405 : Method Not Allowed')
            else :
                self._sendHTTPResponse(404, '404 : Not Found')
        else :
            self._sendHTTPResponse(401, '401 : Unauthorized')

    def _checkAuthentication(self) :
        x = self._headers.get("authorization", None)
        if x :
            x = x.split()
            if len(x) == 2 and x[0].lower() == 'bearer' :
                try :
                    authKey = unhexlify(x[1])
                    return self._router.CheckCentralAuthKey(authKey)
                except :
                    pass
        return False

    def _sendHTTPResponse(self, code, content=None, contentType='text/html', charset='UTF-8') :
        if self._sendLine('HTTP/1.1 %s' % code) :
            if content :
                if type(content) == str :
                    content = content.encode(charset)
                self._sendLine('Content-Type: %s; charset=%s' % (contentType, charset))
                self._sendLine('Content-Length: %s' % len(content))
            self._sendLine('Connection: close')
            ok = self._sendLine()
            if content :
                ok = self._send(content)
            self.Close()
            return ok
        return False

    def _sendJSONResponseOK(self, o) :
        return self._sendHTTPResponse(200, json.dumps(o), 'application/json')

    def SendResponse(self, code, plObject, plFormat) :
        return self._sendJSONResponseOK( {
            "Code"    : code,
            "Payload" : plObject,
            "Format"  : plFormat
        } )

    def SendResponseErrNoDest(self) :
        return self.SendResponse(IoTSocketStruct.RESP_CODE_ERR_NO_DEST, None, 'JSON')

    def SendResponseErrTimeout(self) :
        return self.SendResponse(IoTSocketStruct.RESP_CODE_ERR_TIMEOUT, None, 'JSON')

    def _getJSONContent(self, content) :
        if content :
            try :
                return json.loads(content.decode('UTF-8'))
            except :
                raise Exception('incorrect json format')
        raise Exception('no content')

    def _processPOSTACL(self, content) :
        try :
            o = self._getJSONContent(content)
        except Exception as ex :
            self._sendHTTPResponse(400, '400 : Bad Request (%s)' % ex)
            return
        try :
            acl = [ ]
            ok  = True
            for ac in o :
                groupID = IoTSocketStruct.GroupNameToBin128(ac['GroupName'])
                uid     = IoTSocketStruct.UIDToBin128(ac['UID'])
                authKey = unhexlify(ac['AuthKey'])
                if groupID and uid and authKey and len(authKey) == 16 :
                    acl.append((groupID, uid, authKey))
                else :
                    ok = False
                    break
            if ok :
                self._router.ClearACL()
                for ac in acl :
                    self._router.AddACLAccess(*ac)
                self._router.SaveACL()
                self._sendHTTPResponse(200)
                return
        except :
            pass
        self._sendHTTPResponse(400, '400 : Bad Request (incorrect json data)')

    def _processPOSTRequest(self, content) :
        try :
            o = self._getJSONContent(content)
        except Exception as ex :
            self._sendHTTPResponse(400, '400 : Bad Request (%s)' % ex)
            return
        try :
            uid       = IoTSocketStruct.UIDToBin128(o['UID'])
            timeout   = int(o.get('Timeout', 0))
            fmt, data = IoTSocketStruct.EncodeJSONPayload(o['Payload'], o['Format'])
            if uid and timeout >= 0 and fmt is not None and data is not None :
                exp               = (time() + timeout) if timeout else None
                self._trackingNbr = self._router.AddCentralHTTPRequest(self, exp)
                if not self._router.RouteRequest( fromUID     = None,
                                                  toUID       = uid,
                                                  trackingNbr = self._trackingNbr,
                                                  dataFormat  = fmt,
                                                  formatOpt   = IoTSocketStruct.PLDATA_FMT_OPT_NONE,
                                                  data        = data ) :
                    self._router.RemoveCentralHTTPRequest(self)
                    self.SendResponseErrNoDest()
                return
        except :
            pass
        self._sendHTTPResponse(400, '400 : Bad Request (incorrect json data)')

    @property
    def TrackingNbr(self) :
        return self._trackingNbr
