"""
The MIT License (MIT)
Copyright © 2018 Jean-Christophe Bos & HC² (www.hc2.fr)
"""


from   iotSocketStruct import IoTSocketStruct
from   secrets         import randbelow, token_bytes
from   _thread         import allocate_lock
from   binascii        import hexlify, unhexlify
from   threading       import Timer
from   time            import time
from   datetime        import datetime
import hmac
import hashlib
import json

class IoTSocketRouter :

    def __init__(self, aclFilename, centralAuthKey, keepSessionSec) :
        self._aclFilename           = aclFilename
        self._centralAuthKey        = centralAuthKey
        self._centralAuthKeyHex     = hexlify(centralAuthKey).decode()
        self._keepSessionSec        = keepSessionSec
        self._centralSession        = None
        self._groups                = { }
        self._acl                   = { }
        self._objectsSessions       = { }
        self._keepSessionsData      = { }
        self._centralHTTPRequests   = { }
        self._telemetryTokens       = { }
        self._onGetWebHookRequest   = None
        self._onGetWebHookTelemetry = None
        self._lock                  = allocate_lock()
        self._processing            = True
        self._startTimerCheck()
        self.Log('ROUTER > STARTED')

    def _startTimerCheck(self) :
        Timer(1, self._timerCheckSeconds).start()

    def _timerCheckSeconds(self) :
        nowSec = time()
        with self._lock :
            if self._keepSessionsData :
                for uid in list(self._keepSessionsData) :
                    if nowSec >= self._keepSessionsData[uid][1] :
                        del self._keepSessionsData[uid]
            if self._centralHTTPRequests :
                for trackingNbr in list(self._centralHTTPRequests) :
                    httpReq, exp = self._centralHTTPRequests[trackingNbr]
                    if exp and nowSec >= exp :
                        del self._centralHTTPRequests[trackingNbr]
                        httpReq.SendResponseErrTimeout()
                        self.Log('HTTPS REQUEST TIMEOUT (#%s)' % trackingNbr)
            if self._telemetryTokens :
                for token in list(self._telemetryTokens) :
                    uid, exp = self._telemetryTokens[token]
                    if exp and nowSec >= exp :
                        del self._telemetryTokens[token]
                        self.Log( 'TELEMETRY TOKEN EXPIRED (%s)' %
                                  self.TelemetryTokenToStr(token) )
        for uid in self._objectsSessions :
            self._objectsSessions[uid].CheckRequestsTimeout(nowSec)
        if self._processing :
            self._startTimerCheck()

    def Stop(self) :
        self._processing = False

    def Log(self, line) :
        dt = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        print('[%s] %s' % (dt, line))

    def AddGroup(self, groupName, options={ }) :
        if groupName and type(options) is dict :
            groupID = IoTSocketStruct.GroupNameToBin128(groupName)
            if groupID :
                self._groups[groupID] = options
                return True
        return False

    def GetGroupOption(self, groupID, optName) :
        options = self._groups.get(groupID, None)
        if options :
            return options.get(optName, None)
        return None

    def ClearACL(self) :
        with self._lock :
            self._acl.clear()

    def AddACLAccess(self, groupID, uid, authKey) :
        with self._lock :
            if groupID in self._groups :
                self._acl[uid] = (groupID, authKey)
                return True
        return False

    def SaveACL(self) :
        try :
            o = { }
            with self._lock :
                for uid in self._acl :
                    o[IoTSocketStruct.UIDFromBin128(uid)] = {
                        "GroupName" : IoTSocketStruct.GroupNameFromBin128(self._acl[uid][0]),
                        "AuthKey"   : hexlify(self._acl[uid][1]).decode()
                    }
            with open(self._aclFilename, 'wb') as file :
                file.write(json.dumps(o).encode('UTF-8'))
            return True
        except :
            return False

    def LoadACL(self) :
        try :
            with open(self._aclFilename, 'r') as file :
                o = json.load(file)
            acl = { }
            for strUID in o :
                uid     = IoTSocketStruct.UIDToBin128(strUID)
                groupID = IoTSocketStruct.GroupNameToBin128(o[strUID]["GroupName"])
                authKey = unhexlify(o[strUID]["AuthKey"])
                if not uid or not groupID or len(authKey) != 16 or \
                   not groupID in self._groups :
                    return False
                acl[uid] = (groupID, authKey)
            with self._lock :
                self._acl = acl
            return True
        except :
            return False

    def GetACLAccess(self, uid) :
        return self._acl.get(uid, (None, None))

    def CheckCentralAuthKey(self, authKey) :
        return (authKey == self._centralAuthKey)

    def AuthenticateSession(self, session, token128, hmac256) :
        if session.UID == IoTSocketStruct.CENTRAL_EMPTY_UID :
            central = True
            authKey = self._centralAuthKey
        else :
            groupID, authKey = self.GetACLAccess(session.UID)
            central = False
        if authKey :
            hmac256srv = hmac.new(authKey, token128, hashlib.sha256).digest()
            if hmac.compare_digest(hmac256, hmac256srv) :
                if central :
                    if self._centralSession :
                        self._centralSession.Close()
                    self._centralSession = session
                else :
                    existingSession = self._objectsSessions.get(session.UID, None)
                    if existingSession :
                        existingSession.Close()
                    self._objectsSessions[session.UID] = session
                session.Send(IoTSocketStruct.MakeAuthValidation(True))
                with self._lock :
                    sessionData, exp = self._keepSessionsData.get(session.UID, (None, None))
                    if sessionData is not None :
                        for data in sessionData :
                            session.Send(data)
                        del self._keepSessionsData[session.UID]
                return True
        session.Send(IoTSocketStruct.MakeAuthValidation(False))
        session.Close()
        return False

    def RemoveSession(self, session, keepSessionData) :
        with self._lock :
            removed = False
            if session.UID == IoTSocketStruct.CENTRAL_EMPTY_UID :
                if session == self._centralSession :
                    self._centralSession = None
                    removed              = True
            elif session.UID in self._objectsSessions :
                if session == self._objectsSessions[session.UID] :
                    del self._objectsSessions[session.UID]
                    removed = True
            if removed and keepSessionData :
                exp = time() + self._keepSessionSec
                self._keepSessionsData[session.UID] = ([ ], exp)

    def CentralSessionExists(self) :
        return ( self._centralSession is not None or \
                 IoTSocketStruct.CENTRAL_EMPTY_UID in self._keepSessionsData )

    def AddCentralHTTPRequest(self, httpReq, exp) :
        with self._lock :
            while True :
                trackingNbr = randbelow(2**16)
                if not trackingNbr in self._centralHTTPRequests :
                    self._centralHTTPRequests[trackingNbr] = (httpReq, exp)
                    break
        return trackingNbr

    def RemoveCentralHTTPRequest(self, httpReq) :
        with self._lock :
            if httpReq.TrackingNbr in self._centralHTTPRequests :
                if httpReq == self._centralHTTPRequests[httpReq.TrackingNbr][0] :
                    del self._centralHTTPRequests[httpReq.TrackingNbr]

    def GetNewTelemetryToken(self, uid, expirationMin) :
        with self._lock :
            while True :
                token = token_bytes(8)
                if not token in self._telemetryTokens :
                    if isinstance(expirationMin, int) and expirationMin > 0 :
                        exp = time() + (expirationMin * 60)
                    else :
                        exp = None
                    self._telemetryTokens[token] = (uid, exp)
                    break
        self.Log( 'NEW TELEMETRY TOKEN FOR {%s} EXPIRING IN %s MIN (%s)' %
                  ( IoTSocketStruct.UIDFromBin128(uid),
                    expirationMin,
                    self.TelemetryTokenToStr(token) ) )
        return token

    def TelemetryTokenToStr(self, token) :
        if isinstance(token, bytes) and len(token) == 8 :
            return hexlify(token).decode().upper()
        return 'TOKEN-ERROR'

    def RouteRequest(self, fromUID, toUID, trackingNbr, dataFormat, formatOpt, data) :
        if toUID or self.CentralSessionExists() :
            if toUID :
                session = self._objectsSessions.get(toUID, None)
            else :
                session = self._centralSession
            data = IoTSocketStruct.MakeRequestTRHdr( fromUID,
                                                     trackingNbr,
                                                     dataFormat,
                                                     formatOpt,
                                                     len(data) ) \
                 + data
            if session and session.Send(data) :
                return True
            if not toUID :
                toUID = IoTSocketStruct.CENTRAL_EMPTY_UID
            sessionData, exp = self._keepSessionsData.get(toUID, (None, None))
            if sessionData is not None :
                sessionData.append(data)
                self.Log('ROUTER > REQUEST KEPT (#%s)' % trackingNbr)
                return True
        else :
            if self._onGetWebHookRequest :
                plFormat, plObject = IoTSocketStruct.DecodeJSONPayload(data, dataFormat)
                if plFormat is not None and plObject is not None :
                    webHook = self._onGetWebHookRequest(self)
                    if webHook :
                        webHook.ObjRef       = (fromUID, trackingNbr)
                        webHook.OnResponseOk = self._onWebHookResponseOk
                        webHook.OnClosed     = self._onWebHookClosed
                        webHook.Post(self._centralAuthKeyHex, fromUID, plObject, plFormat)
                        return True
                    self.Log('ROUTER > ERROR TO OPEN WEBHOOK OF REQUEST')
        self.Log('ROUTER > NO DESTINATION FOR REQUEST (#%s)' % trackingNbr)
        return False

    def _onWebHookResponseOk(self, centralHTTPWebHook, o) :
        if o :
            uid, trackingNbr = centralHTTPWebHook.ObjRef
            try :
                code      = int(o['Code'])
                fmt, data = IoTSocketStruct.EncodeJSONPayload(o['Payload'], o['Format'])
                if fmt is not None and data is not None :
                    centralHTTPWebHook.ObjRef = (None, None)
                    session = self._objectsSessions.get(uid, None)
                    if session :
                        session.EndTrackingRequest(trackingNbr)
                        data = IoTSocketStruct.MakeResponseTRHdr( None,
                                                                  trackingNbr,
                                                                  code,
                                                                  fmt,
                                                                  IoTSocketStruct.PLDATA_FMT_OPT_NONE,
                                                                  len(data) ) \
                             + data
                        session.Send(data)
            except :
                pass

    def _onWebHookClosed(self, centralHTTPWebHook) :
        uid, trackingNbr = centralHTTPWebHook.ObjRef
        if uid and trackingNbr :
            session = self._objectsSessions.get(uid, None)
            if session :
                session.EndTrackingRequest(trackingNbr)
                data = IoTSocketStruct.MakeResponseErrTR( None,
                                                          trackingNbr,
                                                          IoTSocketStruct.RESP_CODE_REQ_NOK )
                session.Send(data)

    def RouteResponse(self, fromUID, toUID, trackingNbr, code, dataFormat, formatOpt, data) :
        if toUID or self.CentralSessionExists() :
            if toUID :
                session = self._objectsSessions.get(toUID, None)
            else :
                session = self._centralSession
            if session :
                session.EndTrackingRequest(trackingNbr)
                data = IoTSocketStruct.MakeResponseTRHdr( fromUID,
                                                          trackingNbr,
                                                          code,
                                                          dataFormat,
                                                          formatOpt,
                                                          len(data) ) \
                     + data
                return session.Send(data)
        else :
            httpReq, exp = self._centralHTTPRequests.get(trackingNbr, (None, None))
            if httpReq :
                plFormat, plObject = IoTSocketStruct.DecodeJSONPayload(data, dataFormat)
                if plFormat is not None and plObject is not None :
                    self.RemoveCentralHTTPRequest(httpReq)
                    return httpReq.SendResponse(code, plObject, plFormat)
        self.Log('ROUTER > NO DESTINATION FOR RESPONSE (#%s)' % trackingNbr)
        return False

    def RouteTelemetry(self, token, dataFormat, formatOpt, data) :
        if token and data :
            uid, exp = self._telemetryTokens.get(token, (None, None))
            if uid :
                self.Log( 'ROUTER > TELEMETRY RECEIVED FROM {%s} WITH TOKEN %s' %
                          ( IoTSocketStruct.UIDFromBin128(uid),
                            self.TelemetryTokenToStr(token) ) )
                if self.CentralSessionExists() :
                    session = self._centralSession
                    if session :
                        data = IoTSocketStruct.MakeIdentTelemetryTRHdr( uid,
                                                                        dataFormat,
                                                                        formatOpt,
                                                                        len(data) ) \
                             + data
                        if session.Send(data) :
                            return True
                elif self._onGetWebHookTelemetry :
                    plFormat, plObject = IoTSocketStruct.DecodeJSONPayload(data, dataFormat)
                    if plFormat is not None and plObject is not None :
                        webHook = self._onGetWebHookTelemetry(self)
                        if webHook :
                            webHook.Post(self._centralAuthKeyHex, uid, plObject, plFormat)
                            return True
                        self.Log('ROUTER > ERROR TO OPEN WEBHOOK OF TELEMETRY')
                self.Log('ROUTER > NO DESTINATION FOR TELEMETRY')
        return False

    @property
    def OnGetWebHookRequest(self) :
        return self._onGetWebHookRequest
    @OnGetWebHookRequest.setter
    def OnGetWebHookRequest(self, value) :
        self._onGetWebHookRequest = value

    @property
    def OnGetWebHookTelemetry(self) :
        return self._onGetWebHookTelemetry
    @OnGetWebHookTelemetry.setter
    def OnGetWebHookTelemetry(self, value) :
        self._onGetWebHookTelemetry = value

