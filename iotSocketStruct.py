"""
The MIT License (MIT)
Copyright © 2018 Jean-Christophe Bos & HC² (www.hc2.fr)
"""


from   struct import pack, unpack
import json

class IoTSocketStruct :

    TOT_ACL                         = 0x00
    TOT_PING                        = 0x01
    TOT_PONG                        = 0x02
    TOT_REQUEST                     = 0x03
    TOT_RESPONSE                    = 0x04
    TOT_TELTOKEN                    = 0x05
    TOT_IDENT_TELEMETRY             = 0x06
    TOT_CLOSE_CONN                  = 0x0F

    INIT_NO_RULE                    = 0x00
    INIT_REDIRECT_RULE              = 0x00

    PLDATA_FORMAT_BIN               = 0x00
    PLDATA_FORMAT_ASCII             = 0x01
    PLDATA_FORMAT_UTF8              = 0x02
    PLDATA_FORMAT_JSON              = 0x0A

    PLDATA_FMT_OPT_NONE             = 0x00

    RESP_CODE_REQ_OK                = 0x00
    RESP_CODE_REQ_NOK               = 0x01
    RESP_CODE_ERR_NO_DEST           = 0xA0
    RESP_CODE_ERR_TIMEOUT           = 0xA1
    RESP_CODE_ERR_SAME_TRK_NBR      = 0xA2

    CLOSE_CODE_PROTO_ERR            = 0x00
    CLOSE_CODE_INT_PLANNED          = 0x01
    CLOSE_CODE_MAX_LOAD             = 0x02
    CLOSE_CODE_PROCESS_ERR          = 0x03
    CLOSE_CODE_SLEEP_MODE           = 0xA0
    CLOSE_CODE_FLUSH_RESS           = 0xA1

    CENTRAL_EMPTY_UID               = b'\x00' * 16

    @staticmethod
    def MakeUTF8String(s) :
        if s is not None :
            try :
                data   = s.encode('UTF-8') if s else b''
                length = len(data)
                if length <= 255 :
                    return bytes([length]) + data
            except :
                pass
        return None

    @staticmethod
    def _strIdentTobin128(strIdent) :
        if strIdent is not None :
            try :
                bin128 = strIdent.encode("UTF-8").rjust(16, b'\x00')
                if len(bin128) == 16 :
                    return bin128
            except :
                pass
        return None

    @staticmethod
    def _strIdentFromBin128(bin128) :
        if bin128 and len(bin128) == 16 :
            try :
                return bin128.lstrip(b'\x00').decode('UTF-8')
            except :
                pass
        return None

    @staticmethod
    def GroupNameToBin128(groupName) :
        return IoTSocketStruct._strIdentTobin128(groupName)

    @staticmethod
    def GroupNameFromBin128(bin128) :
        return IoTSocketStruct._strIdentFromBin128(bin128)

    @staticmethod
    def UIDToBin128(uid) :
        return IoTSocketStruct._strIdentTobin128(uid)

    @staticmethod
    def UIDFromBin128(bin128) :
        return IoTSocketStruct._strIdentFromBin128(bin128)

    @staticmethod
    def MakeACLItem(groupID, uid, authKey) :
        return groupID + uid + authKey

    @staticmethod
    def DecodeACLItem(data) :
        groupID = data[  :16]
        uid     = data[16:32]
        authKey = data[32:48]
        return (groupID, uid, authKey)

    @staticmethod
    def MakeInitiationReq(tls, ver, opt, maxTrLen) :
        return bytes([ (tls << 7) | ver ]) + \
               bytes([ opt ]) + \
               pack('>H', maxTrLen)

    @staticmethod
    def DecodeInitiationReq(data) :
        tls      = bool(data[0] >> 7)
        ver      = data[0] & 0x7F
        opt      = data[1]
        maxTrLen = unpack('>H', data[2:4])[0]
        return (tls, ver, opt, maxTrLen)

    @staticmethod
    def MakeInitiationResp(ok, ruleType, ruleFlags=0x00, ruleContent=b'') :
        return bytes([ (ok << 7) | ruleType ]) + \
               bytes([ ruleFlags ]) + \
               ruleContent

    @staticmethod
    def DecodeInitiationResp(data) :
        ok        = bool(data[0] >> 7)
        ruleType  = data[0] & 0x7F
        ruleFlags = data[1]
        return (ok, ruleType, ruleFlags)

    @staticmethod
    def MakeAuthValidation(validated) :
        return bytes([validated])

    @staticmethod
    def DecodeAuthValidation(data) :
        return data is not None and \
               len(data) == 1   and \
               bool(ord(bytes(data)))

    @staticmethod
    def _makeDataTRHdr(tot, uid=None) :
        if uid :
            if len(uid) != 16 :
                raise Exception('MakeDataTransmission UID error.')
            rte = True
        else :
            rte = False
        return bytes([tot << 4 | rte << 3]) + (uid if uid else b'')

    @staticmethod
    def DecodeDataTRHdr(data) :
        tot = data[0] >> 4
        rte = bool(data[0] & (1 << 3))
        return (tot, rte)

    @staticmethod
    def _makePLDataHdr(dataFormat, formatOpt, dataLen) :
        return bytes([ (dataFormat & 0x0F) << 4 | formatOpt & 0x0F ]) + \
               pack('>H', dataLen)

    @staticmethod
    def _decodePLDataHdr(data) :
        dataFormat = data[0] >> 4
        formatOpt  = data[0] & 0x0F
        dataLen    = unpack('>H', data[1:3])[0]
        return (dataFormat, formatOpt, dataLen)

    @staticmethod
    def MakeACLTRHdr(aclItemsCount) :
        return IoTSocketStruct._makeDataTRHdr(IoTSocketStruct.TOT_ACL) + \
               pack('>I', aclItemsCount)

    @staticmethod
    def MakePingTR() :
        return IoTSocketStruct._makeDataTRHdr(IoTSocketStruct.TOT_PING)

    @staticmethod
    def MakePongTR() :
        return IoTSocketStruct._makeDataTRHdr(IoTSocketStruct.TOT_PONG)

    @staticmethod
    def MakeTelemetryTokenTR(token) :
        return IoTSocketStruct._makeDataTRHdr(IoTSocketStruct.TOT_TELTOKEN) + \
               token

    @staticmethod
    def MakeIdentTelemetryTRHdr(uid, dataFormat, formatOpt, dataLen) :
        return IoTSocketStruct._makeDataTRHdr(IoTSocketStruct.TOT_IDENT_TELEMETRY, uid) + \
               IoTSocketStruct._makePLDataHdr(dataFormat, formatOpt, dataLen)

    @staticmethod
    def DecodeIdentTelemetryHdr(data) :
        uid                            = data[:16]
        dataFormat, formatOpt, dataLen = IoTSocketStruct._decodePLDataHdr(data[16:19])
        return (uid, dataFormat, formatOpt, dataLen)

    @staticmethod
    def MakeRequestTRHdr(uid, trackingNbr, dataFormat, formatOpt, dataLen) :
        return IoTSocketStruct._makeDataTRHdr(IoTSocketStruct.TOT_REQUEST, uid) + \
               pack('>H', trackingNbr) + \
               IoTSocketStruct._makePLDataHdr(dataFormat, formatOpt, dataLen)

    @staticmethod
    def DecodeRequestHdr(data) :
        trackingNbr                    = unpack('>H', data[:2])[0]
        dataFormat, formatOpt, dataLen = IoTSocketStruct._decodePLDataHdr(data[2:5])
        return (trackingNbr, dataFormat, formatOpt, dataLen)

    @staticmethod
    def MakeResponseTRHdr(uid, trackingNbr, code, dataFormat, formatOpt, dataLen) :
        return IoTSocketStruct._makeDataTRHdr(IoTSocketStruct.TOT_RESPONSE, uid) + \
               pack('>H', trackingNbr) + \
               bytes([code]) + \
               IoTSocketStruct._makePLDataHdr(dataFormat, formatOpt, dataLen)

    @staticmethod
    def MakeResponseErrTR(uid, trackingNbr, code) :
        return IoTSocketStruct.MakeResponseTRHdr(uid, trackingNbr, code, 0x00, 0x00, 0)

    @staticmethod
    def DecodeResponseHdr(data) :
        trackingNbr                    = unpack('>H', data[:2])[0]
        code                           = data[2]
        dataFormat, formatOpt, dataLen = IoTSocketStruct._decodePLDataHdr(data[3:6])
        return (trackingNbr, code, dataFormat, formatOpt, dataLen)

    @staticmethod
    def MakeCloseConnTR(closeCode) :
        return IoTSocketStruct._makeDataTRHdr(IoTSocketStruct.TOT_CLOSE_CONN) + \
               bytes([closeCode])

    @staticmethod
    def MakeTelemetryPacket(token, dataFormat, formatOpt, data=b'') :
        return token + \
               IoTSocketStruct._makePLDataHdr(dataFormat, formatOpt, len(data)) + \
               data

    @staticmethod
    def DecodeTelemetryPacket(packet) :
        if packet :
            packetLen = len(packet)
            if packetLen >= 11 :
                token                          = packet[:8]
                dataFormat, formatOpt, dataLen = IoTSocketStruct._decodePLDataHdr(packet[8:11])
                if packetLen == 11 + dataLen :
                    data = packet[11:]
                    return (token, dataFormat, formatOpt, data)
        return (None, None, None, None)

    @staticmethod
    def EncodeJSONPayload(plObject, plFormat) :
        try :
            if plFormat == 'JSON' :
                fmt  = IoTSocketStruct.PLDATA_FORMAT_JSON
                data = json.dumps(plObject).encode('UTF-8')
            elif plFormat == 'ASCII' :
                fmt  = IoTSocketStruct.PLDATA_FORMAT_ASCII
                data = plObject.encode('ASCII')
            elif plFormat == 'UTF8' :
                fmt  = IoTSocketStruct.PLDATA_FORMAT_UTF8
                data = plObject.encode('UTF-8')
            elif plFormat == 'BINARY' :
                fmt  = IoTSocketStruct.PLDATA_FORMAT_BIN
                data = b''
                for val in plObject :
                    data += bytes([val])
            else :
                data = None
            if data is not None :
                return (fmt, data)
        except :
            pass
        return (None, None)

    @staticmethod
    def DecodeJSONPayload(data, fmt) :
        try :
            if fmt == IoTSocketStruct.PLDATA_FORMAT_JSON :
                plFormat = 'JSON'
                plObject = json.loads(data.decode('UTF-8'))
            elif fmt == IoTSocketStruct.PLDATA_FORMAT_ASCII :
                plFormat = 'ASCII'
                plObject = data.decode('ASCII')
            elif fmt == IoTSocketStruct.PLDATA_FORMAT_UTF8 :
                plFormat = 'UTF8'
                plObject = data.decode('UTF-8')
            elif fmt == IoTSocketStruct.PLDATA_FORMAT_BIN :
                plFormat = 'BINARY'
                plObject = [ ]
                for val in data :
                    plObject.append(val)
            else :
                plObject = None
            if plObject is not None :
                return (plFormat, plObject)
        except :
            pass
        return (None, None)

