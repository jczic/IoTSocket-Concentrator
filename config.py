
from os   import mkdir
from json import load, dumps

class Config :
    
    # ============================================================================
    # ===( Constructor )==========================================================
    # ============================================================================

    def __init__(self, confName, confPath='') :
        self._confPath = confPath
        if confPath :
            confPath += '/'
        self._filePath = '%s%s.json' % (confPath, confName)
        self._confObj  = None

    # ============================================================================
    # ===( Properties )===========================================================
    # ============================================================================

    @property
    def conf(self) :
        if self._confObj == None :
            try :
                with open(self._filePath, 'r') as jsonFile :
                    self._confObj = load(jsonFile)
            except Exception as ex :
                print(ex)
                self._confObj = { }
        return self._confObj

    # ============================================================================
    # ===( Functions )============================================================
    # ============================================================================

    def isEmpty(self) :
        return len(self.conf) == 0

    # ----------------------------------------------------------------------------

    def save(self, confObj=None) :
        if confObj == None :
            confObj = self.conf
        try :
            jsonStr = dumps(confObj)
            try :
                mkdir(self._confPath)
            except :
                pass
            jsonFile = open(self._filePath, 'wb')
            jsonFile.write(jsonStr)
            jsonFile.close()
            self._confObj = confObj
        except :
            return False
        return True
    
    # ----------------------------------------------------------------------------

    def get(self, path=None, default=None) :
        o = self.conf
        if not path == None :
            for key in path.split('.') :
                if not key == "" :
                    if hasattr(o, 'get') :
                        o = o.get(key, None)
                        if not o == None :
                            continue
                    return default
        return o
    
    # ----------------------------------------------------------------------------

    def set(self, path=None, value=None) :
        o       = self.conf
        lastObj = None
        lastKey = None
        if not path == None :
            for key in path.split('.') :
                if not key == "" :
                    lastObj = o
                    lastKey = key
                    val     = None
                    if hasattr(o, 'get') :
                        val = o.get(key, None)
                    if val == None or not hasattr(val, 'get') :
                        o[key] = { }
                        o = o[key]
                    else :
                        o = val
        if not lastObj == None :
            lastObj[lastKey] = value
            return True
        return False
    
    # ----------------------------------------------------------------------------
    
    def remove(self, path=None) :
        if path == None :
            self._confObj = { }
            return True
        else :
            o       = self.conf
            lastObj = None
            lastKey = None
            for key in path.split('.') :
                if not key == "" :
                    lastObj = o
                    lastKey = key
                    if hasattr(o, 'get') :
                        o = o.get(key, None)
                        if not o == None :
                            continue
                    return False
            if not lastObj == None :
                lastObj.pop(lastKey)
                return True
            return False

    # ============================================================================
    # ============================================================================
    # ============================================================================

