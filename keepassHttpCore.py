import jsonKey
import requestType
import random
from crypto import AESObj

class KeepassHttpCore:

    def __init__(self):
        self.errMsg = ""
        self.funcMap = {
            requestType.TEST_ASSOCIATE: self._test_associate,
            requestType.ASSOCIATE: self._associate,
            requestType.GET_LOGINS: self._get_logins,
        }
        self.keyMap = {} # client_id -> key
        self.aes = None

    def getErrMsg(self):
        return self.errMsg

    def process(self, input_dict, output_dict):
        # check request type in input param
        rt = input_dict.get(jsonKey.REQUESTTYPE, None)
        if not rt:
            self.errMsg = "input json must contains %s" %(jsonKey.REQUESTTYPE)
            return False
        else:
            # find func in map
            func = self.funcMap.get(rt, None)
            if not func:
                # call func
                self.errMsg = "%s:%s not defined" % (jsonKey.REQUESTTYPE, rt)
                return False
            else:
                return func(input_dict, output_dict)

    def _test_associate(self, input_dict, output_dict):
        # judge if bind or not bind
        client_id = input_dict.get(jsonKey.ID)
        if not client_id:
            # not bind
            return True 
        else:
            # already bind, try auth
            if not self._authenticate(input_dict, output_dict):
                #print "auth failed"
                # Auth failed
                return True
            else:
                # Auth success
                output_dict[jsonKey.ID] = client_id 
                output_dict[jsonKey.SUCCESS] = True
                return True 

    def _new_client_id(self):
        return "U%s" % (random.randint(1, 10000))

    def _add_verifier(self, input_dict, output_dict, new_client_id = None):
        if new_client_id:
            client_id = new_client_id
            key = self._get_key_by_client_id(client_id)
            #print key
            if not key:
                return False
        else:
            client_id = input_dict.get(jsonKey.ID, None)
            if not client_id:
                return False
            key = self.aes.get_key()
        # use key to encrypt nonce
        nonce = AESObj.gen_nonce()
        aes = AESObj(key, nonce)
        #print nonce
        nonce_encrypt = aes.encrypt(nonce)
        # set encrypt result
        output_dict[jsonKey.NONCE] = nonce
        output_dict[jsonKey.VERIFIER] = nonce_encrypt 
        return True

    def _associate(self, input_dict, output_dict):
        # check input
        key = input_dict.get(jsonKey.KEY, None)
        if not key:
            return False
        # generate client id and save
        client_id = self._new_client_id()
        self.keyMap[client_id] = key
        # result
        output_dict[jsonKey.ID] = client_id
        output_dict[jsonKey.SUCCESS] = True
        return self._add_verifier(input_dict, output_dict, client_id)

    def _get_key_by_client_id(self, client_id):
        return self.keyMap.get(client_id, None)

    def _authenticate(self, input_dict, output_dict):
        # Check input data
        client_id = input_dict.get(jsonKey.ID, None)
        # Check if id exists
        key = self._get_key_by_client_id(client_id)
        if not key:
            return False
        # Check other input data
        nonce = input_dict.get(jsonKey.NONCE, None)
        verifier = input_dict.get(jsonKey.VERIFIER, None)
        if nonce == None or verifier == None:
            return True 
        # aes
        aes = AESObj(key, nonce)
        if not aes.verify(nonce, verifier):
            # verify failed
            #print "auth failed"
            return True
        else:
            #print "auth succ"
            self.aes = aes
            self._add_verifier(input_dict, output_dict)
            return True

    def _get_logins(self, input_dict, output_dict):
        if not self._authenticate(input_dict, output_dict):
            # auth fail
            return True
        else:
            output_dict[jsonKey.SUCCESS] = True
            output_dict[jsonKey.COUNT] = 1
            return True
