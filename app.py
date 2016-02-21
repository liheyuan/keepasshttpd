import web
import json

import jsonKey
from keepassHttpCore import KeepassHttpCore

urls = (
    '/', 'HttpdCore'
)

khc = KeepassHttpCore()

class HttpdCore:
    def POST(self):
        # try parse json data
        data = web.data()
        print "Request", data
        try:
           obj = json.loads(data) 
        except:
            #print "POST data is not JSON"
            return web.internalerror("POST data is not JSON")
        # dispatch to core for process 
        resp_dict = {}
        if not khc.process(obj, resp_dict):
            return web.internalerror("%s" % (khc.getErrMsg()))
        else:
            print "Resp ", resp_dict
            return json.dumps(resp_dict)

if __name__ == "__main__":
    app = web.application(urls, globals())
    app.run()
