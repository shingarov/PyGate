"""Python Gate server.

"""

import z3

import pdb, traceback
import inspect, sys, json, random
import socket, socketserver
#import angr, archinfo
#from claripy import *
#from pyvex.const import *
#from pyvex.expr  import *
#from pyvex.stmt  import *
#from pyvex       import *

e = {}

class SmalltalkCallbackReturn(Exception):
    def __init__(self, returnValue):
        self.returnValue = returnValue

class PythonGate(socketserver.StreamRequestHandler):

    def read_one(self):
        requestline = self.rfile.readline().decode()
        sys.stdout.write("> %s" % requestline)
        return requestline

    def write_one(self, answer):
        ans = answer  + '\r\n'
        self.wfile.write(ans.encode())
        sys.stdout.write("< %s" % ans)
        self.wfile.flush()


    def handle_one_packet(self):
        requestline = self.read_one()
        answer = self.getAnswer(requestline)
        self.write_one(answer)

    def handle(self):
        self.incomingJsonVarName = None
        while True:
            self.handle_one_packet()

    def getAnswer(self, request):
        if self.incomingJsonVarName:
            e[self.incomingJsonVarName.rstrip()] = self.deser(request)
            self.incomingJsonVarName = None
            return '+'
        if not request:
            return ''
        if request[0]=='.':
            return self.doExec(request[1:])
        elif request[0]==':':
            self.incomingJsonVarName = request[1:]
            return ':'
        elif request[0]=='^':
            raise SmalltalkCallbackReturn(self.deser(request[1:]))
        else:
            return self.doEval(request);

    def doEval(self, request):
        result = eval(request)
        try:
            return 'J' + json.dumps(result)
        except TypeError:
            return '+' + self.getNonJSON(result)

    def doExec(self, value):
        try:
            exec(value)
            return '+'
        except:
            return '-' + traceback.format_exc()

    def getNonJSON(self, value):
        if inspect.isclass(value):
            return 'type:' + value.__name__
        return value.__class__.__name__ + ':' + value.__str__()

    def deser(self, serializedString):
        if serializedString[0]=='!':
            return SmalltalkObject(self, serializedString[1:])
        return json.loads(serializedString)





class SmalltalkRMIActivation:
    def __init__(self, gate, ident, selector, args, kwargs):
        self.gate = gate
        self.ident = ident
        self.selector = selector
        self.args = args
        self.kwargs = kwargs

    def perform(self):
        k = 'rmiAct' + str(random.randint(0,9999999))
        e[k] = self
        self.gate.write_one('!'+k)
        try:
            self.gate.handle()
        except SmalltalkCallbackReturn as ex:
            return ex.returnValue


class SmalltalkRMI:
    def __init__(self, gate, ident, selector):
        self.gate = gate
        self.ident = ident
        self.selector = selector

    def __call__(self, *args, **kwargs):
        return SmalltalkRMIActivation(self.gate, self.ident, self.selector, args, kwargs).perform()


class SmalltalkObject:
    def __init__(self, gate, ident):
        self.gate = gate
        self.ident = ident

    def __getattribute__(self, name):
        if name=='__class__':
            return SmalltalkObject
        if name=='__str__':
            return object.__getattribute__(self, '__str__')
        return SmalltalkRMI(object.__getattribute__(self, 'gate'), object.__getattribute__(self, 'ident'), name)




socketserver.TCPServer(('',7000), PythonGate).serve_forever()
