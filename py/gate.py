"""Python Gate server.

"""


import pdb, traceback
import inspect, sys, json
import socket, SocketServer
import claripy, angr, pyvex, archinfo

e = {}

class PythonGate(SocketServer.StreamRequestHandler):

    def handle_one_packet(self):
        try:
            requestline = self.rfile.readline()
            sys.stdout.write("> %s" % requestline)
            answer = self.getAnswer(requestline) + '\r\n'
            self.wfile.write(answer)
            sys.stdout.write("< %s" % answer)
            self.wfile.flush()
        except socket.timeout, e:
            os._exit(0)
            return

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
        return json.loads(serializedString)

SocketServer.TCPServer(('',7000), PythonGate).serve_forever()
