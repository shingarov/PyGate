Class {
	#name : #PyGateCallbackTest,
	#superclass : #TestCase,
	#category : #'PyGate-Tests'
}

{ #category : #tests }
PyGateCallbackTest >> examplePoint [
	^3@4
]

{ #category : #tests }
PyGateCallbackTest >> testIdenticalSmalltalkHeapObjects [ 

| d p1 p2 |
d := Dictionary new.
p1 := 3@4.
p2 := 3@4.
d at: 1 put: p1.


]

{ #category : #tests }
PyGateCallbackTest >> testSendSmalltalkObject [
	| aPoint p result |
	"A Smalltalk object non-serializable via JSON,
	so the proxy on the Python side points back into the Smalltalk heap."
	aPoint := self examplePoint.
	p := P sendAndFetchObject: aPoint.
	"p is a reference to a var in Python containing the proxy
	pointing back into Smalltalk."
	
	"trying to 'invoke a Python method' on such an object will result
	in a PythonCallbackActivation."
	result := P eval: p ref, '.x()'.
	
	self assert: result equals: 3
	
]
