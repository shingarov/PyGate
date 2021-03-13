Class {
	#name : #PythonCallbackActivation,
	#superclass : #External,
	#category : #'PyGate-Core'
}

{ #category : #'instance creation' }
PythonCallbackActivation class >> new: aVarName [
	^P fetchVar: (ExternalVar named: aVarName)
]

{ #category : #private }
PythonCallbackActivation class >> pythonClassName [ 
	^'SmalltalkRMIActivation'
]

{ #category : #activation }
PythonCallbackActivation >> activate [ 
	| sel |
	sel := self selector asSymbol.
	self args size = 0 ifFalse: [ 	self shouldBeImplemented ].
	self kwargs size = 0 ifFalse: [ self shouldBeImplemented ].
	^self receiver perform: sel
]

{ #category : #activation }
PythonCallbackActivation >> activateAndReturn [
	| return |
	return := self activate.
	^P eval: '^', return serializeOrRemember
]

{ #category : #accessing }
PythonCallbackActivation >> args [
	^self @ 'args'
]

{ #category : #accessing }
PythonCallbackActivation >> ident [
	^self @ 'ident'
]

{ #category : #accessing }
PythonCallbackActivation >> kwargs [
	^self @ 'kwargs'
]

{ #category : #accessing }
PythonCallbackActivation >> receiver [
	| stHeapXXXX xxxx |
	stHeapXXXX := self ident.
	(stHeapXXXX first: 6) = 'stHeap' ifFalse: [self error].
	xxxx := Integer readFrom: (stHeapXXXX allButFirst: 6) base: 32.
	^P current smalltalkObjectAtKey: xxxx
]

{ #category : #accessing }
PythonCallbackActivation >> selector [
	^self @ 'selector'
]
