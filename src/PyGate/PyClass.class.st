Class {
	#name : #PyClass,
	#superclass : #External,
	#category : #'PyGate-Core'
}

{ #category : #printing }
PyClass >> name [
	^P compute: self ref, '.__name__'
]

{ #category : #printing }
PyClass >> printOn: aStream [
	aStream nextPutAll: self name
]

{ #category : #printing }
PyClass >> superclassChain [
	^GenericPyObject create: 'inspect.getmro' constructorSequentialArgs: (Array with: self)
]
