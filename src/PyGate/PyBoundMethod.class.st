Class {
	#name : #PyBoundMethod,
	#superclass : #PyMethod,
	#category : #'PyGate-Core'
}

{ #category : #private }
PyBoundMethod class >> pythonClassName [ 
	^'instancemethod'
]
