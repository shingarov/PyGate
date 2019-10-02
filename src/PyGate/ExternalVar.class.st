Class {
	#name : #ExternalVar,
	#superclass : #ExternalID,
	#category : #'PyGate-Core'
}

{ #category : #'python engine' }
ExternalVar >> ref [
	^P env: self name
]
