Class {
	#name : #ExternalID,
	#superclass : #Object,
	#instVars : [
		'x'
	],
	#category : #'PyGate-Core'
}

{ #category : #'instance creation' }
ExternalID class >> named: varName [
	^super new
		name: varName;
		yourself 
]

{ #category : #'instance creation' }
ExternalID class >> new [
	^self named: self newName
]

{ #category : #'instance creation' }
ExternalID class >> newName [
	^'Var', (100000000 atRandom printStringBase: 32)
]

{ #category : #'as yet unclassified' }
ExternalID >> , aString [
	^ExternalID named: self ref, aString "NB: not self class, because that's ExternalVar"
]

{ #category : #accessing }
ExternalID >> name [
	^ x
]

{ #category : #accessing }
ExternalID >> name: anObject [
	x := anObject
]

{ #category : #'as yet unclassified' }
ExternalID >> pointsToClass [
	^P compute: 'inspect.isclass(', self ref, ')'
]

{ #category : #printing }
ExternalID >> printOn: aStream [
	aStream nextPutAll: self name
]

{ #category : #printing }
ExternalID >> printString [
	^self name
]

{ #category : #accessing }
ExternalID >> pyClass [
	^P compute: self ref, '.__class__'
]

{ #category : #accessing }
ExternalID >> pythonClassName [
	^P eval: self ref, '.__class__.__name__'
]

{ #category : #accessing }
ExternalID >> pythonStr [
	^P eval: self ref, '.__str__()'
]

{ #category : #'python engine' }
ExternalID >> ref [
	"NB: This is probably not what you want.
	See ExternalVar>>#ref.
	This case is when you have an expression you want to reference literally."
	^self name
]

{ #category : #'python engine' }
ExternalID >> value [ 
	^P fetchVar: self
]
