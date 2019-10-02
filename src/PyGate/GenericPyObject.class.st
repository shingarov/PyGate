Class {
	#name : #GenericPyObject,
	#superclass : #External,
	#category : #'PyGate-Core'
}

{ #category : #'python instance creation' }
GenericPyObject class >> create: className [
	^self create: className constructorSequentialArgs: #()
]

{ #category : #'python instance creation' }
GenericPyObject class >> create: constructorFunctionRefString constructorNamedArgs: aDictionary [
	^P compute: constructorFunctionRefString, ' ( ', (self representNamedArgs: aDictionary), ' )'
]

{ #category : #'python instance creation' }
GenericPyObject class >> create: aString constructorSequentialArgs: aCollection [

	^P compute: aString, '(', (self representSequentialArgs: aCollection), ')'
]

{ #category : #private }
GenericPyObject class >> representNamedArgs: aDictionary [
	| argList |
	argList := aDictionary associations inject: '' into: [ :soFar :thisTime |
		| ref |
		ref := thisTime value representSmalltalkInPython.
		soFar,
		thisTime key,
		'=',
		ref,
		',' ].
	^argList
]

{ #category : #private }
GenericPyObject class >> representSequentialArgs: aCollection [
	| argList |
	argList := aCollection inject: '' into: [ :soFar :thisTime |
		| ref |
		ref := thisTime representSmalltalkInPython.
		soFar, ref, ',' ].
	^argList

]
