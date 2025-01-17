Class {
	#name : #PTest,
	#superclass : #TestCase,
	#category : #'PyGate-Tests'
}

{ #category : #tests }
PTest >> exampleDict [
	^Dictionary new 
		at: 'b' put: 52.4;
		at: 's' put: 40;
		at: 'm' put: 33.5;
		yourself
]

{ #category : #tests }
PTest >> testAssign [
	| var |
	var := P evalAndAssign: '1+1'.
	self assert: var value equals: 2

]

{ #category : #tests }
PTest >> testConnectivity [
	self assert: (P send: '1') isString
]

{ #category : #tests }
PTest >> testDictionary [
	| answer |
	answer := (P eval: '{"a": 1, "b": 2}').
	self assert: answer isDictionary.
	self assert: (answer at: 'a') equals: 1.
	self assert: (answer at: 'b') equals: 2.
	self assert: (answer size) equals: 2

	
]

{ #category : #tests }
PTest >> testInstantiateDictionary1 [
	| dict d |
	dict := Dictionary new
		at: 'a' put: 1;
		at: 'b' put: 2;
		yourself.
	d := GenericPyObject create: 'dict' constructorNamedArgs: dict.
	self assert: d equals: dict
]

{ #category : #tests }
PTest >> testInstantiateEmptyDictionary [
	| d |
	d := GenericPyObject create: 'dict'.
	self assert: d equals: Dictionary new
	
]

{ #category : #tests }
PTest >> testInstantiateNestedDictionary [
	| dict d |
	dict := Dictionary new
		at: 'i' put: 1;
		at: 'd' put: self exampleDict;
		yourself.
	d := GenericPyObject create: 'dict' constructorNamedArgs: dict.
	"what's remarkable here, is that we are never going to see the
	actual dict which has been created on the python side, because
	#fetchVar: JSON-deserializes it back into a Smalltalk Dictionary"
	self assert: d equals: dict
]

{ #category : #tests }
PTest >> testInstantiateNestedDictionary2 [
	| dict d o gen |
	o := GenericPyObject create: 'object'.
	dict := Dictionary new
		at: 'i' put: 1;
		at: 'd' put: self exampleDict;
		at: 'o' put: o;
		yourself.
	d := GenericPyObject create: 'dict' constructorNamedArgs: dict.

	"VERY TRICKY here.
	As opposed to pre-Ghost, the 'object' nested	deep in
	the tree of values successully gets passed back and forth,
	so we get our dictionary back, and the 'o' key points to
	the GenericPyObject standing for the 'object' on the Python heap."
	self assert: (d isKindOf: Dictionary).
	
	gen := d at: 'o'.
	self assert: (gen isKindOf: GenericPyObject).
	self assert: gen pyClass name equals: 'object'
]

{ #category : #tests }
PTest >> testPyClass [
	| o c |
	o := GenericPyObject create: 'object'.
	self assert: (o isKindOf: GenericPyObject).
	c := o pyClass.
	self assert: (c isKindOf: PyClass).
	self assert: c name equals: 'object'
]

{ #category : #tests }
PTest >> testRawExec [
	| var |
	var := P env: 'testRawExec123'.
	P rawExec: var, ' = 123'.
	"Actually, the raw exec ends here.
	Everything below, is higher level"
	self assert: (P eval: var) equals: 123
]

{ #category : #tests }
PTest >> testReadVarValue [
	| var name ref |
	var := ExternalVar new.
	name := var name.
	ref := P env: name.
	P rawExec: ref, ' = 123'.
	self assert: var value equals: 123

]

{ #category : #tests }
PTest >> testSendByteArrayToP [
	| d |
	d := #[1 2 3 4 5 6 7 8].
	self
		assert: (P sendAndFetchObject: d)
		equals: d
	
]

{ #category : #tests }
PTest >> testSendJsonToP [
	| d |
	d := self exampleDict.
	self
		assert: (P sendAndFetchObject: d)
		equals: d
	
]

{ #category : #tests }
PTest >> testSendLongByteArrayToP [
	| d |
	d := ByteArray new: 4096*2 withAll: 123.
	self
		assert: (P sendAndFetchObject: d)
		equals: d
	
]
