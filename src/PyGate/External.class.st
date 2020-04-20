"
I am the base superclass of all things mocked via Python libraries.
"
Class {
	#name : #External,
	#superclass : #Object,
	#instVars : [
		'var'
	],
	#category : #'PyGate-Core'
}

{ #category : #'instance creation' }
External class >> construct: aPythonExpressionString [
	| var |
	var := P evalAndAssign: aPythonExpressionString.
	^self var: var
]

{ #category : #'instance creation' }
External class >> fromExternalID: anExternalID [ 
	^self var: anExternalID 
]

{ #category : #'instance creation' }
External class >> sendSmalltalkObject: anObject [
	^self var: (P sendAndAssignObject: anObject)
]

{ #category : #private }
External class >> var: v [
	^self basicNew 
		var: v;
		yourself
]

{ #category : #access }
External >> @ attrName [
	^self at: attrName
]

{ #category : #dispatching }
External >> _dispatch: id arguments: args ifFail: failBlock [
	| callable |
	callable := self ref, '.', id.
	(args size = 1 and: [ args first isCollection and: [ args first isSequenceable not ] ])  ifTrue: [
		"we have named arguments given as a Dictionary"
		^GenericPyObject create: callable constructorNamedArgs: args first
	].
	"a non-orthogonal special case is when the one argument is an association"
	(args size = 1 and: [ args first isKindOf: Association ]) ifTrue: [
		| dict |
		dict := Dictionary newFromAssociations: (Array with: args first).
		^self _dispatch: id arguments: (Array with: dict) ifFail: failBlock
	].
	"everything else should be sequential arguments"
	^GenericPyObject create: callable constructorSequentialArgs: args
]

{ #category : #access }
External >> at: attrName [
	^P compute: self ref, '.', attrName 
]

{ #category : #access }
External >> at: attrName put: x [
	^P rawExec:
		self ref,
		'.',
		attrName,
		' = ',
		x representSmalltalkInPython
]

{ #category : #access }
External >> dir [
	^P compute: 'dir(', self ref, ')'
]

{ #category : #dispatching }
External >> doesNotUnderstand: aMessage [
	| id args |
	id := aMessage selector asString copyUpTo: $:.
	args := aMessage arguments.
	^self _dispatch: id
		arguments: args
		ifFail: [ ^super doesNotUnderstand: aMessage ]
]

{ #category : #GT }
External >> gtInspectorItemsIn: composite [
	<gtInspectorPresentationOrder: 40>
	| everything |
	everything := self dir collect: [ :key | key -> ([P compute: self ref, '.', key] on: Error do: ['????? error getting ', key]) ].
	^ (composite fastTable)
		title: 'dir()';
		display: [ everything ];
		column: 'Reg' evaluated: #key;
		column: 'Value' evaluated: #value;
		beSingle;
		send: [ :selection | 
			selection isNil 
			ifTrue:[nil]
			ifFalse:[ selection value ]]
]

{ #category : #printing }
External >> printOn: aStream [
	aStream nextPutAll: self var pythonStr
]

{ #category : #access }
External >> pyClass [
	^self var pyClass
]

{ #category : #private }
External >> ref [ 
	^self var ref
]

{ #category : #private }
External >> representSmalltalkInPython [
	^self ref
]

{ #category : #private }
External >> var [
	^ var
]

{ #category : #private }
External >> var: anExternalID [
	var := anExternalID
]
