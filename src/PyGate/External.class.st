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
	^self new 
		var: v;
		yourself
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
