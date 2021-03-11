Extension { #name : #Object }

{ #category : #'*PyGate' }
Object >> representSmalltalkInPython [
	^(P sendAndAssignObject: self) ref
]

{ #category : #'*PyGate' }
Object >> serializeOrRemember [
	^[NeoJSONWriter toString: self]
		on: NeoJSONMappingNotFound do: [ | key |
			key := 999999.  "(100000000 atRandom)"
			P current smalltalk at: key put: self.
			^'!stHeap', (key printStringBase: 32)  ]
]
