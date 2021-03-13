Extension { #name : #Object }

{ #category : #'*PyGate' }
Object >> representSmalltalkInPython [
	^(P sendAndAssignObject: self) ref
]

{ #category : #'*PyGate' }
Object >> serializeOrRemember [
	^[NeoJSONWriter toString: self]
		on: NeoJSONMappingNotFound
		do: [^'!stHeap', ((P current keyForSmalltalkObject: self) printStringBase: 32)]
]
