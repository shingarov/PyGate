Extension { #name : #Object }

{ #category : #'*PyGate' }
Object >> representSmalltalkInPython [
	^(P sendAndAssignObject: self) ref
]
