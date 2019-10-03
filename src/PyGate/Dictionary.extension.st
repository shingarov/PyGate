Extension { #name : #Dictionary }

{ #category : #'*PyGate' }
Dictionary >> representSmalltalkInPython [
	| r var |
	r := 'dict ( ', (GenericPyObject representNamedArgs: self), ' )'.
	var := P evalAndAssign: r.
	^var ref
]
