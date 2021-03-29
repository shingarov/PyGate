Extension { #name : #Dictionary }

{ #category : #'*PyGate' }
Dictionary >> representSmalltalkInPython [
	| r var |
	
	"Implementation note.
	At one point, we used the constructor dict(**kwarg).
	This breaks if a key is not a valid identifier, e.g. an integer."


	r := self associations inject: '{ ' into: [ :soFar :thisTime |
		| ref key keyRef |
		ref := thisTime value representSmalltalkInPython.
		key := thisTime key.
		keyRef := key isInteger 
			ifTrue: [ key representSmalltalkInPython ]
			ifFalse: [ '"',key,'"' ].
		soFar,
		keyRef,
		' : ',
		ref,
		',' ].
	r := r, ' }'.

	var := P evalAndAssign: r.
	^var ref
]
