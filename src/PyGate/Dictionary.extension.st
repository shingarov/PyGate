Extension { #name : #Dictionary }

{ #category : #'*PyGate' }
Dictionary >> representSmalltalkInPython [
	| r var |
	
	"Implementation note.
	At one point, we used the constructor dict(**kwarg).
	This breaks if a key is not a valid identifier, e.g. an integer."


	r := self associations inject: '{ ' into: [ :soFar :thisTime |
		| ref keyRef |
		ref := thisTime value representSmalltalkInPython.
		keyRef := thisTime key isInteger 
			ifTrue: [ thisTime key representSmalltalkInPython ]
			ifFalse: [ thisTime key ].
		soFar,
		keyRef,
		' : ',
		ref,
		',' ].
	r := r, ' }'.

	var := P evalAndAssign: r.
	^var ref
]
