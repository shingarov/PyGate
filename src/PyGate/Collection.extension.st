Extension { #name : #Collection }

{ #category : #'*PyGate' }
Collection >> representSmalltalkInPython [ 
	| s |
	s := self inject: '[ ' into: [ :soFar :item |
			soFar, item representSmalltalkInPython, ', ' ].
	s := s, ' ]'.
	^(P evalAndAssign: s) ref
]
