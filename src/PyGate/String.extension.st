Extension { #name : #String }

{ #category : #'*PyGate' }
String >> representSmalltalkInPython [
	^'"', self, '"'
]
