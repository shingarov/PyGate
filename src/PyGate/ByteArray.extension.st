Extension { #name : #ByteArray }

{ #category : #'*PyGate' }
ByteArray >> representSmalltalkInPython [
	| str |
	str := self inject: 'bytes(b''' into: [ :soFar :thisByte |
		soFar, '\x', (thisByte printStringBase: 16 nDigits: 2) ] .
	
	^ str, ''')'
]
