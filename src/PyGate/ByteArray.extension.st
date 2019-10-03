Extension { #name : #ByteArray }

{ #category : #'*PyGate' }
ByteArray >> representSmalltalkInPython [
	| var |
	var := ExternalVar new.
	P sendObject: self andAssignTo: var name.
	^ 'bytes(bytearray(', var ref, '))'
]
