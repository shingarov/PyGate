Class {
	#name : #BaselineOfPyGate,
	#superclass : #BaselineOf,
	#category : #BaselineOfPyGate
}

{ #category : #baselines }
BaselineOfPyGate >> baseline: spec [
	<baseline>
	spec
		for: #pharo
		do: [ 
			spec baseline: 'NeoJSON' with: [spec repository: 'github://svenvc/NeoJSON'].
			spec package: #'PyGate' with:[spec requires: #('NeoJSON')]
		]
]
