Class {
	#name : #PyMethod,
	#superclass : #External,
	#category : #'PyGate-Core'
}

{ #category : #private }
PyMethod class >> pythonClassName [ 
	^'method'
]

{ #category : #GT }
PyMethod >> gtInspectorItemsIn: composite [
	"No items presentation for an instancemethod"
]

{ #category : #GT }
PyMethod >> gtInspectorTextIn: composite [
	<gtInspectorPresentationOrder: 10>
	composite text
		title: 'source';
		display: [ P compute: 'inspect.getsource(', self ref, ')' ]
]
