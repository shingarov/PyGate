Class {
	#name : #PyBoundMethod,
	#superclass : #External,
	#category : #'PyGate-Core'
}

{ #category : #private }
PyBoundMethod class >> pythonClassName [ 
	^'instancemethod'
]

{ #category : #GT }
PyBoundMethod >> gtInspectorItemsIn: composite [
	"No items presentation for an instancemethod"
]

{ #category : #GT }
PyBoundMethod >> gtInspectorTextIn: composite [
	<gtInspectorPresentationOrder: 10>
	composite text
		title: 'source';
		display: [ P compute: 'inspect.getsource(', self ref, ')' ]
]
