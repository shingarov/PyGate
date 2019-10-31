Class {
	#name : #UnderscoreCompilationTest,
	#superclass : #TestCase,
	#category : #'PyGate-Tests'
}

{ #category : #tests }
UnderscoreCompilationTest >> _underscoredSelector [
	^1
]

{ #category : #tests }
UnderscoreCompilationTest >> testUnderscoredArgName [
	self assert: (self underscoredArgName: 1) equals: 2
]

{ #category : #tests }
UnderscoreCompilationTest >> testUnderscoredSelector [
	self assert: self _underscoredSelector  equals: 1 
]

{ #category : #tests }
UnderscoreCompilationTest >> underscoredArgName: _x [
	^_x + 1
]
