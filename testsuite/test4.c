#define LPAREN ( 
#define RPAREN ) 
#define F(x, y) x + y 
#define ELLIP_FUNC(...) __VA_ARGS__ 

1: ELLIP_FUNC(F, LPAREN, 'a', 'b', RPAREN); /* 1st invocation */ 
2: ELLIP_FUNC(F LPAREN 'a', 'b' RPAREN); /* 2nd invocation */ 

// CHECK: 1: F, (, 'a', 'b', );
// CHECK: 2: 'a' + 'b';

/* Right paren scanning, hard case.  Should expand to 3. */
#define i(x) 3,x 
#define a i(yz 
#define b ) 
a b ) ; 

// CHECK:3 ;

#define X() Y
#define Y() X

A: X()()()
// CHECK: {{^}}A: Y{{$}}

// PR3927
#define f(x) h(x
#define for(x) h(x
#define h(x) x()
B: f(f))
C: for(for))

// CHECK: {{^}}B: f(){{$}}
// CHECK: {{^}}C: for(){{$}}

#define cat(a, b) a##b
#define bar(x) [x()] 
#define foo(x) bar(cat(fo,o)
foo())
