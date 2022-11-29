#define CAT2(a, b) a ## b
#define CAT(a, b) CAT2(a, b)

#define M_2 [123]

#define M_0 CAT(N_, 0)
#define M_1 CAT(N_, 1)()

#define N_0 CAT(M_, 2)
#define N_1() CAT(M_, 2)

a: M_0
b: M_1
/*
  CHECK:
  a: CAT(M_, 2)
  b: [123]
*/

#define A() B
#define B() A
c: A()()();

/*
  CHECK:
  c: B;
*/

#define foo(x) [x]
#define bar foo(bar
#define buz bar buz
d: buz)

/*
  CHECK:
  d: [bar buz]
*/

#define fuzz(a, ...) a ,##__VA_ARGS__ a

fuzz(a fuzz,1,1,1,1,)
