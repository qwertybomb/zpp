#define SEQ_TERM(...) SEQ_TERM_(__VA_ARGS__)
#define SEQ_TERM_(...) __VA_ARGS__##_RM

#define EMPTY()
#define RPAREN() )

#define TO_GUIDE_A(...) __VA_ARGS__ RPAREN EMPTY()()TO_GUIDE_B
#define TO_GUIDE_B(...) __VA_ARGS__ RPAREN EMPTY()()TO_GUIDE_A
#define TO_GUIDE_A_RM
#define TO_GUIDE_B_RM
#define TO_GUIDE(seq) SEQ_TERM(TO_GUIDE_A seq)

TO_GUIDE((1)(2)(3)(4)(5)) // 1 )2 )3 )4 )5 )

#define TUPLE_AT_1(x,y,...) y
#define CHECK(...) TUPLE_AT_1(__VA_ARGS__,)

#define CAT_GUIDE_END_END ,CAT_GUIDE_END
#define CAT_GUIDE_A(ctx,x) CHECK(CAT_GUIDE_END_##x,CAT_GUIDE_NEXT)(ctx,x,B)
#define CAT_GUIDE_B(ctx,x) CHECK(CAT_GUIDE_END_##x,CAT_GUIDE_NEXT)(ctx,x,A)
#define CAT_GUIDE_NEXT(ctx,x,next) CAT_GUIDE_##next(ctx##x,
#define CAT_GUIDE_END(ctx,x,next) ctx

#define CAT_GUIDE(guide) CAT_GUIDE_A(,guide
#define CAT_SEQ(seq)  CAT_GUIDE(TO_GUIDE(seq(END)))

CAT_SEQ((1)(2)(3)(4)(5)) // 12345

#define SEQ_TERM(...) SEQ_TERM_(__VA_ARGS__)
#define SEQ_TERM_(...) __VA_ARGS__##_RM

#define A(x) f(x),B
#define B(x) f(x),A

#define A_RM
#define B_RM

SEQ_TERM(A(1)(2)(3)(4)(5)) // f(1),f(2),f(3),f(4),f(5),


#define CHECK_EAT(x,y) 
#define CHECK_RESULT(x) CHECK_RESULT_ x
#define CHECK_RESULT_(x,y) y
#define CHECK(P,x,y) CHECK_RESULT((P##x,y))

#define PROBE ,found)CHECK_EAT(

CHECK(,PROBE,not found)     // found
CHECK(,NOT_PROBE,not found) // not found
