#define buz foo(1, 1)
#define bar(...) [__VA_ARGS__]
#define fuz0(x) bar(1, x, buz
#define fuz1(x) {x}
#define tar0(x) bar(1, x, tar(1, 1)
#define tar1(x) {x}
#define foo(x, n) fuz##n(x)
#define far(x, n) tar##n(x)

// NOTE: this is supposed to match only clang and gcc.
foo(3, 0)) // [1, 3, {1}]
far(3, 0)) // [1, 3, far(1, 1)]
