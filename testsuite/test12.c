
#define X 1
#define Y 2
int pmx0 = X;
int pmy0 = Y;
#define Y 3
#pragma push_macro("Y")
#pragma push_macro("X")
int pmx1 = X;
#define X 2
int pmx2 = X;
#pragma pop_macro("X")
int pmx3 = X;
#pragma pop_macro("Y")
int pmy1 = Y;

// Have a stray 'push' to show we don't crash when having imbalanced
// push/pop
#pragma push_macro("Y")
#define Y 4
int pmy2 = Y;

// The sequence push, define/undef, pop caused problems if macro was not
// previously defined.
#pragma push_macro("PREVIOUSLY_UNDEFINED1")
#undef PREVIOUSLY_UNDEFINED1
#pragma pop_macro("PREVIOUSLY_UNDEFINED1")
#ifndef PREVIOUSLY_UNDEFINED1
int Q;
#endif

#pragma push_macro("PREVIOUSLY_UNDEFINED2")
#define PREVIOUSLY_UNDEFINED2
#pragma pop_macro("PREVIOUSLY_UNDEFINED2")
#ifndef PREVIOUSLY_UNDEFINED2
int P;
#endif

#define FOO(a, b) {a,b}
int j = FOO(3, 4);

#pragma push_macro("FOO")

#undef FOO
#define FOO 12
int k = FOO;

#pragma pop_macro("FOO")

int o = FOO(1, 2);

// CHECK: int pmx0 = 1
// CHECK: int pmy0 = 2
// CHECK: int pmx1 = 1
// CHECK: int pmx2 = 2
// CHECK: int pmx3 = 1
// CHECK: int pmy1 = 3
// CHECK: int pmy2 = 4
// CHECK: int Q;
// CHECK: int P;
// CHECK: int j = {3, 4};
// CHECK: int k = 12;
// CHECK: int o = {1, 2};
