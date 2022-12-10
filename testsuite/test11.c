char *foo = "foo\
foo";

char *bar= "foo\
\
\
bar\
foo";

char *far = L\
"foo\
foo";

char *boo= L\
"foo\
\
\
bar\
foo";

#define LSTR(x) L##x

LSTR("FOO")
LSTR("BAR")

L"FOO"
L"BOO"
