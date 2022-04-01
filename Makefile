CC=clang-cl
SRC=main.c
BIN=prog.exe
MODE=DEBUG
FLAGS=-nologo -W4 -permissive- -GS-
LIBS=kernel32.lib
LINK_FLAGS=-link -incremental:no -out:$(BIN)

!IF "$(MODE)" == "DEBUG"
FLAGS=$(FLAGS) -Od -Zi
LINK_FLAGS=$(LINK_FLAGS) -debug
!ELSE
FLAGS=$(FLAGS) -O2 -Oi
!ENDIF

!IF "$(CC)" == "clang-cl"
FLAGS=$(FLAGS) -Werror-implicit-function-declaration \
	-clang:"-fdiagnostics-format=clang" -Wsign-conversion
!ENDIF

all: 
	@$(CC) $(FLAGS) $(SRC) $(LINK_FLAGS) $(LIBS)

.IGNORE:
clean:
	@del *.obj
	@del *.pdb
	@del *.exe
	@del *.lib
	@del *.exp
!CMDSWITCHES
