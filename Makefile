CC=cl
LINK=link
SRC=src
EXE=prog.exe
BIN=bin
MODE=RELEASE
FLAGS=-nologo -W4 -permissive- -wd4200
LIBS=kernel32.lib
LINK_FLAGS=-incremental:no -out:$(EXE)

!IF "$(MODE)" == "DEBUG"
FLAGS=$(FLAGS) -Od -Zi
LINK_FLAGS=$(LINK_FLAGS) -debug
!ELSE
FLAGS=$(FLAGS) -O2 -Oi -Zi
!ENDIF

!IF "$(CC)" == "clang-cl"
FLAGS=$(FLAGS) -Werror-implicit-function-declaration \
	-clang:"-fdiagnostics-format=clang" -Wsign-conversion
!ENDIF

$(EXE): $(SRC)\*.c $(SRC)\*.h
	@$(CC) $(FLAGS) -Fo$(BIN)\ $(SRC)\*.c -link $(LINK_FLAGS) $(LIBS) -out:$(EXE)
all: $(EXE)

.IGNORE:
clean:
	@del *.obj
	@del *.pdb
	@del $(EXE)
	@del *.lib
	@del *.exp
!CMDSWITCHES
