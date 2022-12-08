SRC=src
BIN=bin
LINK=link
EXE=prog.exe
MODE=DEBUG
LIBS=kernel32.lib
FLAGS=-nologo -W4 -permissive- -wd4200
LINK_FLAGS=-incremental:no -out:$(EXE)

!IF "$(MODE)" == "DEBUG"
FLAGS=$(FLAGS) -Od -Zi
LINK_FLAGS=$(LINK_FLAGS) -debug
!ELSE
FLAGS=$(FLAGS) -O1 -Oi
!ENDIF

!IF "$(CC)" == "clang-cl"
FLAGS=$(FLAGS) -Werror-implicit-function-declaration \
	-clang:"-fdiagnostics-format=clang" -Wsign-conversion \
	-fdiagnostics-absolute-paths
!IF "$(MODE)" != "DEBUG"
FLAGS=$(FLAGS) -O2
!ENDIF
!ENDIF

all: $(SRC)\*.c $(SRC)\*.h
	@$(CC) $(FLAGS) -Fo$(BIN)\ $(SRC)\*.c \
	-link $(LINK_FLAGS) $(LIBS) -out:$(EXE)

.IGNORE:
clean:
	@del *.obj
	@del *.pdb
	@del $(EXE)
	@del *.lib
	@del *.exp
!CMDSWITCHES
