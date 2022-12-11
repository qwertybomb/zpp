SRC=src
BIN=bin
LINK=link
EXE=zpp.exe
LIBS=kernel32.lib
FLAGS=-nologo -W4 -permissive- -wd4200
LINK_FLAGS=-incremental:no -out:$(EXE)

!IF "$(MODE)" == "RELEASE"
FLAGS=$(FLAGS) -O2 -Oi
!ELSE
FLAGS=$(FLAGS) -Od -Zi
LINK_FLAGS=$(LINK_FLAGS) -debug
!ENDIF

!IF "$(CC)" == "clang-cl"
FLAGS=$(FLAGS) -Werror-implicit-function-declaration \
	-clang:"-fdiagnostics-format=clang" -Wsign-conversion \
	-fdiagnostics-absolute-paths
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
