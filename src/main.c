#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#define ZPP_DEFINE
#define ZPP_LINKAGE static
#include "zpp.h"

#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// NOTE: only for testing
static char *read_whole_file(char const *path)
{
    FILE *file = fopen(path, "rb");

    if (file == NULL)
    {
        return NULL;
    }
    
    fseek(file, 0, SEEK_END);
    size_t file_size = (size_t)ftell(file);
    fseek(file, 0, SEEK_SET);

    char *result = malloc(file_size + 1);
    fread(result, 1, file_size, file);
    fclose(file);

    result[file_size] = '\0';
    return result;
}

// TODO: maybe put this into the zpp library
static void ZPP_print_error(ZPP_Error const *error)
{
    static char const *error_messages[] = {
        [ZPP_ERROR_UNEXPECTED_EOF]   = "unexpected eof found",
        [ZPP_ERROR_UNTERMINATED_STR] = "unterminated string literal",
        [ZPP_ERROR_UNTERMINATED_CHR] = "unterminated char literal",
        [ZPP_ERROR_UNEXPECTED_EOL]   = "unexpected eol found",
        [ZPP_ERROR_UNEXPECTED_TOK]   = "unexpected token found",
        [ZPP_ERROR_INVALID_MACRO] = "invalid macro found",
        [ZPP_ERROR_INVALID_PASTE] = "invalid paste formed",
    };
    
    printf("\n<source>:%u:%u: error: %s\n",
           error->row + 1, error->col,
           error_messages[error->error_code]);
}

static void *alloc_gen_alloc(void *ctx, size_t size)
{
    (void)ctx;
    return malloc(size);
}

static void *alloc_gen_calloc(void *ctx, size_t size)
{
    (void)ctx;
    return calloc(size, 1);
}

static void *alloc_gen_realloc(void *ctx, void *ptr, size_t size)
{
    (void)ctx;
    return realloc(ptr, size);
}

static void alloc_gen_free(void *ctx, void *ptr)
{
    (void)ctx;
    free(ptr);
}


static int ZPP_define_macro(ZPP_State *state,
                            ZPP_Error *error, 
                            char *name, char *val)
{
    ZPP_Lexer lexer = {
        .pos =
        {
            .ptr = val,
        },
    };

    int ec;
    if ((ec = ZPP_lexer_lex_direct(&lexer, error)) < 0)
    {
        return ec;
    }

    ZPP_Token *tokens = NULL;
    if (ec != 0)
    {
        tokens = ZPP_ARRAY_NEW3(sizeof *tokens, 1);
        tokens[0] = lexer.result;
    }
    
    ZPP_String text_str = {
        .ptr = name,
        .len = strlen(name),
    };

    ZPP_Ident *old_macro =
        ZPP_ident_map_get(state, text_str);
    
    ZPP_Ident new_macro = {
        .tokens = tokens,
        .token_len = tokens != NULL,
        .name = text_str.ptr,
        .name_len = (uint32_t)text_str.len,
        .is_macro = true,
    };

    if (old_macro != NULL)
    {
        new_macro.name = old_macro->name;
        new_macro.hash = old_macro->hash;

        ZPP_ARRAY_FREE(old_macro->tokens);
        *old_macro = new_macro;
    }
    else
    {
        ZPP_ident_map_set(state, &new_macro);
    }

    ZPP_gen_free(state, tokens);
    return 1;
}

// TODO: make sure to add space when two tokens cannot paste e.g. | | != ||, a | == a|
int main(int argc, char **argv)
{
    int ec = 0;
    ZPP_Error error = {0};

    time_t start_time = time(NULL);
    ZPP_State state = {
        .allocator = &(ZPP_Allocator)
        {
            .gen_free    = &alloc_gen_free,
            .gen_alloc   = &alloc_gen_alloc,
            .gen_calloc  = &alloc_gen_calloc,
            .gen_realloc = &alloc_gen_realloc,
        },
    };

    if (ZPP_init_state(&state, NULL) < 0) return 1;

    char *file_path = NULL;
    bool print_time = false;
    bool dump_macros = false;
    for (int i = 1; i < argc; ++i)
    {
        if (argv[i][0] == '-' && argv[i][1] == 'D')
        {
            char *macro_name = argv[i] + 2;
            if (*macro_name == '\0') continue;
            
            char *macro_val = strstr(macro_name, "=");
            if (macro_val == NULL) macro_val = "";
            else macro_val[-1] = '\0';
            
            if (ZPP_define_macro(&state, &error, 
                                 macro_name, macro_val) < 0)
            {
                goto error;
            }  
                                
        }
        else if (strcmp(argv[i], "--dump") == 0)
        {
            dump_macros = true;
        }
        else if (strcmp(argv[i], "--time") == 0)
        {
            print_time = true;
        }
        else
        {
            file_path = argv[i];
        }
    }
    
    if (file_path == NULL) return 0;
    char *file_data = read_whole_file(file_path);

    if (file_data == NULL) return 1;
    if (ZPP_init_state(&state, file_data) <= 0) return 1;

    size_t last_row = 0;    
    for(;;)
    {
        ec = ZPP_read_token(&state, &error);
        if (ec == 0)
        {
            break;
        }
        else if (ec == -1)
        {
            goto error;
            break;
        }

        ZPP_Token token = state.result;
        if (token.pos.row != last_row)
        {
            size_t line_difference = token.pos.row - last_row;
            if (line_difference < 3)
            {
                fwrite("\n\n", 1, line_difference, stdout);
            }
            else
            {
                printf("\n#line %u\n", token.pos.row + 1);
            }

            last_row = token.pos.row;
        }

        if ((token.flags & ZPP_TOKEN_SPACE) != 0)
        {
            fputc(' ', stdout);
        }
        
        fwrite(token.pos.ptr, 1, token.len, stdout);
    }
    
    time_t end_time = time(NULL);
    if (dump_macros)
    {
        printf("\n\n---------------------\n"
               "Macros defined:\n");
        for (uint32_t i = 0; i < state.ident_map.cap; ++i)
        {
            if (!state.ident_map.keys[i].is_alive ||
                !state.ident_map.keys[i].is_macro)
            {
                continue;
            }
        
            ZPP_Ident *macro = &state.ident_map.keys[i];

            printf("#define %.*s",
                   (int)macro->name_len, macro->name);

            if (macro->is_fn_macro)
            {
                printf("(");
                for (uint32_t j = 0; j < macro->arg_len; ++j)
                {
                    printf("%.*s",
                           (int)macro->args[j].len,
                           macro->args[j].ptr);

                    if (j + 1 < macro->arg_len)
                    {
                        printf(", ");
                    }
                }
                printf(")");
            }

            printf(" ");
            
            for (uint32_t j = 0; j < macro->token_len; ++j)
            {
                ZPP_Token token = macro->tokens[j];
                if((token.flags & ZPP_TOKEN_SPACE) != 0)
                {
                    fputc(' ', stdout);
                }

                if ((token.flags & ZPP_TOKEN_MACRO_ARG) != 0)
                {
                    ZPP_String arg = macro->args[token.len];
                    token = (ZPP_Token) {
                        .len = (uint32_t)arg.len,
                        .pos.ptr = arg.ptr, 
                    };
                }

                printf("%.*s", (int)token.len, token.pos.ptr);
            }

            printf("\n");
            fflush(stdout);
        }
    }
    
    if (print_time)
    {
        printf("\nIt took %g seconds.\n",
               (double)(end_time - start_time) / CLOCKS_PER_SEC);
    }

    return 0;
    
error:
    ZPP_print_error(&error);
}
