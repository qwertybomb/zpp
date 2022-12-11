#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "platform.h"

#define ZPP_DEFINE
#define ZPP_LINKAGE static
#include "zpp.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

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
static void ZPP_print_error(ZPP_Error *error)
{
    printf("%s:%u:%u: error: %.*s\n",
           error->file, error->row + 1, error->col +1,
           (int)error->msg_len, error->msg);
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

static void canonicalize_path_impl(void *ctx, char *path)
{
    (void)ctx;
    canonicalize_path(path);
}

static char *open_file_impl(void *ctx, char const *path)
{
    (void)ctx;
    return read_whole_file(path);
}

// TODO: make sure to add space when two tokens cannot paste e.g. | | != ||, a | == a|
int main(int argc, char **argv)
{
    int ec = 0;
    ZPP_Error error = {0};

    start_clock();
    int64_t start_time = get_clock();
    ZPP_State state = {
        .platform = &(ZPP_Platform)
        {
            .open_file   = &open_file_impl,
            .gen_free    = &alloc_gen_free,
            .gen_alloc   = &alloc_gen_alloc,
            .gen_calloc  = &alloc_gen_calloc,
            .gen_realloc = &alloc_gen_realloc,
            .canonicalize_path = &canonicalize_path_impl,
        },
    };

    if (ZPP_init_state(&state, NULL, "") < 0)
    {
        return 1;
    }

    char *file_path = NULL;
    bool print_time = false;
    bool dump_macros = false;
    for (int i = 1; i < argc; ++i)
    {
        if (argv[i][0] == '-' && argv[i][1] == 'D')
        {
            char *macro_name = argv[i] + 2;
            if (*macro_name == '\0') continue;
            
            char *macro_val;
            if ((macro_val = strstr(macro_name, "=")) == NULL)
            {
                macro_val = "";
        
            }
            else
            {
                *macro_val++ = '\0';
            }
            
            if (ZPP_user_define_macro(&state, &error, 
                                      macro_name, macro_val) < 0)
            {
                error.file = "<arg>";
                ZPP_print_error(&error);
                return 1;
            }  
                                
        }
        else if (argv[i][0] == '-' && argv[i][1] == 'I')
        {
            char *include_path = argv[i] + 2;
            if (*include_path == '\0')
            {
                if (i + 1 > argc) continue;
                include_path = argv[++i];
            }

            ZPP_include_path_add(&state,
                                 (ZPP_String) {
                                     .ptr = include_path,
                                     .len = strlen(include_path),
                                 });
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
    if (ZPP_init_state(&state, file_data, file_path) <= 0)
    {
        return 1;
    }

    size_t last_row = 0;
    char const *last_file = file_path;
    for(;;)
    {
        ec = ZPP_read_token(&state, &error);
        if (ec == 0)
        {
            break;
        }
        else if (ec == -1)
        {
            putchar('\n');
            ZPP_print_error(&error);
            return 1;
        }

        ZPP_Token token = state.result;
        if (token.pos.file != last_file)
        {
            printf("\n#line %u %s\n", token.pos.row, token.pos.file);
        }
        else if (token.pos.row != last_row)
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
        }

        last_row = token.pos.row;
        last_file = token.pos.file;
        
        if ((token.flags & ZPP_TOKEN_SPACE) != 0)
        {
            fputc(' ', stdout);
        }
        
        fwrite(token.pos.ptr, 1, token.len, stdout);
    }
    
    int64_t end_time = get_clock();
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
        }
    }
    
    if (print_time)
    {
        printf("\nIt took %g seconds.\n",
               (double)(end_time - start_time)/clocks_per_sec);
    }

    return 0;
}
