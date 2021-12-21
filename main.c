#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#define ZPP_DEFINE
#define ZPP_LINKAGE static
#include "zpp.h"

#include <stdio.h>
#include <stdlib.h>

// NOTE: only for testing
static char *read_whole_file(char const *path)
{
    FILE *file = fopen(path, "rb");

    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *result = malloc(file_size + 1);
    fread(result, 1, file_size, file);
    fclose(file);

    result[file_size] = '\0';
    return result;
}

// TODO: maybe put this into the zpp library
static void ZPP_format_error(ZPP_Error const *error,
                             char *buffer,
                             size_t buffer_size)
{
    static char const *error_messages[] = {
        [ZPP_ERROR_UNEXPECTED_EOF]   = "unexpected eof found",
        [ZPP_ERROR_UNTERMINATED_STR] = "unterminated string literal",
        [ZPP_ERROR_UNTERMINATED_CHR] = "unterminated char literal",
        [ZPP_ERROR_UNEXPECTED_EOL]   = "unexpected eol found",
        [ZPP_ERROR_UNEXPECTED_TOK]   = "unexpected token found",
    };
    
    snprintf(buffer, buffer_size,
             "<source>:%u:%u: error: %s",
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

int main(void)
{
    ZPP_State state = {
        .allocator = &(ZPP_Allocator)
        {
            .gen_free    = &alloc_gen_free,
            .gen_alloc   = &alloc_gen_alloc,
            .gen_calloc  = &alloc_gen_calloc,
            .gen_realloc = &alloc_gen_realloc,
        },
        .lexer =
        {
            .pos.ptr = read_whole_file("Z:/projects/zpp/zpp.h"),
        },
    };

    if (ZPP_init_state(&state) <= 0) return 1;

    size_t last_row = 0;    
    for(;;)
    {
        ZPP_Error error = {0};
        int error_result =
            ZPP_read_token(&state, &error);

        if (error_result == 0)
        {
            break;
        }
        else if (error_result == -1)
        {
            char buffer[1024] = {0};
            ZPP_format_error(&error, buffer, sizeof buffer);
            printf("\n%s\n", buffer);
            break;
        }

        ZPP_Token token = state.lexer.result;
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

    printf("\n\n---------------------\n"
           "Macros defined:\n");
    for (uint32_t i = 0; i < state.macro_map.cap; ++i)
    {
        if (state.macro_map.keys[i].name.ptr == NULL ||
            state.macro_map.keys[i].is_dead)
        {
            continue;
        }

        printf("#define %.*s",
               (int)state.macro_map.keys[i].name.len,
               state.macro_map.keys[i].name.ptr);

        ZPP_Macro *macro = &state.macro_map.keys[i];
        for (uint32_t j = 0; j < macro->token_len; ++j)
        {
            if((macro->tokens[j].flags & ZPP_TOKEN_SPACE) != 0)
            {
                fputc(' ', stdout);
            }
            
            printf("%.*s",
                   (int)macro->tokens[j].len,
                   macro->tokens[j].pos.ptr);
        }

        printf("\n");
    }
}
