#ifndef ZPP_ZPP_H
#define ZPP_ZPP_H

/*
  define this yourself if you want to change the linkage of functions
  for example for a dll you might use __declspec(dllimport) or __declspec(dllexport)
*/

#ifndef ZPP_LINKAGE
#define ZPP_LINKAGE
#endif

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/*
  NOTE: regarding whitespace and tokens
  normally in a lexer whitespace is just ignored and skipped.
  however while in a preprocessor we only really need to store 
  if whitespace is behind a token but if we do that when converting
  the tokens back into the source form it will look weird and line/row
  numbers won't match which will make compiler errors cryptic.
*/

enum
{
    ZPP_TOKEN_BOL   = 1 << 1, // token is at the Beginning Of Line
    ZPP_TOKEN_SPACE = 1 << 2, // a space is before this token 
    ZPP_TOKEN_IDENT = 1 << 3, // token is an identifier
    ZPP_TOKEN_PUNCT = 1 << 4, // 6.4.6 Punctuator
    ZPP_TOKEN_PPNUM = 1 << 5, // token is a pp-number
    ZPP_TOKEN_STR   = 1 << 6, // token is a "string" L"literal"
    ZPP_TOKEN_CHAR  = 1 << 7, // token is a {L'c', 'h', 'a', 'r', ' ', l', 't', 'e', 'r', 'a', L'l'}
    ZPP_TOKEN_ALLOC = 1 << 8, // this token is dynamically allocated
    ZPP_TOKEN_MACRO = 1 << 9, // NOTE: internal use only
    ZPP_TOKEN_MACRO_ARG = 1 << 10,
    ZPP_TOKEN_NO_EXPAND = 1 << 11,
};

enum
{
    ZPP_FILE_CONTEXT,
    ZPP_MACRO_CONTEXT,
    ZPP_IF_CONTEXT,
};

enum
{
    ZPP_ERROR_UNEXPECTED_EOF,
    ZPP_ERROR_UNTERMINATED_STR,
    ZPP_ERROR_UNTERMINATED_CHR,
    ZPP_ERROR_UNEXPECTED_EOL,
    ZPP_ERROR_UNEXPECTED_TOK,
    ZPP_ERROR_INVALID_MACRO,
};

typedef struct ZPP_Allocator ZPP_Allocator;
struct ZPP_Allocator
{
    void (*gen_free)(void*, void*);
    void *(*gen_alloc)(void*, size_t);
    void *(*gen_calloc)(void*, size_t);
    void *(*gen_realloc)(void*, void*, size_t);
};

typedef struct
{
    char *ptr;
    uint32_t row;
    uint32_t col;
} ZPP_Pos;

typedef struct
{
    ZPP_Pos pos;
    uint32_t len;
    uint32_t flags;
} ZPP_Token;

typedef struct
{
    uint32_t len;
    uint32_t cap;
    ZPP_Token *ptr;
} ZPP_TokenArray;

typedef struct
{
    uint32_t len;
    uint32_t cap;
    ZPP_TokenArray *ptr;
} ZPP_MacroArgs;

typedef struct ZPP_Context
{
    struct ZPP_Context *prev;
    uint32_t type;
} ZPP_Context;

typedef struct
{
    ZPP_Context base;
    
    ZPP_Pos pos;
    ZPP_Token result;
    
    uint32_t tok_flags;
    bool in_pp_directive : 1;
} ZPP_Lexer;

typedef struct 
{
    uint32_t row;
    uint32_t col;
    uint32_t error_code;
} ZPP_Error;

typedef struct
{
    char *ptr;
    uint32_t len;
} ZPP_String;

// TODO: hash all idents not just macros
typedef struct
{
    ZPP_Token *tokens;
    ZPP_String *args;
    ZPP_String name;
 
    uint32_t hash;
    uint32_t token_len;
    uint32_t arg_len;
    uint32_t expand_level;

    bool is_alive : 1;
    bool is_va_args : 1;
    bool is_fn_macro : 1;
    bool is_macro : 1;
} ZPP_Ident;

typedef struct
{
    ZPP_Context base;
    ZPP_Ident *macro;
    ZPP_Token *tokens;
    uint32_t token_len;
} ZPP_MacroContext;

typedef struct
{
    ZPP_Ident *keys;
    uint32_t len;
    uint32_t cap;
} ZPP_IdentMap;

typedef union
{
    ZPP_Lexer lexer;
    ZPP_Context context;
    ZPP_MacroContext macro_context;
} ZPP_ContextBlock;

typedef struct ZPP_ContextAllocator
{
    size_t len;
    struct ZPP_ContextAllocator *prev;
    ZPP_ContextBlock data[];
} ZPP_ContextAllocator;

typedef struct
{
    ZPP_Context *context; 
    ZPP_Allocator *allocator;
    ZPP_ContextAllocator *context_allocator;
    
    ZPP_IdentMap ident_map;
    ZPP_Token result;

    bool keep_context_allocator : 1;
}  ZPP_State;

ZPP_LINKAGE int ZPP_init_state(ZPP_State *state, char *file_data);
ZPP_LINKAGE int ZPP_read_token(ZPP_State *state, ZPP_Error *error);

/*
  NOTE: regarding functions defined explicitly with `static`.
  these are for internal use only and do not expect them to be stable.
*/

#ifdef ZPP_DEFINE

#define ZPP_LEXER_TRY_READ(l_, e_)                           \
    do                                                       \
    {                                                        \
        ec = ZPP_context_lex_direct(l_, e_);                 \
        if (ec <= 0) return ec;                              \
    } while(false)

#define ZPP_STR_STATIC(str_) ((ZPP_String){.ptr=(str_), .len=sizeof((str_)) - 1})

static void *ZPP_memcpy(void *dest, void const *src, size_t size)
{
    char *dest8 = dest;
    char const *src8 = src;

    while (size-- != 0) *dest8++ = *src8++;
    return dest;
}

static bool ZPP_is_horizontal_space(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\r';          
}

static bool ZPP_is_ident_char(char ch)
{
    return
        (ch >= 'a' && ch <= 'z') ||
        (ch >= 'A' && ch <= 'Z') ||
        ch == '$' || ch == '_';
}

static bool ZPP_is_digit(char ch)
{
    return ch >= '0' && ch <= '9';
}

static bool ZPP_is_newline_escape(char *ptr)
{
    return
        ptr[0] == '\\' &&
        (ptr[0] == '\n' ||
         (ptr[1] == '\r' && ptr[2] == '\n'));
}

static int ZPP_pos_return_error(ZPP_Pos *pos,
                                ZPP_Error *error,
                                uint32_t error_code)
{
    error->row = pos->row;
    error->col = pos->col;
    error->error_code = error_code;
    return -1;
}

// NOTE: before using this remember to save the old location
static char ZPP_lexer_read_char(ZPP_Lexer *lexer)
{
    if (ZPP_is_newline_escape(lexer->pos.ptr))
    {
        do
        {
            ++lexer->pos.row;
            lexer->pos.col = 0;
            lexer->pos.ptr += lexer->pos.ptr[1] == '\r' ? 3 : 2;
        } while(ZPP_is_newline_escape(lexer->pos.ptr));
    }
 
    ++lexer->pos.col;
    return *lexer->pos.ptr++;
}

static int ZPP_lexer_read_string_rest(ZPP_Lexer *lexer, ZPP_Error *error, char delimiter)
{
    // NOTE: because the caller might pass a COW memory map we don't want to always write
    bool write_mode = false;
    char *write_ptr = lexer->pos.ptr;

    char last_chars[2] = {0};
    for(;;)
    {
        if (ZPP_is_newline_escape(lexer->pos.ptr))
        {
            do
            {
                ++lexer->pos.row;
                lexer->pos.col = 0;
                lexer->pos.ptr += lexer->pos.ptr[1] == '\r' ? 3 : 2;
            } while(ZPP_is_newline_escape(lexer->pos.ptr));
            write_mode = true;
        }

        char ch = *lexer->pos.ptr;
        if (ch == '\n' || ch == '\0')
        {
            return ZPP_pos_return_error(&lexer->pos, error,
                                        delimiter == '"'           ?
                                        ZPP_ERROR_UNTERMINATED_STR :
                                        ZPP_ERROR_UNTERMINATED_CHR);
        }
        
        if (write_mode)
        {
            *write_ptr = *lexer->pos.ptr;
        }
        
        ++write_ptr;
        ++lexer->pos.ptr;
        ++lexer->pos.col;
        ++lexer->result.len;
        
        // check for a delimiter and make sure we have
        // (<delim> or \\<delim>) and not \<delim>  
        if (ch == delimiter &&
            (last_chars[0] != '\\' ||
             (last_chars[0] == '\\' &&
              last_chars[1] == '\\')))
        {
            return 1;
        }

        last_chars[1] = last_chars[0];
        last_chars[0] = ch;
    }
}

static int ZPP_lexer_read_ident_rest(ZPP_Lexer *lexer,
                                     ZPP_Error *error)
{
    (void)error;
    do
    {
        ++lexer->result.len;
        ++lexer->pos.col;
        ++lexer->pos.ptr;
    } while (ZPP_is_ident_char(*lexer->pos.ptr) ||
             ZPP_is_digit(*lexer->pos.ptr));

    lexer->result.flags |= ZPP_TOKEN_IDENT;
    return 1;
}

static int ZPP_lexer_lex_direct(ZPP_Lexer *lexer, ZPP_Error *error)
{
    lexer->result.flags = lexer->tok_flags;
    lexer->tok_flags = 0;
    
    // NOTE: we check for comments later in the giant switch
    for(;;)
    {
        if (ZPP_is_horizontal_space(*lexer->pos.ptr))
        {
            do
            {   
                ++lexer->pos.ptr;
                ++lexer->pos.col;
            } while (ZPP_is_horizontal_space(*lexer->pos.ptr));

            lexer->result.flags |= ZPP_TOKEN_SPACE;
        }

        if (*lexer->pos.ptr == '\n')
        {
            if (lexer->in_pp_directive)
            {
                return 0;
            }
            
            bool is_carriage_return = false;
            do
            {
                ++lexer->pos.row;
                lexer->pos.col = 0;
                lexer->pos.ptr += is_carriage_return + 1;
                
            } while ((lexer->pos.ptr[0] == '\n') ||
                     ((is_carriage_return =
                       (lexer->pos.ptr[0] == '\r')) != false // NOTE: MSVC warns without != false
                      && lexer->pos.ptr[1] == '\n'));

            lexer->result.flags |= ZPP_TOKEN_BOL;
            lexer->result.flags &= ~ZPP_TOKEN_SPACE;
            continue;
        }

        if (ZPP_is_newline_escape(lexer->pos.ptr))
        {
            do
            {
                ++lexer->pos.row;
                lexer->pos.col = 0;
                lexer->pos.ptr += lexer->pos.ptr[1] == '\r' ? 3 : 2;
            } while(ZPP_is_newline_escape(lexer->pos.ptr));
            continue;
        }
        
        if (*lexer->pos.ptr == '\0')
        {
eof_found:
            lexer->result.pos = lexer->pos; 
            return 0;
        }
    
        lexer->result.pos = lexer->pos;
        
        /*
         *  NOTE: we sometimes replace the pointer of `result`      
         *  because of newline escapes which could make some tokens not
         *  contiguous
         */

        char *new_ptr;
        switch (*lexer->pos.ptr)
        {
            case '\'':
            {
                ++lexer->pos.ptr;
                ++lexer->pos.col;
                
                lexer->result.len = 1;
                lexer->result.flags |= ZPP_TOKEN_CHAR;
                return ZPP_lexer_read_string_rest(lexer, error, '\'');
            }
            
            case '"':
            {
                ++lexer->pos.ptr;
                ++lexer->pos.col;

                lexer->result.len = 1;
                lexer->result.flags |= ZPP_TOKEN_STR;
                return ZPP_lexer_read_string_rest(lexer, error, '"');
            }
            
            case '^': new_ptr = "^="; goto star_case;
            case '%': new_ptr = "%="; goto star_case;
            case '!': new_ptr = "!="; goto star_case;
            case '=': new_ptr = "=="; goto star_case;
            case '*': new_ptr = "*=";
            {
star_case:
                ++lexer->pos.ptr;
                ++lexer->pos.col;

                lexer->result.len = 1;
                lexer->result.flags |= ZPP_TOKEN_PUNCT;

                ZPP_Pos old_pos = lexer->pos;
                if (ZPP_lexer_read_char(lexer) == '=')
                {
                    lexer->result.len = 2;
                    lexer->result.pos.ptr = new_ptr;
                    return 1;
                }
                lexer->pos = old_pos;

                return 1;
            }
            
            case '&':
            case '|':
            case '+':
            {
                char start_ch = *lexer->pos.ptr;

                ++lexer->pos.col;
                ++lexer->pos.ptr;

                lexer->result.len = 1;
                lexer->result.flags |= ZPP_TOKEN_PUNCT;

                ZPP_Pos old_pos = lexer->pos;
                char ch = ZPP_lexer_read_char(lexer);

                if (ch == start_ch)
                {
                    lexer->result.len = 2;
                    lexer->result.pos.ptr =
                        ch == '&' ? "&&" :
                        ch == '|' ? "||" : "++";

                    return 1;
                }
                else if (ch == '=')
                {
                    lexer->result.len = 2;
                    lexer->result.pos.ptr =
                        start_ch == '&' ? "&=" :
                        start_ch == '|' ? "|=" : "+=";
                    
                    return 1;   
                }
                
                lexer->pos = old_pos;
                return 1;
            }
            
            case '-':
            {
                ++lexer->pos.col;
                ++lexer->pos.ptr;

                lexer->result.len = 1;
                lexer->result.flags |= ZPP_TOKEN_PUNCT;

                ZPP_Pos old_pos = lexer->pos;
                {
                    char ch = ZPP_lexer_read_char(lexer);
                    if (ch == '>')
                    {
                        lexer->result.len = 2;
                        lexer->result.pos.ptr = "->";
                        return 1;
                    }
                    else if (ch == '=')
                    {
                        lexer->result.len = 2;
                        lexer->result.pos.ptr = "-=";
                        return 1;
                    }
                    else if (ch == '-')
                    {
                        lexer->result.len = 2;
                        lexer->result.pos.ptr = "--";
                        return 1;
                    }
                }
                lexer->pos = old_pos;

                return 1;
            }
            
            case '.':
            {
                ++lexer->pos.col;
                ++lexer->pos.ptr;
                lexer->result.flags |= ZPP_TOKEN_PUNCT;
            
                ZPP_Pos old_pos = lexer->pos;
                if (ZPP_lexer_read_char(lexer) == '.' &&
                    ZPP_lexer_read_char(lexer) == '.')
                {
                    lexer->result.len = 3;
                    lexer->result.pos.ptr = "...";
                    return 1;
                }
                lexer->pos = old_pos;

                lexer->result.len = 1;
                return 1;
            }
            
            case '>':
            case '<':
            {
                char start_ch = *lexer->pos.ptr;
                
                ++lexer->pos.col;
                ++lexer->pos.ptr;

                lexer->result.len = 1;
                lexer->result.flags |= ZPP_TOKEN_PUNCT;

                ZPP_Pos old_pos = lexer->pos;
                char ch = ZPP_lexer_read_char(lexer);
                switch (ch)
                {
                    case '>':
                    case '<':
                    {
                        if (start_ch == ch)
                        {
                            ZPP_Pos old_pos2 = lexer->pos;
                            if (ZPP_lexer_read_char(lexer) != '=')
                            {
                                lexer->result.len = 2;
                                lexer->result.pos.ptr = start_ch == '<' ? "<<" : ">>";
                                lexer->pos = old_pos2;
                                return 1;
                            }
                                
                            lexer->result.len = 3;
                            lexer->result.pos.ptr = start_ch == '<' ? "<<=" : ">>=";
                            return 1;
                        }

                        break;
                    }
                        
                    case '=':
                    {
                        lexer->result.len = 2;
                        lexer->result.pos.ptr = start_ch == '<' ? "<=" : ">=";
                        return 1;
                    }
                }                    

                lexer->pos = old_pos;
                return 1;
            }
            
            case '#':
            {
                ++lexer->pos.col;
                ++lexer->pos.ptr;
                
                lexer->result.len = 1;
                lexer->result.flags |= ZPP_TOKEN_PUNCT;

                ZPP_Pos old_pos = lexer->pos;
                {
                    char ch = ZPP_lexer_read_char(lexer);
                    if (ch == '#')
                    {
                        ++lexer->result.len;
                        lexer->result.pos.ptr = "##";
                        return 1;
                    }
                }
                
                lexer->pos = old_pos;
                return 1;
            }

            case '~':
            case '?':
            case ';':
            case ':':
            case ',':
            case '[':
            case ']':
            case '{':
            case '}':
            case '(':
            case ')':
            {
                ++lexer->pos.col;
                ++lexer->pos.ptr;
                
                lexer->result.len = 1;
                lexer->result.flags |= ZPP_TOKEN_PUNCT;
                return 1;
            }

            case '/':
            {
                ++lexer->pos.col;
                ++lexer->pos.ptr;
                
                ZPP_Pos old_pos = lexer->pos;
                char ch = ZPP_lexer_read_char(lexer);
                if (ch == '/')
                {
                    lexer->result.flags |= ZPP_TOKEN_BOL;
                    lexer->result.flags &= ~ZPP_TOKEN_SPACE;
                    for(;;)
                    {
                        char cur = ZPP_lexer_read_char(lexer);
                            
                        if (cur == '\n')
                        {
                            if (lexer->in_pp_directive)
                            {
                                return 0;
                            }
                            
                            ++lexer->pos.row;
                            lexer->pos.col = 0;
                            break;
                        }
                        else if (cur == '\0')
                        {
                            goto eof_found;
                        }
                    }

                    continue;
                }
                else if (ch == '*')
                {
                    lexer->result.flags |= ZPP_TOKEN_SPACE;
                    char cur = ZPP_lexer_read_char(lexer);
                    for(;;)
                    {
                        switch(cur)
                        {
                            case '*':
                            {
                                cur = ZPP_lexer_read_char(lexer);
                                if (cur == '/') goto comment_done;
                                continue; 
                            }
                            
                            case '\n':
                            {
                                ++lexer->pos.row;
                                lexer->pos.col = 0;
                                break;
                            }

                            case '\0':
                            {
                                goto eof_found;
                            }
                        }

                        cur = ZPP_lexer_read_char(lexer);
                    }
comment_done:
                    continue;
                }
                else if (ch == '=')
                {
                    lexer->result.len = 2;
                    lexer->result.flags |= ZPP_TOKEN_PUNCT;

                    return 1;
                }
                lexer->pos = old_pos;

                lexer->result.len = 1;
                lexer->result.flags |= ZPP_TOKEN_PUNCT;
                return 1;
            }
        
            
            default:
            {
                if (ZPP_is_ident_char(*lexer->pos.ptr))
                {
                    lexer->result.len = 0;
                    return ZPP_lexer_read_ident_rest(lexer, error);
                }

                if (ZPP_is_digit(*lexer->pos.ptr))
                {
                    lexer->result.len = 0;
                    lexer->result.flags |= ZPP_TOKEN_PPNUM;
                
                    do
                    {
                        ++lexer->result.len;
                        ++lexer->pos.ptr;
                        ++lexer->pos.col;
                    } while (ZPP_is_digit(*lexer->pos.ptr) ||
                             ZPP_is_ident_char(*lexer->pos.ptr));

                    return true;
                }

                __debugbreak();
                return 0;
            }
        }
    }
}

static void *ZPP_gen_alloc(ZPP_State *state, size_t size)
{
    return state->allocator->gen_alloc(state->allocator, size); 
}

static void *ZPP_gen_calloc(ZPP_State *state, size_t size)
{
    return state->allocator->gen_calloc(state->allocator, size); 
}

static void *ZPP_gen_realloc(ZPP_State *state, void *ptr, size_t size)
{
    return state->allocator->gen_realloc(state->allocator, ptr, size); 
}

static void ZPP_gen_free(ZPP_State *state, void *ptr)
{
    state->allocator->gen_free(state->allocator, ptr); 
}

#define ZPP_BLOCK_COUNT \
    ((0x1000 - offsetof(ZPP_ContextAllocator, data)) / sizeof(ZPP_ContextBlock))

static int ZPP_context_pop(ZPP_State *state)
{
    if (state->context_allocator->len == 1)
    {
        ZPP_ContextAllocator *prev =
            state->context_allocator->prev;

        // only free the allocator if it's not being used
        if (!state->keep_context_allocator)
        {
            ZPP_gen_free(state,  state->context_allocator);
        }
        
        if (prev == NULL)
        {
            return 0;
        }

        state->context_allocator = prev;
    }
    else
    {
        --state->context_allocator->len;
    }

    state->context = state->context->prev;    
    return 1;
}

static void ZPP_context_push(ZPP_State *state, ZPP_ContextBlock *item)
{
    if (state->context_allocator == NULL ||
        ++state->context_allocator->len > ZPP_BLOCK_COUNT)
    {
        ZPP_ContextAllocator *allocator =
            ZPP_gen_alloc(state,
                          sizeof *allocator +
                          sizeof(ZPP_ContextBlock) *
                          ZPP_BLOCK_COUNT);
        
        allocator->len = 1;
        allocator->prev = state->context_allocator;
        state->context_allocator = allocator;
    }

    ZPP_ContextBlock *context =
        &state->context_allocator->data
        [state->context_allocator->len - 1];

    *context = *item;
    context->context.prev = state->context;
    state->context = &context->context;
}

static int ZPP_context_lex_direct(ZPP_State *state, ZPP_Error *error)
{
    for(;;)
    {
        switch (state->context->type)
        {
            case ZPP_FILE_CONTEXT:
            {
                ZPP_Lexer *lexer = (ZPP_Lexer*)state->context;
            
                int result = ZPP_lexer_lex_direct(lexer, error);
                state->result = lexer->result;

                if (result == 0)
                {
                    if (ZPP_context_pop(state) != 0)
                    {
                         continue;
                    }
                    
                    return 0;
                }
            
                return result;
            }

            case ZPP_MACRO_CONTEXT:
            {
                ZPP_MacroContext *macro_context =
                    (ZPP_MacroContext*)state->context;

                if (macro_context->token_len == 0)
                {
                    --macro_context->macro->expand_level;
                    if (ZPP_context_pop(state) != 0)
                    {
                         continue;
                    }
                    
                    return 0; 
                }

                --macro_context->token_len;
                state->result = *macro_context->tokens++;

                return 1;
            }
            
            default: __debugbreak(); return -1;
        }
    }
}

static bool ZPP_string_equal(ZPP_String a, ZPP_String b)
{
    if (a.len != b.len) return false;

    for (uint32_t i = 0; i < a.len; ++i)
    {
        if (a.ptr[i] != b.ptr[i]) return false;
    }
    
    return true;
}

static uint32_t ZPP_string_hash(ZPP_String str)
{
    uint32_t hash = 5381;
    for (uint32_t i = 0; i < str.len; ++i)
        hash = ((hash << 5) + hash) + str.ptr[i]; /* hash * 33 + c */

    return hash;
}

static ZPP_Ident *ZPP_ident_map_get(ZPP_State *state, ZPP_String name)
{
    uint32_t name_hash = ZPP_string_hash(name);
    uint32_t map_index = name_hash & (state->ident_map.cap - 1);
    
    for(uint32_t i = 0; i < state->ident_map.cap; ++i)
    {
        ZPP_Ident *key = &state->ident_map.keys[map_index];
        if (key->is_alive &&
            key->hash == name_hash && ZPP_string_equal(key->name, name))
        {
            return key;
        }

        ++map_index;
        map_index  &= state->ident_map.cap - 1;
    }

    return NULL;
}

static void ZPP_ident_map_set(ZPP_State *state, ZPP_Ident *macro)
{
    if ((state->ident_map.len + 1) * 4 / 3 > state->ident_map.cap)
    {
        uint32_t new_cap = state->ident_map.cap * 2;
        ZPP_Ident *new_keys =
            ZPP_gen_calloc(state, new_cap * sizeof *new_keys);

        for (ZPP_Ident
                 *start = state->ident_map.keys,
                 *end = state->ident_map.keys +
                 state->ident_map.cap;
             start != end; ++start)
        {
            if (!start->is_alive) continue;
            
            uint32_t map_index = start->hash & (new_cap - 1);
            for(;;)
            {
                if (!new_keys[map_index].is_alive)
                {
                    new_keys[map_index] = *start;
                    break;
                }

                ++map_index;
                map_index &= new_cap - 1;
            }
        }

        ZPP_gen_free(state, state->ident_map.keys);
        
        state->ident_map.cap = new_cap;
        state->ident_map.keys = new_keys;
    }

    macro->is_alive = true;
    macro->hash = ZPP_string_hash(macro->name);
    uint32_t map_index =
        macro->hash & (state->ident_map.cap - 1);

    for(;;)
    {
        if (!state->ident_map.keys[map_index].is_alive)
        {
            state->ident_map.keys[map_index] = *macro;
            return;
        }

        ++map_index;
        map_index &= state->ident_map.cap - 1;
    }
}

static ZPP_String ZPP_tok_to_str(ZPP_Token *token)
{
    return (ZPP_String) {
        .len = token->len,
        .ptr = token->pos.ptr,
    };
}

ZPP_LINKAGE int ZPP_init_state(ZPP_State *state, char *file_data)
{
    state->ident_map.cap = 512;
    state->ident_map.keys =
        ZPP_gen_calloc(state,
                       state->ident_map.cap *
                       sizeof *state->ident_map.keys);
    
    ZPP_context_push(state, &(ZPP_ContextBlock)
                     {
                         .lexer = {
                             .pos.ptr = file_data,
                             .tok_flags = ZPP_TOKEN_BOL,
                             .base.type = ZPP_FILE_CONTEXT,
                         }
                     });
    
    return 1;
}

// TODO: support function macros and handle `#`, `##`, and `__VA_ARGS__`
static int ZPP_expand_macro(ZPP_State *state, ZPP_Error *error,
                            bool *had_macro)
{
    if ((state->result.flags & ZPP_TOKEN_IDENT) == 0 ||
        (state->result.flags & ZPP_TOKEN_NO_EXPAND) != 0)
    {
        return 1;
    }

    ZPP_String name_str = ZPP_tok_to_str(&state->result);
    ZPP_Ident *ident = ZPP_ident_map_get(state, name_str);

    if (ident == NULL)
    {
        ZPP_ident_map_set(state,
                          &(ZPP_Ident)
                          {
                              .name = name_str,
                              .is_macro = false,
                          });

        return 1;
    }
    else if (!ident->is_macro || ident->is_fn_macro)
    {
        return 1;
    }
    else if(ident->expand_level != 0)
    {
        state->result.flags |= ZPP_TOKEN_NO_EXPAND;
        return 1;
    }

    *had_macro = true;

    ZPP_Token *tokens = NULL;

    if (ident->token_len != 0)
    {
        tokens =
            ZPP_gen_alloc(state, ident->token_len * sizeof *tokens);

        ZPP_memcpy(tokens, ident->tokens, ident->token_len * sizeof *tokens);

        tokens[0].flags |=
            state->result.flags & ZPP_TOKEN_SPACE;

        // make all the tokens expanded from this macro have the location of the macro
        for (uint32_t i = 0; i < ident->token_len; ++i)
        {
            tokens[i].pos.row = state->result.pos.row;
            tokens[i].pos.col = state->result.pos.col;
        }
    }
    
    // disable the macro before expanding it
    ++ident->expand_level;
    ZPP_context_push(state,
                     &(ZPP_ContextBlock)
                     {
                         .macro_context = {
                             .base.type = ZPP_MACRO_CONTEXT,
                             .macro = ident,
                             .tokens = tokens,
                             .token_len = ident->token_len,
                         }
                     });
    
    return 1;
}

ZPP_LINKAGE int ZPP_read_token(ZPP_State *state, ZPP_Error *error)
{
read_token:;
    int ec;
    ZPP_LEXER_TRY_READ(state, error);
    
    bool had_macro = false;
    if ((ec = ZPP_expand_macro(state, error, &had_macro)) < 0)
    {
        return ec;
    }

    if (had_macro) goto read_token;
    
    if (state->result.pos.ptr[0] != '#' ||
        (state->result.flags & ZPP_TOKEN_BOL) == 0)
    {
        return 1;
    }

    // NOTE: only a file lexer should be able to return a BOL token
    // meaning that we can directly cast our context to a ZPP_Lexer

    ZPP_Lexer *lexer = (ZPP_Lexer*)state->context;
    ZPP_Lexer old_lex = *lexer;
    
    lexer->in_pp_directive = true;
    switch (ec = ZPP_lexer_lex_direct(lexer, error))
    {
        case 1: break;
        case 0:
        {
            lexer->in_pp_directive = false;
            goto read_token;
        }
              
        default: return ec;
    }
    
#define ZPP_DIRECTIVE_TRY_READ(l_, e_)                              \
    do                                                              \
    {    ec = ZPP_lexer_lex_direct(l_, e_);                         \
        if (ec < 0) return ec;                                      \
        if (ec == 0)                                                \
        {                                                           \
            return ZPP_pos_return_error(&(l_)->pos, e_,             \
                                        ZPP_ERROR_UNEXPECTED_EOL);  \
        }                                                           \
    } while (false)

    if (ZPP_string_equal(ZPP_tok_to_str(&lexer->result),
                         ZPP_STR_STATIC("define")))
    {
        ZPP_DIRECTIVE_TRY_READ(lexer, error);

        if ((lexer->result.flags & ZPP_TOKEN_IDENT) == 0)
        {
            return ZPP_pos_return_error(&lexer->result.pos, error,
                                        ZPP_ERROR_UNEXPECTED_TOK);
        }

        ZPP_Pos name_pos = lexer->result.pos;
        ZPP_String name_str = ZPP_tok_to_str(&lexer->result);
        ZPP_Ident *macro = ZPP_ident_map_get(state, name_str);

        // TODO: handle this
        if (macro != NULL && macro->is_macro)
        {
            __debugbreak();
            return -1;
        }

        uint32_t token_cap = 0;
        bool first_token = true;
        ZPP_Ident new_macro = {
            .name = name_str,
            .is_macro = true,
        };
        
        for(;;)
        {
            ec = ZPP_lexer_lex_direct(lexer, error);
            switch (ec)
            {
                case 0:
                {
                    if (new_macro.token_len != 0 &&
                        ((new_macro.tokens[0].len == 2 &&
                          *new_macro.tokens[0].pos.ptr == '#') ||
                         *new_macro.tokens[new_macro.token_len - 1].pos.ptr == '#'))
                    {
                        return ZPP_pos_return_error(&name_pos, error,
                                                    ZPP_ERROR_INVALID_MACRO); 
                    }
                    
                    lexer->in_pp_directive = false;
                    if (macro == NULL)
                    {
                        ZPP_ident_map_set(state, &new_macro);
                    }
                    else
                    {
                        new_macro.is_alive = true;
                        new_macro.hash = macro->hash;
                        new_macro.name = macro->name;
                        *macro = new_macro;
                    }
                    
                    goto read_token;
                }
                
                case 1:
                {
                    // see if we have a function macro
                    if (first_token &&
                        lexer->result.pos.ptr[0] == '(' &&
                        (lexer->result.flags & ZPP_TOKEN_SPACE) == 0)
                    {
                        uint32_t arg_cap = 0;
                        new_macro.is_fn_macro = true;
                        
                        for(;;)
                        {
                            ZPP_DIRECTIVE_TRY_READ(lexer, error);

                            // if we see an ident add it to the array of args
                            if ((lexer->result.flags & ZPP_TOKEN_IDENT) != 0)
                            {
                                if (new_macro.token_len + 1 > token_cap)
                                {
                                    arg_cap = (new_macro.arg_len + 1) * 3 / 2;
                                    new_macro.args =
                                        ZPP_gen_realloc(state,
                                                        new_macro.args,
                                                        arg_cap * sizeof *new_macro.args);
                                }

                                new_macro.args[new_macro.arg_len++] =
                                    (ZPP_String)
                                    {
                                        .len = lexer->result.len,
                                        .ptr = lexer->result.pos.ptr,
                                    };

                            }
                            else if (lexer->result.pos.ptr[0] == '.' &&
                                     lexer->result.pos.ptr[1] == '.' &&
                                     lexer->result.pos.ptr[2] == '.')
                            {
                                new_macro.is_va_args = true;
                            }
                            else
                            {
                                return ZPP_pos_return_error(&lexer->result.pos, error,
                                                            ZPP_ERROR_UNEXPECTED_TOK);
                            }
                            
                            ZPP_DIRECTIVE_TRY_READ(lexer, error);
                            if (new_macro.is_va_args &&
                                *lexer->result.pos.ptr != ')')
                            {
                                return ZPP_pos_return_error(&lexer->result.pos, error,
                                                            ZPP_ERROR_UNEXPECTED_TOK);
                            }

                            if (*lexer->result.pos.ptr == ')')
                            {
                                break;
                            }
                            else if (*lexer->result.pos.ptr != ',')
                            {
                                return ZPP_pos_return_error(&lexer->result.pos, error,
                                                            ZPP_ERROR_UNEXPECTED_TOK);
                            }
                        }

                        break;
                    }
                    
                    if (new_macro.token_len + 1 > token_cap)
                    {
                        token_cap = (new_macro.token_len + 1) * 3 / 2;
                        new_macro.tokens =
                            ZPP_gen_realloc(state,
                                            new_macro.tokens,
                                            token_cap *
                                            sizeof *new_macro.tokens);
                    }

                    // for any tokens in the macro body that corrisipond to a macro argument
                    // replace the tokens with their respective macro argument index 
                    if (new_macro.is_fn_macro)
                    {
                        ZPP_String result_str = ZPP_tok_to_str(&lexer->result);
                        for (uint32_t i = 0; i < new_macro.arg_len; ++i)
                        {
                            if (ZPP_string_equal(result_str, new_macro.args[i]))
                            {
                                lexer->result.pos.ptr = (char*)(uintptr_t)i;
                                lexer->result.flags |= ZPP_TOKEN_MACRO_ARG;
                                break;
                            }
                        }
                    }
                    
                    new_macro.tokens[new_macro.token_len++] =
                        lexer->result;

                    if (first_token)
                    {
                        new_macro.tokens[new_macro.token_len - 1].flags &=
                            ~(uint32_t)ZPP_TOKEN_SPACE;
                    }

                    first_token = false;
                    break;
                }

                case -1: return -1;
            }
        }
    }
    else if (ZPP_string_equal(ZPP_tok_to_str(&lexer->result),
                              ZPP_STR_STATIC("undef")))
    {
        ZPP_DIRECTIVE_TRY_READ(lexer, error);
        
        if ((lexer->result.flags & ZPP_TOKEN_IDENT) == 0)
        {
            return ZPP_pos_return_error(&lexer->result.pos, error,
                                        ZPP_ERROR_UNEXPECTED_TOK);
        }
        
        ZPP_Ident *macro =
            ZPP_ident_map_get(state,
                              ZPP_tok_to_str(&lexer->result));

        if (macro != NULL)
        {
            macro->is_macro = false;
            ZPP_gen_free(state, macro->args);
            ZPP_gen_free(state, macro->tokens);
            
            ec = ZPP_lexer_lex_direct(lexer, error);
            if (ec < 0) return ec;
            else if (ec == 1)
            {
                return ZPP_pos_return_error(&lexer->result.pos, error,
                                            ZPP_ERROR_UNEXPECTED_TOK);
            }
        }
        else
        {
            __debugbreak();
        }
        
        lexer->in_pp_directive = false;
        goto read_token;
    }

    *lexer = old_lex;
    return 1;
}

//#undef ZPP_STR_STATIC
//#undef ZPP_LEXER_TRY_READ
    
#endif // ZPP_DEFINE
#endif // ZPP_ZPP_H
