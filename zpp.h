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

typedef struct ZPP_Allocator ZPP_Allocator;
struct ZPP_Allocator
{
    void (*gen_free)(void*, void*);
    void *(*gen_alloc)(void*, size_t);
    void *(*gen_calloc)(void*, size_t);
    void *(*gen_realloc)(void*, void*, size_t);
};

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
    ZPP_TOKEN_FREE  = 1 << 8, // this token is dynamically allocated
    ZPP_TOKEN_MACRO = 1 << 9, // NOTE: internal use only
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

// TODO: create an enum for ZPP_lexer_lex_direct return values
typedef struct
{
    ZPP_Pos pos;
    ZPP_Token result;
    ZPP_TokenArray tokens;
    
    uint32_t tok_flags;
    bool in_pp_directive;
} ZPP_Lexer;

enum
{
    ZPP_ERROR_UNEXPECTED_EOF,
    ZPP_ERROR_UNTERMINATED_STR,
    ZPP_ERROR_UNTERMINATED_CHR,
    ZPP_ERROR_UNEXPECTED_EOL,
    ZPP_ERROR_UNEXPECTED_TOK,
    ZPP_ERROR_INVALID_MACRO,
};

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

typedef struct
{
    ZPP_String name;
    ZPP_Token *tokens;
    ZPP_String *args;

    uint32_t hash;
    uint32_t token_len;
    uint32_t arg_len;

    bool is_dead : 1;
    bool is_va_args : 1;
    bool is_fn_macro : 1;
} ZPP_Macro;

typedef struct
{
    ZPP_Macro *keys;
    uint32_t len;
    uint32_t cap;
} ZPP_MacroMap;

typedef struct
{
    ZPP_Lexer lexer;
    ZPP_Allocator *allocator;
    ZPP_MacroMap macro_map;
}  ZPP_State;

ZPP_LINKAGE int ZPP_init_state(ZPP_State *state);
ZPP_LINKAGE int ZPP_read_token(ZPP_State *state, ZPP_Error *error);

/*
  NOTE: regarding functions defined explicitly with `static`.
  these are for internal use only and do not expect them to be stable.
*/

#ifdef ZPP_DEFINE

#define ZPP_LEXER_TRY_READ(l_, e_)                         \
    do                                                     \
    {                                                      \
        ec = ZPP_lexer_lex_direct(l_, e_);                 \
        if (ec <= 0) return ec;                            \
    } while(false)

#define ZPP_STR_STATIC(str_) ((ZPP_String){.ptr=(str_), .len=sizeof((str_)) - 1})

static void ZPP_memcpy(void *dest, void const *src, size_t size)
{
    char *dest8 = dest;
    char const *src8 = src;

    while (size-- != 0) *dest8++ = *src8++;
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

static int ZPP_lexer_return_error(ZPP_Lexer *lexer,
                                  ZPP_Error *error,
                                  uint32_t error_code)
{
    error->row = lexer->pos.row;
    error->col = lexer->pos.col;
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
            return ZPP_lexer_return_error(lexer, error,
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

static int ZPP_lexer_lex_direct(ZPP_Lexer *lexer,
                                ZPP_Error *error)
{
    if (lexer->tokens.len != 0)
    {
        --lexer->tokens.len;
        
        lexer->result = *lexer->tokens.ptr++;
        lexer->result.flags |= ZPP_TOKEN_MACRO;
        return 1;
    }
    
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
                return -2;
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
                                return -2;
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

static bool ZPP_str_equal(ZPP_String a, ZPP_String b)
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

static ZPP_Macro *ZPP_macro_map_get(ZPP_State *state, ZPP_String name)
{
    uint32_t name_hash = ZPP_string_hash(name);
    uint32_t map_index = name_hash & (state->macro_map.cap - 1);
    
    for(uint32_t i = 0; i < state->macro_map.cap; ++i)
    {
        ZPP_Macro *key = &state->macro_map.keys[map_index];
        if (!key->is_dead &&
            key->hash == name_hash && ZPP_str_equal(key->name, name))
        {
            return key;
        }

        ++map_index;
        map_index  &= state->macro_map.cap - 1;
    }

    return NULL;
}

static void ZPP_macro_map_set(ZPP_State *state, ZPP_Macro *macro)
{
    if ((state->macro_map.len + 1) * 4 / 3 > state->macro_map.cap)
    {
        uint32_t new_cap = state->macro_map.cap * 2;
        ZPP_Macro *new_keys =
            ZPP_gen_calloc(state, new_cap * sizeof *new_keys);

        for (ZPP_Macro
                 *start = state->macro_map.keys,
                 *end = state->macro_map.keys +
                 state->macro_map.cap;
             start != end; ++start)
        {
            if (start->is_dead) continue;
            
            uint32_t map_index = start->hash & (new_cap - 1);
            for(;;)
            {
                if (new_keys[map_index].name.ptr == NULL)
                {
                    new_keys[map_index] = *start;
                    break;
                }

                ++map_index;
                map_index &= new_cap - 1;
            }
        }

        ZPP_gen_free(state, state->macro_map.keys);
        
        state->macro_map.cap = new_cap;
        state->macro_map.keys = new_keys;
    }

    macro->hash = ZPP_string_hash(macro->name);
    uint32_t map_index =
        macro->hash & (state->macro_map.cap - 1);

    for(;;)
    {
        if (state->macro_map.keys[map_index].name.ptr == NULL)
        {
            state->macro_map.keys[map_index] = *macro;
            return;
        }

        ++map_index;
        map_index &= state->macro_map.cap - 1;
    }
}

static ZPP_String ZPP_tok_to_str(ZPP_Token *token)
{
    return (ZPP_String) {
        .len = token->len,
        .ptr = token->pos.ptr,
    };
}

static void ZPP_token_array_push(ZPP_State *state,
                                 ZPP_TokenArray *self,
                                 ZPP_Token arg)
{
    if (self->len + 1 > self->cap)
    {
        self->cap = (self->len + 1) * 3 / 2;
        self->ptr = ZPP_gen_realloc(state,
                                    self->ptr,
                                    self->cap *
                                    sizeof *self->ptr);
    }

    self->ptr[self->len++] = arg;
}

static void ZPP_macro_args_push(ZPP_State *state,
                                ZPP_MacroArgs *self,
                                ZPP_TokenArray *arg)
{
    if (self->len + 1 > self->cap)
    {
        self->cap = (self->len + 1) * 3 / 2;
        self->ptr = ZPP_gen_realloc(state,
                                    self->ptr,
                                    self->cap *
                                    sizeof *self->ptr);
    }

    self->ptr[self->len++] = *arg;
}

static ZPP_TokenArray ZPP_token_array_copy(ZPP_State *state,
                                           ZPP_TokenArray *self)
{
    ZPP_TokenArray result = {
        .ptr = ZPP_gen_alloc(state,
                             self->len *
                             sizeof *self->ptr),
        .len = self->len,
        .cap = self->cap
    };

    ZPP_memcpy(result.ptr, self->ptr, self->len * sizeof *self->ptr);
    return result;
}

static ZPP_MacroArgs ZPP_macro_args_copy(ZPP_State *state,
                                         ZPP_MacroArgs *self)
{
    ZPP_MacroArgs result = {
        .ptr = ZPP_gen_alloc(state,
                             self->len *
                             sizeof *self->ptr),
        .len = self->len,
        .cap = self->cap
    };

    for (uint32_t i = 0; i < result.len; ++i)
    {
        result.ptr[i] = ZPP_token_array_copy(state, &self->ptr[i]);
    }

    return result;
}

// TODO: properly handle memory mangment so we don't have memory leaks

static int ZPP_parse_macro_args(ZPP_State *state,
                                ZPP_Macro *macro,
                                ZPP_MacroArgs *macro_args,
                                ZPP_Error *error)
{
    int ec;
    int32_t paren_count = 1;
    for(;;)
    {
        ZPP_LEXER_TRY_READ(&state->lexer, error);
        ZPP_Token result = state->lexer.result;
                
        if (*result.pos.ptr == '(') ++paren_count;
        else if (*result.pos.ptr == ')') --paren_count;

        if (paren_count == 1 && *result.pos.ptr == ',')
        {
            // for __VA_ARGS__ just add the comma to the current argument
            if (macro->is_va_args &&
                macro_args->len == macro->arg_len)
            {
                ZPP_token_array_push(state,
                                     &macro_args->ptr
                                     [macro_args->len - 1], result);
            }
            else if (macro_args->len + 1 > macro->arg_len)
            {
                // to many arguments were passed to the macro
                return ZPP_lexer_return_error(&state->lexer, error,
                                              ZPP_ERROR_INVALID_MACRO);
            }
            else
            {
                // change the current argument to a new argument
                ZPP_macro_args_push(state, macro_args, &(ZPP_TokenArray){0});
                continue;
            }
        }
        else if (paren_count == 0)
        {
            if (macro_args->len < macro->arg_len)
            {
                return ZPP_lexer_return_error(&state->lexer, error,
                                              ZPP_ERROR_INVALID_MACRO);
            }

            return 1;
        }

        if (macro_args->len == 0)
        {
            ZPP_macro_args_push(state, macro_args, &(ZPP_TokenArray){0});
        }
                
        // add the token to the current argument
        ZPP_token_array_push(state,
                             &macro_args->ptr
                             [macro_args->len - 1], result);
    }
}

// NOTE: https://stackoverflow.com/a/66596396
static void ZPP_expand_macro(ZPP_State *state,
                             ZPP_Macro *macro,
                             ZPP_MacroArgs *macro_args)
{
    if (macro->is_fn_macro)
    {
    }
    
    
    state->lexer.tokens = (ZPP_TokenArray) {
        .ptr = macro->tokens,
        .len = macro->token_len,
        .cap = macro->token_len
    };
}

ZPP_LINKAGE int ZPP_init_state(ZPP_State *state)
{
    state->macro_map.cap = 512;
    state->macro_map.keys =
        ZPP_gen_calloc(state,
                       state->macro_map.cap *
                       sizeof *state->macro_map.keys);
    
    state->lexer.tok_flags |= ZPP_TOKEN_BOL;
    return 1;
}

ZPP_LINKAGE int ZPP_read_token(ZPP_State *state,
                               ZPP_Error *error)
{
read_another_token:;
    
    int ec;
    ZPP_LEXER_TRY_READ(&state->lexer, error);
    if ((state->lexer.result.flags & ZPP_TOKEN_IDENT) != 0)
    {
        ZPP_String name_str = ZPP_tok_to_str(&state->lexer.result);
        ZPP_Macro *macro = ZPP_macro_map_get(state, name_str);

        if (macro == NULL) return 1;

        ZPP_Lexer old_lex = state->lexer; 
        if (macro->is_fn_macro &&
            (ec = ZPP_lexer_lex_direct(&state->lexer, error)) > 0 &&
            *state->lexer.result.pos.ptr == '(')
        {
            ZPP_MacroArgs macro_args = {0};
            ZPP_parse_macro_args(state, macro, &macro_args, error);
            
            state->lexer.tokens = (ZPP_TokenArray){
                .ptr = macro->tokens,
                .len = macro->token_len,
                .cap = macro->token_len
            };
            
            ZPP_expand_macro(state, macro, &macro_args);
            goto read_another_token;
        }
        else if (macro->is_fn_macro) // if the fn macro is not being called just return it unexpanded
        {
            state->lexer = old_lex;
            return 1;
        }
        else
        {
            state->lexer = old_lex;
            state->lexer.tokens = (ZPP_TokenArray){
                .ptr = macro->tokens,
                .len = macro->token_len,
                .cap = macro->token_len
            };
            
            ZPP_expand_macro(state, macro, NULL);
        }
        
        goto read_another_token;
    }
    else if (state->lexer.result.pos.ptr[0] != '#' ||
             (state->lexer.result.flags & ZPP_TOKEN_BOL) == 0)
    {
        return 1;
    }
    
    ZPP_Lexer old_lex = state->lexer;
    
    state->lexer.in_pp_directive = true;
    ZPP_LEXER_TRY_READ(&state->lexer, error);

    ZPP_Pos directive_pos = state->lexer.pos;
    if (ZPP_str_equal(ZPP_tok_to_str(&state->lexer.result),
                      ZPP_STR_STATIC("define")))
    {
        ZPP_LEXER_TRY_READ(&state->lexer, error);

        if ((state->lexer.result.flags & ZPP_TOKEN_IDENT) == 0)
        {
            return ZPP_lexer_return_error(&state->lexer, error,
                                          ZPP_ERROR_UNEXPECTED_TOK);
        }

        ZPP_String name_str = ZPP_tok_to_str(&state->lexer.result);
        ZPP_Macro *macro = ZPP_macro_map_get(state, name_str);

        // TODO: handle this
        if (macro != NULL)
        {
            __debugbreak();
            return -1;
        }

        uint32_t token_cap = 0;
        bool first_token = true;
        ZPP_Macro new_macro = {
            .name = name_str,
        };
        
        for(;;)
        {
            ec = ZPP_lexer_lex_direct(&state->lexer, error);
            switch (ec)
            {
                case -2:
                {
                    state->lexer.in_pp_directive = false;
                    ZPP_macro_map_set(state, &new_macro);
                    goto read_another_token;
                }
                
                case 1:
                {
                    // see if we have a function macro
                    if (first_token &&
                        state->lexer.result.pos.ptr[0] == '(' &&
                        (state->lexer.result.flags &
                         (ZPP_TOKEN_SPACE | ZPP_TOKEN_BOL)) == 0)
                    {
                        uint32_t arg_cap = 0;
                        new_macro.is_fn_macro = true;
                        
                        for(;;)
                        {
                            ZPP_LEXER_TRY_READ(&state->lexer, error);

                            // if we see an ident add it to the array of args
                            if ((state->lexer.result.flags & ZPP_TOKEN_IDENT) != 0)
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
                                        .len = state->lexer.result.len,
                                        .ptr = state->lexer.result.pos.ptr,
                                    };

                            }
                            else if (state->lexer.result.pos.ptr[0] == '.' &&
                                     state->lexer.result.pos.ptr[1] == '.' &&
                                     state->lexer.result.pos.ptr[2] == '.')
                            {
                                new_macro.is_va_args = true;
                            }
                            else
                            {
                                return ZPP_lexer_return_error(&state->lexer, error,
                                                              ZPP_ERROR_UNEXPECTED_TOK);
                            }
                            
                            ZPP_LEXER_TRY_READ(&state->lexer, error);
                            if (new_macro.is_va_args &&
                                *state->lexer.result.pos.ptr != ')')
                            {
                                return ZPP_lexer_return_error(&state->lexer, error,
                                                              ZPP_ERROR_UNEXPECTED_TOK);
                            }

                            if (*state->lexer.result.pos.ptr == ')')
                            {
                                break;
                            }
                            else if (*state->lexer.result.pos.ptr != ',')
                            {
                                return ZPP_lexer_return_error(&state->lexer, error,
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

                    new_macro.tokens[new_macro.token_len++] =
                        state->lexer.result;

                    if (first_token)
                    {
                        new_macro.tokens[new_macro.token_len - 1].flags &=
                            ~(uint32_t)ZPP_TOKEN_SPACE;
                    }

                    first_token = false;
                    break;
                }

                case -1: return -1;
                case 0:
                {   
                    state->lexer.in_pp_directive = false;
                    return 0;
                }
            }
        }
    }
    else if (ZPP_str_equal(ZPP_tok_to_str(&state->lexer.result),
                           ZPP_STR_STATIC("undef")))
    {
        ZPP_LEXER_TRY_READ(&state->lexer, error);
        
        if ((state->lexer.result.flags & ZPP_TOKEN_IDENT) == 0)
        {
            return ZPP_lexer_return_error(&state->lexer, error,
                                          ZPP_ERROR_UNEXPECTED_TOK);
        }
        
        ZPP_Macro *macro =
            ZPP_macro_map_get(state,
                              ZPP_tok_to_str(&state->lexer.result));

        if (macro != NULL)
        {
            macro->is_dead = true;
            ZPP_gen_free(state, macro->args);
            ZPP_gen_free(state, macro->tokens);
            
            ec = ZPP_lexer_lex_direct(&state->lexer, error);
            if (ec == 1)
            {
                return ZPP_lexer_return_error(&state->lexer, error,
                                              ZPP_ERROR_UNEXPECTED_TOK);
            }
        }
        else
        {
            __debugbreak();
        }
        
        state->lexer.in_pp_directive = false;
        goto read_another_token;
    }

    state->lexer = old_lex;
    return 1;
}

#undef ZPP_STR_STATIC
#undef ZPP_LEXER_TRY_READ
    
#endif // ZPP_DEFINE
#endif // ZPP_ZPP_H
