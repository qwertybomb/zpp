#ifndef ZPP_ZPP_H
#define ZPP_ZPP_H

/*
  define this yourself if you want to change the linkage of functions
  for example for a dll you might use __declspec(dllimport) or __declspec(dllexport)
*/

#ifndef ZPP_LINKAGE
#define ZPP_LINKAGE
#endif

// TODO: remove any headers that are only needed for tested when this is done
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define ZPP_ARRAY(type) type *
#define ZPP_ARRAY_NEW1() ZPP_array_new_impl(state, 0, 0, 0)
#define ZPP_ARRAY_NEW2(t_, c_) ZPP_array_new_impl(state, t_, 0, c_)
#define ZPP_ARRAY_NEW3(t_, s_) ZPP_array_new_impl(state, t_, s_, s_)

#define ZPP_ARRAY_GROW(a_, g_)                          \
    ZPP_array_grow_impl(state, a_, sizeof(**(a_)), g_)

#define ZPP_ARRAY_FREE(a_)                          \
    ZPP_gen_free(state, (ZPP_GenArray*)(a_) - 1)

#define ZPP_ARRAY_MEM(a_)                       \
    ((ZPP_GenArray*)(a_) - 1)

#define ZPP_ALEN(a_)                            \
    ((ZPP_GenArray*)(a_) - 1)->len

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
    ZPP_TOKEN_BOL       = 1 << 1, // token is at the Beginning Of Line
    ZPP_TOKEN_SPACE     = 1 << 2, // a space is before this token 
    ZPP_TOKEN_IDENT     = 1 << 3, // token is an identifier
    ZPP_TOKEN_PUNCT     = 1 << 4, // 6.4.6 Punctuator
    ZPP_TOKEN_PPNUM     = 1 << 5, // token is a pp-number
    ZPP_TOKEN_STR       = 1 << 6, // token is a "string" L"literal"
    ZPP_TOKEN_CHAR      = 1 << 7, // token is a 'c'har literal
    ZPP_TOKEN_ALLOC     = 1 << 8, // this token is dynamically allocated
    ZPP_TOKEN_READY     = 1 << 9,
    ZPP_TOKEN_MACRO_ARG = 1 << 10,
    ZPP_TOKEN_NO_EXPAND = 1 << 11,
    ZPP_TOKEN_IDENT_PTR = 1 << 12,
    ZPP_TOKEN_INC       = 1 << 13,
};

enum
{
    ZPP_CONTEXT_FILE = 1 << 0,
    ZPP_CONTEXT_MACRO = 1 << 1,
    ZPP_CONTEXT_LOCK = 1 << 2,
    ZPP_CONTEXT_TYPES = ~(ZPP_CONTEXT_LOCK),
};

enum
{
    ZPP_LEXER_PP = 1 << 0,
    ZPP_LEXER_BOL = 1 << 1,
    ZPP_LEXER_INC = 1 << 2,
};

// NOTE: the first 127 values are just the normal ascii values
enum
{
    ZPP_TYPE_XORQ = 128, // ^=
    ZPP_TYPE_ADDQ,       // +=
    ZPP_TYPE_SUBQ,       // -=
    ZPP_TYPE_MULQ,       // *=
    ZPP_TYPE_DIVQ,       // /=
    ZPP_TYPE_ANDQ,       // &=
    ZPP_TYPE_ORQ,        // |=
    ZPP_TYPE_MODQ,       // %=
    ZPP_TYPE_NOTQ,       // !=
    ZPP_TYPE_EQQ,        // ==
    ZPP_TYPE_ADD2,       // ++
    ZPP_TYPE_SUB2,       // --
    ZPP_TYPE_AND2,       // &&
    ZPP_TYPE_OR2,        // ||
    ZPP_TYPE_SHIFTR,     // >>
    ZPP_TYPE_SHIFTL,     // <<
    ZPP_TYPE_SHIFTRQ,    // >>=
    ZPP_TYPE_SHIFTLQ,    // <<=
    ZPP_TYPE_LT,         // <
    ZPP_TYPE_GT,         // >
    ZPP_TYPE_LTQ,        // <=
    ZPP_TYPE_GTQ,        // >=
    ZPP_TYPE_HASH2,      // ##
    ZPP_TYPE_DOT3,       // ...
    ZPP_TYPE_SUBGT,      // ->
};

#define ZPP_ERROR_INVALID_MACRO "invalid macro"
#define ZPP_ERROR_INVALID_PASTE "invalid paste"
#define ZPP_ERROR_UNEXPECTED_TOK "unexpected token"
#define ZPP_ERROR_UNEXPECTED_EOF "unexpected ending"

typedef struct 
{
    void (*gen_free)(void*, void*);
    void *(*gen_alloc)(void*, size_t);
    void *(*gen_calloc)(void*, size_t);
    char *(*open_file)(void*, char const*);
    void (*canonicalize_path)(void*, char*);
    void *(*gen_realloc)(void*, void*, size_t);
} ZPP_Platform;

typedef struct
{
    char *ptr;
    uint32_t row;
    uint32_t col;
    char const *file;
} ZPP_Pos;

typedef struct
{
    ZPP_Pos pos;
    uint32_t len; // NOTE: this also stores macro arg index sometimes
    uint32_t flags : 16;
    uint32_t type : 16;
} ZPP_Token;

typedef struct
{
    ZPP_Token *ptr;
    uint32_t len;
    uint32_t cap;
} ZPP_TokenArray;

typedef struct
{
    ZPP_TokenArray *ptr;
    size_t len;
} ZPP_MacroArgs;

typedef struct
{
    uint32_t flags;
    uint16_t cur_len;
    uint16_t prev_len;
} ZPP_Context;

typedef struct
{
    char *ptr;
    size_t len;
} ZPP_String;

typedef struct
{
    ZPP_Context base;
    
    ZPP_Pos pos;
    ZPP_Token result;
    ZPP_String cur_dir;
    char const *cur_file;
    
    uint32_t bstack[8];
    uint32_t flags : 3;
    uint32_t bstack_len : 29;
    uint32_t is_else_off;
} ZPP_Lexer;

typedef struct 
{
    uint32_t row;
    uint32_t col;
    size_t msg_len;
    char const *msg;
    char const *file;
} ZPP_Error;

typedef struct
{
    ZPP_Token *tokens;
    ZPP_String *args;
    char *name;

    uint32_t hash;
    uint32_t token_len;
    uint32_t arg_len;
    uint32_t name_len;

    bool is_alive : 1;
    bool is_va_args : 1;
    bool is_fn_macro : 1;
    bool is_macro : 1;
    bool disabled : 1;
} ZPP_Ident;

typedef struct
{
    ZPP_Context base;
    uint32_t token_len;
    
    ZPP_Ident *macro;
    ZPP_Token *tokens;
    uint32_t token_total;
} ZPP_MacroContext;

typedef struct
{
    ZPP_Ident *keys;
    uint32_t len;
    uint32_t cap;
} ZPP_IdentMap;

typedef struct
{
    char *name;
    uint32_t hash;
    uint32_t name_len;
} ZPP_GenKey;

typedef struct
{
    ZPP_GenKey **keys;
    uint32_t len;
    uint32_t cap;
} ZPP_GenMap;

typedef union
{
    ZPP_Lexer lexer;
    ZPP_Context base;
    ZPP_MacroContext macro_context;
} ZPP_ContextBlock;
                   
typedef struct
{
    size_t len;
    size_t cap;
} ZPP_GenArray;

typedef struct
{
    int32_t min_prec;
    uint32_t pr_level;
} ZPP_IfData;

typedef struct
{
    int64_t val;
    bool sign;
} ZPP_PPNum;

typedef struct
{
    ZPP_GenKey key;
    ZPP_Ident *macro;
    ZPP_ARRAY(ZPP_Ident) val;
} ZPP_MacroStack;

typedef struct
{
    ZPP_Token result;
    ZPP_Token peek_tok;
    ZPP_ARRAY(void *) line_buf;
    ZPP_IdentMap ident_map;
    ZPP_GenMap macro_stack;

    ZPP_Platform *platform;
    ZPP_ContextBlock *context;
    ZPP_ARRAY(char) context_mem;

    ZPP_String cur_dir;
    char const *cur_file;
    ZPP_ARRAY(ZPP_String) include_paths;

    uint32_t pp_if_gr_type : 8;
    bool has_init : 1;
    bool pp_if_noeval : 1;
    bool no_file_error : 1;
}  ZPP_State;

ZPP_LINKAGE int ZPP_init_state(ZPP_State *state,
                               char *file_data,
                               char const *file_name);

ZPP_LINKAGE int ZPP_read_token(ZPP_State *state, ZPP_Error *error);

ZPP_LINKAGE void ZPP_include_path_add(ZPP_State *state, ZPP_String path);

/*
  NOTE: regarding functions defined explicitly with `static`.
  these are for internal use only and do not expect them to be stable.
*/

#ifdef ZPP_DEFINE
#define ZPP_LEXER_TRY_READ(s_, e_)                           \
    do                                                       \
    {                                                        \
        ec = ZPP_context_lex_direct(s_, e_);                 \
        if (ec <= 0) return ec;                              \
    } while(false)

#define ZPP_LEXER_TRY_READ_FULL(s_, e_)                             \
    do                                                              \
    {                                                               \
        ec = ZPP_context_lex_direct(s_, e_);                        \
        if (ec < 0) return ec;                                      \
        if (ec == 0)                                                \
        {                                                           \
            return ZPP_return_error(&(s_)->result.pos, e_,          \
                                    ZPP_ERROR_UNEXPECTED_EOF);      \
        }                                                           \
    } while (false)

#define ZPP_STATE_TRY_READ_FULL(s_, e_)                              \
    do                                                               \
    {                                                                \
        ec = ZPP_read_token(s_, e_);                                 \
        if (ec < 0) return ec;                                       \
        if (ec == 0)                                                 \
        {                                                            \
            return ZPP_return_error(&(s_)->result.pos, e_,           \
                                    ZPP_ERROR_UNEXPECTED_EOF);       \
        }                                                            \
    } while (false)

static void *ZPP_memcpy(void *dest, void const *src, size_t size)
{
    char *dest8 = dest;
    char const *src8 = src;

    while (size-- != 0) *dest8++ = *src8++;
    return dest;
}

static size_t ZPP_strlen(char const *str)
{
    size_t len = 0;
    while (*str++) ++len;
    return len;
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
        (ptr[1] == '\n' ||
         (ptr[1] == '\r' && ptr[2] == '\n'));
}

static int ZPP_return_error(ZPP_Pos *pos,
                            ZPP_Error *error,
                            char const *message)
{
    error->msg = message;
    error->row = pos->row;
    error->col = pos->col;
    error->file = pos->file;
    error->msg_len = ZPP_strlen(message);
    
    return -1;
}

// NOTE: assumes uint32_t is 4 bytes
static bool ZPP_lexer_bget(ZPP_Lexer *lexer,
                           uint32_t bit_index)
{    
    return ((lexer->bstack[bit_index/32] >> bit_index % 32) & 0x1) != 0;
}

static int ZPP_lexer_btop(ZPP_ContextBlock *context)
{
    if ((context->base.flags & ZPP_CONTEXT_FILE) == 0) return -1;

    ZPP_Lexer *lexer = &context->lexer;
    if (lexer->bstack_len == 0) return -1;
    
    return ZPP_lexer_bget(lexer, lexer->bstack_len - 1);
}

static void ZPP_lexer_bpop(ZPP_Lexer *lexer)
{
    --lexer->bstack_len;
}

static void ZPP_lexer_bpush(ZPP_Lexer *lexer, bool bit)
{
    uint32_t bit_index = lexer->bstack_len++;

    uint32_t mask = (uint32_t)0x1 << bit_index%32;
    lexer->bstack[bit_index/32] &= ~mask;
    lexer->bstack[bit_index/32] |= mask * bit;
    lexer->bstack[bit_index/32 + 4] &= ~mask;
}

static bool ZPP_lexer_btope(ZPP_Lexer *lexer)
{
    return ZPP_lexer_bget(lexer, lexer->bstack_len + 127);
}

static bool ZPP_lexer_belse(ZPP_Lexer *lexer)
{
    if (ZPP_lexer_btope(lexer))
    {
        return true;
    }

    if (!lexer->is_else_off)
    {
        uint32_t bit_index = lexer->bstack_len - 1;
        lexer->bstack[bit_index/32] ^= (uint32_t)0x1 << bit_index%32;
        lexer->bstack[bit_index/32 + 4] |= (uint32_t)0x1 << bit_index%32;
    }
    
    return false;
}

// NOTE: before using this remember to save the old location
static char ZPP_lexer_read_char(ZPP_Lexer *lexer)
{
    while(ZPP_is_newline_escape(lexer->pos.ptr))
    {
        ++lexer->pos.row;
        lexer->pos.col = 0;
        lexer->pos.ptr += lexer->pos.ptr[1] == '\r' ? 3 : 2;
    }
 
    ++lexer->pos.col;
    return *lexer->pos.ptr++;
}

static void ZPP_lexer_fix_tok(ZPP_Token *token,
                              ZPP_String range)
{
    ptrdiff_t line_count = 0;
    char *read_ptr = range.ptr;
    char *write_ptr = range.ptr;

    for (uint32_t i = 0; i < token->len; ++i)
    {
        while(ZPP_is_newline_escape(read_ptr))
        {
            ++line_count;
            read_ptr += read_ptr[1] == '\r' ? 3 : 2;
        }

        *write_ptr++ = *read_ptr++;
    }

    // fill old data with spaces and newlines
    ptrdiff_t left_over = read_ptr - write_ptr - line_count;
    for (ptrdiff_t i = 0; i < left_over; ++i)
    {
        *write_ptr++ = ' ';
    }

    while (write_ptr != read_ptr)
    {
        *write_ptr++ = '\n';
    }   
}

static int ZPP_lexer_read_string_rest(ZPP_Lexer *lexer, ZPP_Error *error,
                                      char delimiter, bool slow_path)
{
    char last_chars[2] = {0};
    for(;;)
    {
        if (ZPP_is_newline_escape(lexer->pos.ptr))
        {
            slow_path = true;
            do
            {
                ++lexer->pos.row;
                lexer->pos.col = 0;
                lexer->pos.ptr += lexer->pos.ptr[1] == '\r' ? 3 : 2;
            } while(ZPP_is_newline_escape(lexer->pos.ptr));
        }

        char ch = *lexer->pos.ptr;
        if (ch == '\n' || ch == '\0')
        {
            return ZPP_return_error(&lexer->pos, error,
                                    delimiter == '"' ?
                                    "expected \"" :
                                    "expected '");
        }
        
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
            if (slow_path)
            {
                ZPP_lexer_fix_tok(&lexer->result,
                                  (ZPP_String) {
                                      lexer->result.pos.ptr,
                                      (size_t)
                                      (lexer->pos.ptr -
                                       lexer->result.pos.ptr + 1),
                                  });
            }
    
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
    lexer->result.flags = 0;
    if ((lexer->flags & ZPP_LEXER_BOL) != 0)
    {
        lexer->result.flags = ZPP_TOKEN_BOL;
    }
    lexer->flags &= ~(uint32_t)ZPP_LEXER_BOL;

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
            if ((lexer->flags & ZPP_LEXER_PP) != 0)
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
        lexer->result.type = (uint32_t)*lexer->pos.ptr; 
        switch (*lexer->pos.ptr)
        {
            case '\'':
            {
                ++lexer->pos.ptr;
                ++lexer->pos.col;
                
                lexer->result.len = 1;
                lexer->result.flags |= ZPP_TOKEN_CHAR;
                return ZPP_lexer_read_string_rest(lexer, error, '\'', false);
            }
            
            case '"':
            {
                ++lexer->pos.ptr;
                ++lexer->pos.col;

                lexer->result.len = 1;
                lexer->result.flags |= ZPP_TOKEN_STR;
                return ZPP_lexer_read_string_rest(lexer, error, '"', false);
            }  
            
            case '^': new_ptr = "^="; lexer->result.type = ZPP_TYPE_XORQ; goto star_case;
            case '%': new_ptr = "%="; lexer->result.type = ZPP_TYPE_MODQ; goto star_case;
            case '!': new_ptr = "!="; lexer->result.type = ZPP_TYPE_NOTQ; goto star_case;
            case '=': new_ptr = "=="; lexer->result.type = ZPP_TYPE_EQQ;  goto star_case;
            case '*': new_ptr = "*="; lexer->result.type = ZPP_TYPE_MULQ;
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

                lexer->result.type = (uint32_t)*lexer->result.pos.ptr;
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
                    if (ch == '&')
                    {
                        lexer->result.pos.ptr = "&&";
                        lexer->result.type = ZPP_TYPE_AND2;
                    }
                    else if (ch == '|')
                    {
                        lexer->result.pos.ptr = "||";
                        lexer->result.type = ZPP_TYPE_OR2;
                    }
                    else
                    {
                        lexer->result.pos.ptr = "++";
                        lexer->result.type = ZPP_TYPE_ADD2;
                    }
                    
                    return 1;
                }
                else if (ch == '=')
                {
                    if (ch == '&')
                    {
                        lexer->result.pos.ptr = "&=";
                        lexer->result.type = ZPP_TYPE_ANDQ;
                    }
                    else if (ch == '|')
                    {
                        lexer->result.pos.ptr = "|=";
                        lexer->result.type = ZPP_TYPE_ORQ;
                    }
                    else
                    {
                        lexer->result.pos.ptr = "+=";
                        lexer->result.type = ZPP_TYPE_ADDQ;
                    }
                    lexer->result.len = 2;

                    return 1;   
                }
                
                lexer->pos = old_pos;
                return 1;
            }
            
            case '-':
            {
                ++lexer->pos.col;
                ++lexer->pos.ptr;
                lexer->result.flags |= ZPP_TOKEN_PUNCT;

                ZPP_Pos old_pos = lexer->pos;
                {
                    lexer->result.len = 2;
                    char ch = ZPP_lexer_read_char(lexer);
                    if (ch == '>')
                    {
                        lexer->result.pos.ptr = "->";
                        lexer->result.type = ZPP_TYPE_SUBGT;
                        return 1;
                    }
                    else if (ch == '=')
                    {
                        lexer->result.pos.ptr = "-=";
                        lexer->result.type = ZPP_TYPE_SUBQ;
                        return 1;
                    }
                    else if (ch == '-')
                    {
                        lexer->result.pos.ptr = "--";
                        lexer->result.type = ZPP_TYPE_SUB2;
                        return 1;
                    }
                }
                lexer->pos = old_pos;

                lexer->result.len = 1;
                return 1;
            }
            
            case '.':
            {
                ++lexer->pos.col;
                ++lexer->pos.ptr;
                lexer->result.flags |= ZPP_TOKEN_PUNCT;

                // NOTE: we don't care about line splices for numbers right now
                if (ZPP_is_digit(*lexer->pos.ptr) ||
                    (*lexer->pos.ptr == '.' &&
                     ZPP_is_digit(*lexer->pos.ptr + 1)))
                {
                    ++lexer->result.len;
                    goto lex_number;
                }

                ZPP_Pos old_pos = lexer->pos;
                if (ZPP_lexer_read_char(lexer) == '.' &&
                    ZPP_lexer_read_char(lexer) == '.')
                {
                    lexer->result.len = 3;
                    lexer->result.pos.ptr = "...";
                    lexer->result.type = ZPP_TYPE_DOT3;
                    return 1;
                }
                lexer->pos = old_pos;

                lexer->result.len = 1;
                return 1;
            }
            
            case '<':
            {
                if ((lexer->flags & ZPP_LEXER_INC) != 0)
                {
                    ++lexer->pos.col;
                    ++lexer->pos.ptr;
                    
                    lexer->result.len = 1;
                    lexer->result.flags |= ZPP_TOKEN_INC;

                    for (;;)
                    {
                        char c = *lexer->pos.ptr;
                        if (c == '\0' ||
                            ((lexer->flags & ZPP_LEXER_PP) != 0 && c == '\n'))
                        {
                            return 0;
                        }

                        ++lexer->pos.col;
                        ++lexer->pos.ptr;
                        ++lexer->result.len;

                        if (c == '>')
                        {
                            break;
                        }
                    }

                    return 1;
                }
            }
            
            case '>':
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
                        if (start_ch != ch) break;
                        
                        ZPP_Pos old_pos2 = lexer->pos;
                        if (ZPP_lexer_read_char(lexer) != '=')
                        {
                            lexer->result.len = 2;
                            if (start_ch == '<')
                            {
                                lexer->result.pos.ptr = "<<";
                                lexer->result.type = ZPP_TYPE_SHIFTL;
                            }
                            else
                            {
                                lexer->result.pos.ptr = ">>";
                                lexer->result.type = ZPP_TYPE_SHIFTR;
                            }
                                                    
                            lexer->pos = old_pos2;
                            return 1;
                        }
                                
                        lexer->result.len = 3;
                        if (start_ch == '<')
                        {
                            lexer->result.pos.ptr = "<<=";
                            lexer->result.type = ZPP_TYPE_SHIFTLQ;
                        }
                        else
                        {
                            lexer->result.pos.ptr = ">>=";
                            lexer->result.type = ZPP_TYPE_SHIFTRQ;
                        }
                        
                        return 1;
                    }
                        
                    case '=':
                    {
                        lexer->result.len = 2;
                        if (start_ch == '<')
                        {
                            lexer->result.pos.ptr = "<=";
                            lexer->result.type = ZPP_TYPE_LTQ;
                        }
                        else
                        {
                            lexer->result.pos.ptr = ">=";
                            lexer->result.type = ZPP_TYPE_GTQ;
                        }
                        
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
                        lexer->result.type = ZPP_TYPE_HASH2;
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

                    char cur;
                    while ((cur = ZPP_lexer_read_char(lexer)) != '\n')
                    {
                        if (cur == '\0')
                        {
                            goto eof_found;
                        }
                    }

                    if ((lexer->flags & ZPP_LEXER_PP) != 0)
                    {
                        return 0;
                    }
                            
                    ++lexer->pos.row;
                    lexer->pos.col = 0;
                    continue;
                }
                else if (ch == '*')
                {
                    lexer->result.flags |= ZPP_TOKEN_SPACE;
                    char cur = ZPP_lexer_read_char(lexer);
                    for(;;)
                    {
                        if (cur == '*')
                        {
                            cur = ZPP_lexer_read_char(lexer);
                            if (cur == '/') break;
                            continue;
                        }
                        else if (cur == '\n')
                        {
                            ++lexer->pos.row;
                            lexer->pos.col = 0;
                        }
                        else if (cur == '\0')
                        {
                            goto eof_found;
                        }
                        
                        cur = ZPP_lexer_read_char(lexer);
                    }
                    
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
                    if (*lexer->pos.ptr == 'L')
                    {
                        ZPP_Pos old_pos = lexer->pos;

                        ++lexer->pos.ptr;
                        ++lexer->pos.col;
                        char cur = ZPP_lexer_read_char(lexer);
                        if (cur == '\'' || cur == '"')
                        {
                            lexer->result.len = 2;
                            lexer->result.flags |=
                                cur == '"' ? ZPP_TOKEN_STR : ZPP_TOKEN_CHAR;

                            // if lexer->pos.ptr[-1] != 'L' then there are line splices
                            return
                                ZPP_lexer_read_string_rest(lexer, error, cur,
                                                           lexer->pos.ptr[-1] != 'L');
                        }
                        
                        lexer->pos = old_pos;
                    }
                    
                    lexer->result.len = 0;
                    return ZPP_lexer_read_ident_rest(lexer, error);
                }

                if (ZPP_is_digit(*lexer->pos.ptr))
                {
                    lexer->result.len = 0;
lex_number:         
                    lexer->result.flags |= ZPP_TOKEN_PPNUM;
                    do
                    {
                        ++lexer->result.len;
                        ++lexer->pos.ptr;
                        ++lexer->pos.col;
                    } while (*lexer->pos.ptr == '.' || 
                             ZPP_is_digit(*lexer->pos.ptr) ||
                             ZPP_is_ident_char(*lexer->pos.ptr) ||
                             ((*lexer->pos.ptr == '+' || *lexer->pos.ptr == '-') &&
                              (*lexer->pos.ptr == 'E' || *lexer->pos.ptr == 'e' ||
                               *lexer->pos.ptr == 'P' || *lexer->pos.ptr == 'p')));
                             
                    return 1;
                }

                ++lexer->pos.ptr;
                ++lexer->pos.col;
                lexer->result.len = 1;
                
                return 1;
            }
        }
    }
}

static void *ZPP_gen_alloc(ZPP_State *state, size_t size)
{
    return state->platform->gen_alloc(state->platform, size); 
}

static void *ZPP_gen_calloc(ZPP_State *state, size_t size)
{
    return state->platform->gen_calloc(state->platform, size); 
}

static void *ZPP_gen_realloc(ZPP_State *state, void *ptr, size_t size)
{
    return state->platform->gen_realloc(state->platform, ptr, size); 
}

static void ZPP_gen_free(ZPP_State *state, void *ptr)
{
    state->platform->gen_free(state->platform, ptr); 
}

static void ZPP_canonicalize_path(ZPP_State *state, char *str)
{
    state->platform->canonicalize_path(state->platform, str);
}

static char *ZPP_open_file(ZPP_State *state, char const *str)
{
    return state->platform->open_file(state, str);
}

static int ZPP_context_pop(ZPP_State *state)
{
    if ((state->context->base.flags & ZPP_CONTEXT_LOCK) != 0)
    {
        return 0;
    }

    if (ZPP_ALEN(state->context_mem) == 0 ||
        (ZPP_ALEN(state->context_mem) -=
         state->context->base.cur_len) == 0)
    {
        return 0;
    }
    
    state->context =
        (ZPP_ContextBlock*)((char*)state->context -
                            state->context->base.prev_len);
    return 1;
}

static void *ZPP_array_new_impl(ZPP_State *state,
                                size_t type,
                                size_t len, size_t cap)
{
    ZPP_GenArray *block =
        ZPP_gen_alloc(state, sizeof *block + cap * type);

    block->len = len;
    block->cap = cap;

    return &block[1];
}

static void ZPP_array_grow_impl(ZPP_State *state,
                                void *gen_array_ptr,
                                size_t type, size_t grow)
{
    void **array_ptr = gen_array_ptr;
    ZPP_GenArray *block = (ZPP_GenArray*)*array_ptr - 1;

    if (block->len + grow > block->cap)
    {
        block->cap = (block->len + grow)*3/2;
        block = ZPP_gen_realloc(state, block,
                                sizeof *block +
                                block->cap * type);
        *array_ptr = &block[1];
    }

    block->len += grow;
}

static void ZPP_context_push(ZPP_State *state, ZPP_ContextBlock *item)
{
    uint16_t prev_len =
        ZPP_ALEN(state->context_mem) != 0 ?
        state->context->base.cur_len : 0;
    
    ZPP_ARRAY_GROW(&state->context_mem, item->base.cur_len);
    
    state->context =
        (ZPP_ContextBlock*)
        (state->context_mem +
         ZPP_ALEN(state->context_mem) -
         item->base.cur_len);
    
    ZPP_memcpy(state->context, item, item->base.cur_len);
    state->context->base.prev_len = prev_len;
}

static int ZPP_context_lex_direct(ZPP_State *state, ZPP_Error *error)
{
    if (state->peek_tok.pos.ptr != NULL)
    {
        state->result = state->peek_tok;
        state->peek_tok = (ZPP_Token){0};
        return 1;
    }
    
    if (ZPP_ALEN(state->context_mem) == 0)
    {
        return 0;
    }
    
    for(;;)
    {   
        switch (state->context->base.flags &
                (uint32_t)ZPP_CONTEXT_TYPES)
        {
            case ZPP_CONTEXT_FILE:
            {
                ZPP_Lexer *lexer = &state->context->lexer;
            
                int result = ZPP_lexer_lex_direct(lexer, error);
                state->result = lexer->result;
                state->result.pos.file = state->cur_file;
                    
                if (result == 0)
                {
                    if (lexer->bstack_len != 0 &&
                        (lexer->flags & ZPP_LEXER_PP) == 0)
                    {
                        return
                            ZPP_return_error(&lexer->pos, error,
                                             "missing #endif");
                    }

                    char const *last_file = lexer->pos.file;
                    if (ZPP_context_pop(state) != 0)
                    {
                        // NOTE: we don't want to free the base file name
                        ZPP_gen_free(state, (void*)last_file);

                        lexer = &state->context->lexer;
                        state->cur_dir = lexer->cur_dir;
                        state->cur_file = lexer->pos.file;
                        continue;
                    }
                    
                    return 0;
                }
            
                return result;
            }
 
            case ZPP_CONTEXT_MACRO:
            {
                ZPP_MacroContext *macro_context =
                    &state->context->macro_context;

                if (macro_context->token_len == 0)
                {
                    if (macro_context->macro != NULL)
                    {
                        macro_context->macro->disabled = false;
                    }
                    
                    if (ZPP_context_pop(state) != 0)
                    {
                        ZPP_gen_free(state,
                                     macro_context->tokens -
                                     macro_context->token_total);
                        continue;
                    }
                    
                    return 0; 
                }

                --macro_context->token_len;
                state->result = *macro_context->tokens++;

                return 1;
            }
            
            default: return -1;
        }
    }
}

static ZPP_String ZPP_tok_to_str(ZPP_Token *token)
{
    return (ZPP_String) {
        .len = token->len,
        .ptr = token->pos.ptr,
    };
}

static bool ZPP_string_cmp(ZPP_String a, ZPP_String b)
{
    if (a.len != b.len) return false;

    for (size_t i = 0; i < a.len; ++i)
    {
        if (a.ptr[i] != b.ptr[i]) return false;
    }
    
    return true;
}

// NOTE: assumes that str contains no null terminator
static bool ZPP_string_cmp2(ZPP_String str, char const *lit)
{
    for (size_t i = 0; i < str.len; ++i, ++lit)
    {
        if (str.ptr[i] != *lit) return false;
    }

    return *lit == '\0';
}

static bool ZPP_string_cmp3(ZPP_Token *tok, char const *lit)
{
    return ZPP_string_cmp2(ZPP_tok_to_str(tok), lit);
}

static uint32_t ZPP_string_hash(char *ptr, size_t len)
{
    uint32_t hash = 5381;
    for (size_t i = 0; i < len; ++i)
        hash = ((hash << 5) + hash) + (uint32_t)ptr[i]; /* has * 33 + c */

    return hash;
}

static ZPP_Ident *ZPP_ident_map_get(ZPP_State *state, ZPP_String name)
{
    uint32_t name_hash = ZPP_string_hash(name.ptr, name.len);
    uint32_t map_index = name_hash & (state->ident_map.cap - 1);
    
    for(uint32_t i = 0; i < state->ident_map.cap; ++i)
    {
        ZPP_Ident *key = &state->ident_map.keys[map_index];
        if (!key->is_alive) break;
        
        if (key->hash == name_hash &&
            ZPP_string_cmp((ZPP_String){key->name, key->name_len}, name))
        {
            return key;
        }

        ++map_index;
        map_index  &= state->ident_map.cap - 1;
    }

    return NULL;
}

static ZPP_Ident *ZPP_ident_map_set(ZPP_State *state, ZPP_Ident *macro)
{
    if ((state->ident_map.len + 1)*4/3 > state->ident_map.cap)
    {
        uint32_t new_cap = state->ident_map.cap * 2;
        ZPP_Ident *new_keys =
            ZPP_gen_calloc(state, new_cap*sizeof *new_keys);

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

    ++state->ident_map.len;
    macro->is_alive = true;
    macro->hash = ZPP_string_hash(macro->name, macro->name_len);
    uint32_t map_index = macro->hash & (state->ident_map.cap - 1);

    for(;;)
    {
        if (!state->ident_map.keys[map_index].is_alive)
        {
            ZPP_Ident *ret =
                &state->ident_map.keys[map_index];

            *ret = *macro;
            return ret;
        }

        ++map_index;
        map_index &= state->ident_map.cap - 1;
    }
}

static void *ZPP_gen_map_get(ZPP_GenMap *map,
                             ZPP_String name)
{
    uint32_t name_hash =
        ZPP_string_hash(name.ptr, name.len);
    
    uint32_t map_index =
        name_hash & (map->cap - 1);
    
    for(uint32_t i = 0; i < map->cap; ++i)
    {
        ZPP_GenKey *key = map->keys[map_index];
        if (key == NULL) break;
        
        if (key->hash == name_hash &&
            ZPP_string_cmp(
                (ZPP_String) {
                    key->name,
                    key->name_len
                }, name))
        {
            return key;
        }

        ++map_index;
        map_index  &= map->cap - 1;
    }

    return NULL;
}

static void ZPP_gen_map_set(ZPP_State *state,
                            ZPP_GenMap *map,
                            ZPP_GenKey *key)
{
    if ((map->len + 1)*4/3 > map->cap)
    {
        uint32_t new_cap = map->cap * 2;
        ZPP_GenKey **new_keys =
            ZPP_gen_calloc(state, new_cap*sizeof *new_keys);

        for (ZPP_GenKey
                 **start = map->keys,
                 **end = map->keys +
                 map->cap;
             start != end; ++start)
        {
            if (*start == NULL) continue;
            
            uint32_t map_index = (*start)->hash & (new_cap - 1);
            for(;;)
            {
                if (new_keys[map_index] == NULL)
                {
                    new_keys[map_index] = *start;
                    break;
                }

                ++map_index;
                map_index &= new_cap - 1;
            }
        }

        ZPP_gen_free(state, map->keys);
        
        map->cap = new_cap;
        map->keys = new_keys;
    }

    ++map->len;
    key->hash = ZPP_string_hash(key->name, key->name_len);
    uint32_t map_index = key->hash & (map->cap - 1);

    for(;;)
    {
        if (map->keys[map_index] == NULL)
        {
            map->keys[map_index] = key;
            return;
        }

        ++map_index;
        map_index &= map->cap - 1;
    }
}

static ZPP_String ZPP_parse_path_dir(char const *path)
{
    ZPP_String result = {
        .ptr = (char*)path,
        .len = ZPP_strlen(path),
    };

    for (size_t i = result.len; i-- != 0; --result.len)
    {
        if (path[i] == '\\' || path[i] == '/')
        {
            break;
        }
    }

    return result;
}
 
ZPP_LINKAGE int ZPP_init_state(ZPP_State *state,
                               char *file_data,
                               char const *file_name)
{
    if (!state->has_init)
    {
        state->ident_map.cap = 512;
        state->ident_map.keys =
            ZPP_gen_calloc(state,
                           state->ident_map.cap *
                           sizeof *state->ident_map.keys);

        state->macro_stack.cap = 16;
        state->macro_stack.keys =
            ZPP_gen_calloc(state,
                           state->macro_stack.cap *
                           sizeof *state->macro_stack.keys);
        
        state->line_buf = ZPP_ARRAY_NEW1();
        state->context_mem = ZPP_ARRAY_NEW1();
        state->include_paths = ZPP_ARRAY_NEW1();
        state->has_init = true;
    }

    if (file_data != NULL)
    {
        state->cur_file = file_name;
        state->cur_dir = ZPP_parse_path_dir(file_name);
        
        ZPP_context_push(state,
                         &(ZPP_ContextBlock)
                         {
                             .lexer = {
                                 .pos.ptr = file_data,
                                 .pos.file = file_name,
                                 .flags = ZPP_LEXER_BOL,
                                 .cur_dir = state->cur_dir,
                                 .base.flags = ZPP_CONTEXT_FILE,
                                 .base.cur_len = sizeof(ZPP_Lexer),
                             }
                         });

    }
    
    return 1;
}

static int ZPP_paste_tokens(ZPP_State *state, ZPP_Error *error,
                            ZPP_Token *result, ZPP_Token *rhs)
{
    // NOTE: most c preprocessors seem to do it this way
    char *concat_token_spell =
        ZPP_gen_alloc(state, result->len + rhs->len + 1);

    ZPP_memcpy(concat_token_spell, result->pos.ptr, result->len);
    ZPP_memcpy(concat_token_spell + result->len, rhs->pos.ptr, rhs->len);
    concat_token_spell[result->len + rhs->len] = '\0';

    ZPP_Lexer lexer = { 
        .pos =
        {
            .ptr = concat_token_spell,
            .row = rhs->pos.row,
            .col = rhs->pos.col,
        },
    };

    // NOTE: this will only break if we allow custom defined identifiers 
    // NOTE: if we manage to make ZPP_lexer_lex_direct error we have done
    // we have either done something wrong or custom identifiers
    int ec;
    if ((ec = ZPP_lexer_lex_direct(&lexer, error)) < 0)
    {
        return ec;
    }
    else if (ec == 0 || *lexer.pos.ptr != '\0')
    {
        // we either had a comment /##/ meaning EOF or
        // the paste is not valid as a single token
        return ZPP_return_error(&rhs->pos, error,
                                ZPP_ERROR_INVALID_PASTE);
    }

    *result = lexer.result;
    result->pos.file = rhs->pos.file;
    if (result->pos.ptr == concat_token_spell)
    {
        // add to array of allocated tokens
        result->flags |= ZPP_TOKEN_ALLOC;
        ZPP_ARRAY_GROW(&state->line_buf, 1);
        state->line_buf[ZPP_ALEN(state->line_buf) - 1] =
            result->pos.ptr;
    }
    else
    {
        ZPP_gen_free(state, concat_token_spell);
    }

    return 1;
}

static void ZPP_fix_ident_token(ZPP_Token *token)
{
    if ((token->flags & ZPP_TOKEN_IDENT_PTR) != 0)
    {
        ZPP_Ident *arg_ident = (void*)token->pos.ptr;
        token->pos.ptr = arg_ident->name;
        token->flags &= ~(uint32_t)ZPP_TOKEN_IDENT_PTR;
    }
}

// TODO: figure out how to handle memory mangement(will probably be similar to token paste)
static int ZPP_stringize_arg(ZPP_State *state, ZPP_Error *error,
                             ZPP_Token *result, ZPP_Token arg,
                             ZPP_TokenArray *macro_args)
{
    // TODO: maybe we should just handle this when actually parsing macro define
    if ((arg.flags & ZPP_TOKEN_MACRO_ARG) == 0)
    {
        return ZPP_return_error(&arg.pos, error,
                                ZPP_ERROR_INVALID_MACRO);
    }
    
    ZPP_TokenArray args = macro_args[arg.len];
    ZPP_ARRAY(char) result_str = ZPP_ARRAY_NEW3(sizeof *result_str, 2);
    result_str[0] = '"';

    // append each token to the result string
    for (uint32_t i = 0; i < args.len; ++i)
    {
        // TODO: handle strings and chars
        ZPP_Token tok = args.ptr[i];
        bool has_space =
            i != 0 && (tok.flags & (ZPP_TOKEN_SPACE | ZPP_TOKEN_BOL)) != 0;
        
        ZPP_ARRAY_GROW(&result_str, tok.len + has_space);

        size_t str_len = ZPP_ALEN(result_str);
        if (has_space) result_str[str_len - tok.len - 2] = ' ';
        ZPP_memcpy(result_str + str_len - tok.len - 1, tok.pos.ptr, tok.len);
    }
    
    // NOTE: there will always be enough memory for a closing quote
    result_str[ZPP_ALEN(result_str) - 1] = '"';
    
    // NOTE: assumes result is a `#` token
    result->len = (uint32_t)ZPP_ALEN(result_str);
    result->pos.ptr = result_str;
    result->flags ^= (uint32_t)ZPP_TOKEN_PUNCT | (uint32_t)ZPP_TOKEN_STR;

    // keep track of allocated memory
    ZPP_ARRAY_GROW(&state->line_buf, 1);
    state->line_buf[ZPP_ALEN(state->line_buf) - 1] =
        ZPP_ARRAY_MEM(result_str);
    
    return 1;
}

static int ZPP_expand_macro(ZPP_State *state, ZPP_Error *error, bool *had_macro);
static int ZPP_expand_macro_arg(ZPP_State *state,
                                ZPP_Error *error,
                                ZPP_TokenArray *macro_arg)
{    
    ZPP_TokenArray current_arg = *macro_arg;
    ZPP_context_push(state,
                     &(ZPP_ContextBlock)
                     {
                         .macro_context = {
                             .base.flags =
                             ZPP_CONTEXT_MACRO | ZPP_CONTEXT_LOCK,
                             .base.cur_len =
                             sizeof(ZPP_MacroContext),
                             .macro = NULL,
                             .tokens = current_arg.ptr,
                             .token_len = (uint32_t)current_arg.len,
                             .token_total = (uint32_t)current_arg.len,
                         }
                     });

    ZPP_TokenArray new_tok_arr = {0};
    for(;;)
    {
        int ec;
        if ((ec = ZPP_context_lex_direct(state, error)) < 0)
        {
            return ec;
        }
                
        if (ec == 0)
        {
            // remove all modifications done to the normal args
            for (size_t j = 0; j < current_arg.len; ++j)
            {
                macro_arg->ptr[j].flags &= ~(uint32_t)ZPP_TOKEN_NO_EXPAND;
                ZPP_fix_ident_token(&current_arg.ptr[j]);
            }
                    
            break;
        }

        bool token_had_macro = false;
        if ((ec = ZPP_expand_macro(state, error, &token_had_macro)) < 0)
        {
            return ec;
        }
        
        if (token_had_macro)
        {
            continue;
        }

        if (++new_tok_arr.len > new_tok_arr.cap)
        {
            new_tok_arr.cap = (new_tok_arr.cap + 1)*3/2;
            new_tok_arr.ptr = ZPP_gen_realloc(state,
                                              new_tok_arr.ptr,
                                              new_tok_arr.cap *
                                              sizeof *new_tok_arr.ptr);
        }

        new_tok_arr.ptr[new_tok_arr.len - 1] = state->result;
    }

    ZPP_gen_free(state, macro_arg->ptr);
    *macro_arg = new_tok_arr;
    
    // remove current locked context
    state->context->base.flags &= ~(uint32_t)ZPP_CONTEXT_LOCK;
    ZPP_context_pop(state);
    return 1;
}

static ZPP_Token ZPP_num_to_tok(ZPP_State *state, uint32_t number)
{
    char *result = ZPP_gen_alloc(state, 10);

    char *ptr = result;
    uint32_t scale = number;
    do
    {
        ++ptr;
        scale /= 10;
    } while(scale != 0);

    uint32_t len = (uint32_t)(ptr - result);
    do
    {
        *--ptr = number % 10 + '0';
        number /= 10;
    } while (ptr != result);

    ZPP_ARRAY_GROW(&state->line_buf, 1);
    state->line_buf[ZPP_ALEN(state->line_buf) - 1] = result;

    return (ZPP_Token) {
        .len = len,
        .pos.ptr = result,
        .flags = ZPP_TOKEN_PPNUM,
    };
}

static int ZPP_builtin_macro(ZPP_State *state,
                             ZPP_Token *macro,
                             ZPP_Token token)
{
    token.pos.row = macro->pos.row;
    token.pos.col = macro->pos.col;
    token.pos.file = macro->pos.file;
    token.flags |= macro->flags & ZPP_TOKEN_SPACE;
    state->result = token;
    
    return 1;
}

// TODO: handles cases such as:
// #define a +
// #define b =
// a+b currently expands to ++=
// a+b should expand to + + =
// also handle removal of spaces when including macro args
// TODO: handle `#`
static int ZPP_expand_macro(ZPP_State *state, ZPP_Error *error, bool *had_macro)
{
    int ec;
    if ((state->result.flags & ZPP_TOKEN_IDENT) == 0 ||
        (state->result.flags & ZPP_TOKEN_NO_EXPAND) != 0)
    {
        ZPP_fix_ident_token(&state->result);
        return 1;
    }
    
    ZPP_Ident *ident;
    ZPP_String name_str = {0};
    if ((state->result.flags & ZPP_TOKEN_IDENT_PTR) != 0)
    {
        ident = (ZPP_Ident*)state->result.pos.ptr;
        ZPP_fix_ident_token(&state->result);
    }
    else
    {
        name_str = ZPP_tok_to_str(&state->result);
        ident = ZPP_ident_map_get(state, name_str);
    }
    
    ZPP_Token ident_tok = state->result;
    if (ident == NULL) 
    {
        if (ZPP_string_cmp3(&ident_tok, "__LINE__"))
        {
            return
                ZPP_builtin_macro(state, &ident_tok,
                                  ZPP_num_to_tok(state, ident_tok.pos.row));
        }
        
        return 1;
    }
    else if (!ident->is_macro)
    {
        return 1;
    }
    else if(ident->disabled)
    {
        state->result.flags |= ZPP_TOKEN_NO_EXPAND;
        return 1;
    }
 
    ZPP_ARRAY(ZPP_TokenArray) macro_args = NULL;
    ZPP_ARRAY(ZPP_TokenArray) expand_macro_args = NULL;
    if (ident->is_fn_macro)
    {
        // peek a token ahead for '(' and if not found just leave this token alone
        ZPP_Token old_result = state->result;
        if ((ec = ZPP_context_lex_direct(state, error)) < 0)
        {
            return ec;
        }
        else if (ec == 0 ||
                 *state->result.pos.ptr != '(')
        {
            if (ec != 0) state->peek_tok = state->result;
            state->result = old_result;
            return 1; 
        }

        // read the macro function arguments
        size_t token_args_cap = 0;
        macro_args =
            ZPP_ARRAY_NEW2(sizeof *macro_args, ident->arg_len);
        
        if (ident->arg_len != 0)
        {
            macro_args[0] = (ZPP_TokenArray){0};
        }

        // NOTE: we need to handle cases where a macro currently not enabled
        // becomes enabled by macro expansions split across other contexts.
        // for example in:
        // #define foo(x) [x]
        // #define bar foo(bar
        // #define buz bar)
        // we would need to make sure not to expand the bar in `foo(bar`
        for(ptrdiff_t scope_level = 1;;)
        {
            ZPP_LEXER_TRY_READ_FULL(state, error);
            
            if (*state->result.pos.ptr == ')')
            {
                --scope_level;
                if (scope_level != 0)
                {
                    goto push_token;
                }

                // handle the case where arguments can omitted
                if (ZPP_ALEN(macro_args) != ident->arg_len &&
                    (ident->is_va_args || ident->arg_len == 1))
                {
                    size_t *macro_args_len =
                        &ZPP_ALEN(macro_args);
                    *macro_args_len = ident->arg_len;
                    macro_args[*macro_args_len - 1] = (ZPP_TokenArray){0};
                }

                // return an error if the macro did not have enough arguments
                if (ident->arg_len != ZPP_ALEN(macro_args))
                {
                    return ZPP_return_error(&state->result.pos, error,
                                            ZPP_ERROR_INVALID_MACRO);
                }

                break;
            }
                
            if (ZPP_ALEN(macro_args) == 0)
            {
                ZPP_ALEN(macro_args) = 1;
            }

            if (*state->result.pos.ptr == '(')
            {
                ++scope_level;
            }
            else if (*state->result.pos.ptr == ',' && scope_level < 2)
            {
                // we have a new argument
                if (ZPP_ALEN(macro_args) != ident->arg_len)
                {
                    token_args_cap = 0;
                    macro_args[ZPP_ALEN(macro_args)++] =
                        (ZPP_TokenArray){0};   
                    continue;
                }

                // for ... commas are just added to __VA_ARGS__ instead being a new argument
                if (ident->is_va_args)
                {
                    goto push_token;
                }

                return ZPP_return_error(&state->result.pos, error,
                                        ZPP_ERROR_INVALID_MACRO);
            }
            
push_token:;
            ZPP_TokenArray *current =
                &macro_args[ZPP_ALEN(macro_args) - 1];
            if (++current->len > token_args_cap)
            {
                token_args_cap = (token_args_cap + 1)*3/2;
                current->ptr = ZPP_gen_realloc(state,
                                               current->ptr,
                                               token_args_cap *
                                               sizeof *current->ptr);
            }
            current->ptr[current->len - 1] = state->result;
            
            if ((state->result.flags & ZPP_TOKEN_IDENT) == 0)
            {
                continue;
            }

            ZPP_Ident *arg_ident =
                ZPP_ident_map_get(state, ZPP_tok_to_str(&state->result));
            
            if (arg_ident == NULL)
            {
                continue;
            }

            current->ptr[current->len - 1].pos.ptr = (char*)arg_ident;
            current->ptr[current->len - 1].flags |= ZPP_TOKEN_IDENT_PTR;

            if (arg_ident->disabled)
            {        
                current->ptr[current->len - 1].flags |= ZPP_TOKEN_NO_EXPAND;
            }
        }

        expand_macro_args =
            ZPP_ARRAY_NEW3(sizeof *expand_macro_args, ident->arg_len);

        size_t macro_args_len =
            ZPP_ALEN(macro_args);
        for (uint32_t i = 0; i < macro_args_len; ++i)
        {
            ZPP_TokenArray src =
                macro_args[i];
            
            ZPP_TokenArray copy = {
                .ptr = ZPP_gen_alloc(state,
                                     src.len*sizeof *src.ptr),
                .len = src.len,
            };

            ZPP_memcpy(copy.ptr, src.ptr, src.len*sizeof *src.ptr);
            expand_macro_args[i] = copy;

            // fix unexpanded macros
            for (uint32_t j = 0; j < src.len; ++j)
            {
                ZPP_fix_ident_token(&src.ptr[j]);
                src.ptr[j].flags &= ~(uint32_t)ZPP_TOKEN_NO_EXPAND;
            }
        }        
    }

    *had_macro = true;
    if (ident->token_len != 0)
    {
        ZPP_GenArray tok_arr = {
            .cap = ident->token_len
        };
        ZPP_Token *tokens =
            ZPP_gen_alloc(state, tok_arr.cap*sizeof *tokens);
        
        for (uint32_t i = 0; i < ident->token_len; ++i)
        {
            bool is_stringize =
                ident->tokens[i].len == 1 &&
                *ident->tokens[i].pos.ptr == '#';
            
            bool is_paste_next = 
                i + 1 + is_stringize < ident->token_len &&
                ident->tokens[i + 1 + is_stringize].len == 2 &&
                *ident->tokens[i + 1 + is_stringize].pos.ptr == '#';

            bool is_lhs_empty = false;

            if (is_stringize)
            {
                if (++tok_arr.len > tok_arr.cap)
                {
                    tok_arr.cap = tok_arr.len*3/2;
                    tokens = ZPP_gen_realloc(state, tokens,
                                             tok_arr.cap *
                                             sizeof *tokens);
                }
                
                tokens[tok_arr.len - 1] = ident->tokens[i];
                if ((ec = ZPP_stringize_arg(state, error,
                                            &tokens[tok_arr.len - 1],
                                            ident->tokens[i + 1],
                                            macro_args)) < 0)
                {
                    return ec;
                }

                // skip #arg
                ++i;
                goto was_stringize;
            }
            
            if ((ident->tokens[i].flags & ZPP_TOKEN_MACRO_ARG) != 0)
            {
                ZPP_TokenArray *arg;
                if (!is_paste_next)
                {
                    arg =
                        &expand_macro_args[ident->tokens[i].len];

                    if (arg->cap != UINT32_MAX &&
                        (ec = ZPP_expand_macro_arg(state, error, arg)) < 0)
                    {
                        return ec;
                    }
                    else
                    {
                        arg->cap = UINT32_MAX;
                    }
                }
                else
                {
                    arg = &macro_args[ident->tokens[i].len];
                }
                
                // if the arg is empty we don't need to append anything
                if (arg->len == 0)
                {
                    is_lhs_empty = true;
                }

                tok_arr.len += arg->len;
                if (tok_arr.len > tok_arr.cap)
                {
                    tok_arr.cap = tok_arr.len*3/2;
                    tokens =
                        ZPP_gen_realloc(state, tokens,
                                        tok_arr.cap *
                                        sizeof *tokens);
                }
                
                ZPP_memcpy(tokens +
                           tok_arr.len - arg->len,
                           arg->ptr, arg->len*sizeof *tokens);
            }
            else
            {
                if (++tok_arr.len > tok_arr.cap)
                {
                    tok_arr.cap = tok_arr.len*3/2;
                    tokens = ZPP_gen_realloc(state, tokens,
                                             tok_arr.cap *
                                             sizeof *tokens);
                }
                
                tokens[tok_arr.len - 1] = ident->tokens[i];
            }

was_stringize:;
            if (!is_paste_next) continue;            
            do
            {
                i += 2;
                if ((ident->tokens[i].flags & ZPP_TOKEN_MACRO_ARG) != 0)
                {
                    bool is_tok_va_args =
                        ident->is_va_args &&
                        ident->tokens[i].len == ident->arg_len - 1; 

                    ZPP_TokenArray arg =
                        macro_args[ident->tokens[i].len];
                        
                    // if the arg is empty we don't need to append anything
                    if (arg.len == 0)
                    {
                        // TODO: maybe have this as an option
                        // NOTE: GNU extension __VA_ARGS__ comma omission
                        // ,##__VA_ARGS__ becomes empty when __VA_ARGS__ is empty
                        if (!is_lhs_empty && is_tok_va_args &&
                            *tokens[tok_arr.len - 1].pos.ptr == ',')
                        {
                            --tok_arr.len;
                        }

                        continue;
                    }

                    bool arg_skip = !is_lhs_empty;
                    if (!is_lhs_empty)
                    {
                        // NOTE: for gcc ,##__VA_ARGS__ it just appends __VA_ARGS__
                        if (is_tok_va_args &&
                            *tokens[tok_arr.len - 1].pos.ptr == ',')
                        {
                            arg_skip = false;
                        }
                        else if ((ec =
                                  ZPP_paste_tokens(state, error,
                                                   &tokens[tok_arr.len - 1],
                                                   &arg.ptr[0])) < 0)
                        {
                            return ec;
                        }
                    }

                    tok_arr.len += arg.len - arg_skip;
                    if (tok_arr.len > tok_arr.cap)
                    {
                        tok_arr.cap = tok_arr.len*3/2;
                        tokens = ZPP_gen_realloc(state, tokens,
                                                 tok_arr.cap *
                                                 sizeof *tokens);
                    }
                    
                    ZPP_memcpy(tokens +
                               tok_arr.len -
                               arg.len + arg_skip, arg.ptr + arg_skip,
                               (arg.len - arg_skip)*sizeof *tokens);
                }
                else
                {
                    ZPP_Token pasted_tok = ident->tokens[i];
                    
                    if ((is_stringize =
                         ident->tokens[i].len == 1 &&
                         *ident->tokens[i].pos.ptr == '#') != false)
                    {
                        if ((ec = ZPP_stringize_arg(state, error,
                                                    &pasted_tok,
                                                    ident->tokens[i + 1],
                                                    macro_args)) < 0)
                        {
                            return ec;
                        }
                    }

                    if (!is_lhs_empty)
                    {
                        if (((ec = ZPP_paste_tokens(state, error,
                                                    &tokens[tok_arr.len - 1],
                                                    &pasted_tok)) < 0))
                        {
                            return ec;
                        }
                    }
                    else
                    {                        
                        if (++tok_arr.len > tok_arr.cap)
                        {
                            tok_arr.cap = tok_arr.len*3/2;
                            tokens = ZPP_gen_realloc(state, tokens,
                                                     tok_arr.cap *
                                                     sizeof *tokens);
                        }
                    
                        tokens[tok_arr.len - 1] = pasted_tok;
                    }

                    i += is_stringize;
                }

                // NOTE: then if we reached this point then the lhs is not empty
                is_lhs_empty = false;
            } while (i + 1 < ident->token_len &&
                     ident->tokens[i + 1].len == 2 &&
                     *ident->tokens[i + 1].pos.ptr == '#');            
        }

        if (tok_arr.len != 0)
        {
            tokens[0].flags |= ident_tok.flags & ZPP_TOKEN_SPACE;
        }
        
        // make all the tokens expanded from this macro have the location of the macro
        for (size_t i = 0; i < tok_arr.len; ++i)
        {
            tokens[i].pos.row = ident_tok.pos.row;
            tokens[i].pos.col = ident_tok.pos.col;
            tokens[i].pos.file = ident_tok.pos.file;
        }
        
        // disable the macro before expanding it
        ident->disabled = true;
        ZPP_context_push(state,
                         &(ZPP_ContextBlock)
                         {
                             .macro_context = {
                                 .macro = ident,
                                 .tokens = tokens,
                                 .token_len = (uint32_t)tok_arr.len,
                                 .token_total = (uint32_t)tok_arr.len,
                                 .base.flags = ZPP_CONTEXT_MACRO,
                                 .base.cur_len = sizeof(ZPP_MacroContext),
                             }
                         });

        if (macro_args != NULL)
        {
            ZPP_ARRAY_FREE(macro_args);
        }
        
        if (expand_macro_args != NULL)
        {
            ZPP_ARRAY_FREE(expand_macro_args);
        }    
    }
    
    return 1;
}

static bool ZPP_is_defined(ZPP_State *state, ZPP_Token *macro_tok)
{
    ZPP_Ident *ident =
        ZPP_ident_map_get(state, ZPP_tok_to_str(macro_tok));

    return ident != NULL;
}

// TODO: handle sign, char literals, more number literals, more Ops, and short circut. 
static int ZPP_handle_if_pp(ZPP_State *state,
                            ZPP_Error *error,
                            ZPP_PPNum *result,
                            int32_t min_prec,
                            uint32_t pr_level)
{
    enum {
        PLEVEL_MIN,
        PLEVEL_SEL,
        PLEVEL_LOR,
        PLEVEL_LAND,
        PLEVEL_BOR,
        PLEVEL_BXOR,
        PLEVEL_BAND,
        PLEVEL_CMP,
        PLEVEL_SHF,   
        PLEVEL_SUM,
        PLEVEL_MUL,
        PLEVEL_MAX,
    };
    
    int ec;
    ZPP_PPNum x = {-9876, 0};  
    ZPP_STATE_TRY_READ_FULL(state, error);
    if ((state->result.flags & ZPP_TOKEN_IDENT) != 0)
    {
        if (ZPP_string_cmp3(&state->result, "defined"))
        {
            int is_defined = -1;
            bool found_paren = false;
            for(;;)
            {
                ZPP_LEXER_TRY_READ_FULL(state, error);
                if (state->result.type == '(')
                {
                    found_paren = true;
                    continue;
                }
                else if (state->result.type == ')')
                {
                    if (!found_paren || is_defined == -1)
                    {
                        return ZPP_return_error(&state->result.pos, error,
                                                ZPP_ERROR_UNEXPECTED_TOK);
                    }
                    
                    x.val = is_defined;
                    goto parsed_fac;
                }
                else if ((state->result.flags & ZPP_TOKEN_IDENT) == 0)
                {
                    return ZPP_return_error(&state->result.pos, error,
                                            ZPP_ERROR_UNEXPECTED_TOK);
                }
                
                is_defined = ZPP_is_defined(state, &state->result);
                if (!found_paren)
                {
                    x.val = is_defined;
                    goto parsed_fac;
                }
            }
        }

        x.val = 0;
    }
    else if ((state->result.flags & ZPP_TOKEN_PPNUM) != 0)
    {
        uint32_t i = 0;
        ZPP_PPNum val = {0};
        if (state->result.pos.ptr[0] == '0')
        {
            if (state->result.len > 2 &&
                (state->result.pos.ptr[1] == 'x' ||
                 state->result.pos.ptr[1] == 'X'))
            {
                for (i = 2; i < state->result.len; ++i)
                {   
                    char c = state->result.pos.ptr[i];
                    if (c >= '0' && c <= '9')
                    {
                        val.val = val.val*16 + c - '0';
                    }
                    else if (c >= 'a' && c <= 'f')
                    {
                        val.val = val.val*16 + c - 'a' + 10;
                    }
                    else if (c >= 'A' && c <= 'F')
                    {
                        val.val = val.val*16 + c - 'A' + 10;
                    }
                    else
                    {
                        break;
                    }
                }
            }
            else
            {
                for (i = 1; i < state->result.len; ++i)
                {
                    char c = state->result.pos.ptr[i];
                    if (c < '0' || c > '8')
                    {
                        break;
                    } 

                    val.val = val.val*8 + c - '0';
                }
            }
        }
        else
        {
            for (i = 0; i < state->result.len; ++i)
            {
                char c = state->result.pos.ptr[i];
                if (c < '0' || c > '9')
                {
                    break;
                }

                val.val = val.val*10 + c - '0';
            }
        }
        
        if (i != state->result.len)
        {
            do
            {
#define ZPP_ERROR_INVALID_NUM "invalid integer literal"
                char c = state->result.pos.ptr[i];
                if (c == 'u' || c == 'U')
                {
                    if (val.sign == 1)
                    {
                        return
                            ZPP_return_error(&state->result.pos, error,
                                             ZPP_ERROR_INVALID_NUM);
                    }
                    
                    val.sign = 1;
                    continue;
                }

                if (c == 'l' || c == 'L')
                {
                    if (i + 1 >= state->result.len)
                    {
                        break;
                    }

                    if (i + 2 >= state->result.len &&
                        state->result.pos.ptr[i + 1] == c)
                    {
                        break;
                    }
                }

                return
                    ZPP_return_error(&state->result.pos, error,
                                     ZPP_ERROR_INVALID_NUM);
#undef ZPP_ERROR_INVALID_NUM
            } while (++i < state->result.len);
        }
        
        x = val;
    }
    else if ((state->result.flags & ZPP_TOKEN_PUNCT))
    {
        ZPP_Token op_tok = state->result;
        for (int i = 0; i < 2; ++i)
        {
            switch(op_tok.type)
            {
                case '(':
                {
                    uint32_t old_gr_type = state->pp_if_gr_type;
                    state->pp_if_gr_type = ')';
                    if ((ec = ZPP_handle_if_pp(state, error, &x, 0, 1)) < 0)
                    {
                        return ec;
                    }
                    state->pp_if_gr_type = old_gr_type;
            
                    goto parsed_fac;
                }
                
                case '+': if (i != 0) { continue; } break;
                case '-': if (i != 0) { x.val = -x.val; continue; } break;
                case '!': if (i != 0) { x.val = !x.val; continue; } break;
                case '~': if (i != 0) { x.val = ~x.val; continue; } break;
                default:
                {
                    return ZPP_return_error(&op_tok.pos, error,
                                            ZPP_ERROR_UNEXPECTED_TOK);
                }   
            }
            
            if ((ec = ZPP_handle_if_pp(state, error,
                                       &x, PLEVEL_MAX,
                                       !!pr_level*2)) < 0)
            {
                return ec;
            }
        }
    }
    else
    {
        // TODO: handle
        __debugbreak();
    }

parsed_fac:;
    if (min_prec == PLEVEL_MAX)
    {
        *result = x;
        return 1;
    }
    
    for(;;)
    {
        ZPP_Token old_tok = state->result;
        if ((ec = ZPP_read_token(state, error)) < 0)
        {
            return ec;
        }
        else if (ec == 0)
        {
            if (pr_level > 0)
            {
                return ZPP_return_error(&old_tok.pos, error,
                                        ZPP_ERROR_UNEXPECTED_EOF);
            }
            
            *result = x;
            return 1;
        }
        
        ZPP_PPNum y = {-1234, 0};
        ZPP_Token op_tok = state->result;
        if (op_tok.type == state->pp_if_gr_type)
        {
            if (pr_level > 0)
            {
                *result = x;
                if (pr_level == 2)
                {
                    state->peek_tok = op_tok;
                }
                
                return 1;
            }
            else
            {
                return ZPP_return_error(&op_tok.pos, error,
                                        ZPP_ERROR_UNEXPECTED_TOK);
            }
        }

        int min_op_prec = -1;
        bool old_noeval = state->pp_if_noeval;
        for (int i = 0; i < 2; ++i)
        {
            switch (op_tok.type)
            {
                case ZPP_TYPE_SHIFTL:
                {
                    if (i != 0)
                    {
                        x.val =
                            x.sign                              ?
                            (int64_t)((uint64_t)x.val << y.val) :
                            x.val << y.val;
                        
                        continue;
                    }
                }
                
                case ZPP_TYPE_SHIFTR:
                {
                    if (i != 0)
                    {
                        x.val =
                            x.sign                              ?
                            (int64_t)((uint64_t)x.val >> y.val) :
                            x.val >> y.val;
                        
                        continue;
                    }
                       
                    min_op_prec = PLEVEL_SHF;
                    break;
                }

#define SIGN_OP(c) if (true) { x.val c y.val; x.sign &= y.sign; continue; } else
                case '+': if (i != 0) { SIGN_OP(+=); }
                case '-': if (i != 0) { SIGN_OP(-=); }
                {
                    min_op_prec = PLEVEL_SUM;
                    break;
                }
                
                case '*': if (i != 0) { SIGN_OP(*=); }
                case '/':
                {
                    if (i != 0)
                    {
                        if (y.val == 0)
                        {
                            y.val = 1;
                            if (!state->pp_if_noeval)
                            {
                                return
                                    ZPP_return_error(&op_tok.pos, error,
                                                     "division by zero");
                            }
                        }
                        
                        SIGN_OP(/=);
                    }
                }
                case '%':
                {
                    if (i != 0)
                    {
                        if (y.val == 0)
                        {
                            y.val = 1;
                            if (!state->pp_if_noeval)
                            {
                                return
                                    ZPP_return_error(&op_tok.pos, error,
                                                     "division by zero");
                            }
                        }
                        
                        SIGN_OP(%=);
                    }
                    
                    min_op_prec = PLEVEL_MUL;
                    break;
                }

                case '|':
                {
                    if (i != 0)
                    {
                        SIGN_OP(|=);
                    }
                    
                    min_op_prec = PLEVEL_BOR;
                    break;
                }

                case '^':
                {
                    if (i != 0)
                    {
                        SIGN_OP(^=);
                    }
                    
                    min_op_prec = PLEVEL_BXOR;
                    break;
                }

                case '&':
                {
                    if (i != 0)
                    {
                        SIGN_OP(&=);
                    }
                    
                    min_op_prec = PLEVEL_BAND;
                    break;
                }

                case ZPP_TYPE_OR2:
                {
                    if (i != 0)
                    {
                        x.val = x.val != 0 || y.val != 0;
                        continue;
                    }

                    state->pp_if_noeval |= x.val != 0;
                    min_op_prec = PLEVEL_LOR;
                    break;
                }
                
                case ZPP_TYPE_AND2:
                {
                    if (i != 0)
                    {
                        x.val = x.val != 0 && y.val != 0;
                        continue;
                    }

                    state->pp_if_noeval |= x.val == 0;
                    min_op_prec = PLEVEL_LAND;
                    break;
                }
                
#undef SIGN_OP
                
#define SIGN_CMP(c)                                                     \
                if (true)                                               \
                {                                                       \
                    x.val = !x.sign ?                                   \
                        (uint64_t)x.val c (uint64_t)y.val :             \
                        x.val c y.val;                                  \
                    continue;                                           \
                } else
                
                case '<': if (i != 0) { SIGN_CMP(<); }
                case '>': if (i != 0) { SIGN_CMP(>); }
                case ZPP_TYPE_GTQ: if (i != 0) { SIGN_CMP(>=); }
                case ZPP_TYPE_LTQ: if (i != 0) { SIGN_CMP(<=); }
                case ZPP_TYPE_EQQ:
                case ZPP_TYPE_NOTQ:
                {
                    if (i != 0)
                    {
                        x.val =
                            op_tok.type == ZPP_TYPE_NOTQ ?
                            x.val != y.val : x.val == y.val;
                        
                        continue;
                    }

                    min_op_prec = PLEVEL_CMP;
                    break;
                }
#undef SIGN_CMP

                case '?':
                {
                    if (min_prec > PLEVEL_SEL)
                    {
                        state->peek_tok = op_tok;
                        *result = x;
                        return 1;
                    }
            

                    old_noeval = state->pp_if_noeval;
                    if (x.val == 0) state->pp_if_noeval |= 1;
                    
                    ZPP_PPNum b;
                    uint32_t old_gr_type = state->pp_if_gr_type;
                    state->pp_if_gr_type = ':';
                    if ((ec = ZPP_handle_if_pp(state, error, &b, 0, 1)) < 0)
                    {
                        return ec;
                    }
                    state->pp_if_gr_type = old_gr_type;

                    state->pp_if_noeval = old_noeval;
                    if (x.val != 0) state->pp_if_noeval |= 1;
                    
                    ZPP_PPNum c;
                    if ((ec = ZPP_handle_if_pp(state, error,
                                               &c, PLEVEL_SEL,
                                               !!pr_level*2)) < 0)
                    {
                        return ec;
                    }
                    state->pp_if_noeval = old_noeval;
                    
                    x = x.val != 0 ? b : c;
                    goto op_break;
                }
                
                default:
                {
                    return ZPP_return_error(&op_tok.pos, error,
                                            ZPP_ERROR_UNEXPECTED_TOK);
                }
            }
            
            if (min_prec > min_op_prec)
            {
                state->peek_tok = op_tok;
                *result = x;
                return 1;
            }
            
            if ((ec = ZPP_handle_if_pp(state, error, &y,
                                       min_op_prec + 1,
                                       !!pr_level*2)) < 0)
            {
                return ec;
            }
        }
op_break:
        state->pp_if_noeval = old_noeval;    
    }
}

static void ZPP_clear_line_buf(ZPP_State *state)
{
    size_t *len = &ZPP_ALEN(state->line_buf);
    for (size_t i = 0; i < *len; ++i)
    {
        ZPP_gen_free(state, state->line_buf[i]);
    }

    *len = 0;
}

static int ZPP_handle_pragma(ZPP_State *state,
                             ZPP_Error *error,
                             bool *not_found)
{
    int ec;
    ZPP_LEXER_TRY_READ_FULL(state, error);

    bool is_push_macro;
    if ((is_push_macro =
         ZPP_string_cmp3(&state->result, "push_macro")) != false ||
        ZPP_string_cmp3(&state->result, "pop_macro"))
    {
        ZPP_LEXER_TRY_READ_FULL(state, error);
        if (state->result.type != '(')
        {
            return ZPP_return_error(&state->result.pos,
                                    error, "expected '('");
        }

        ZPP_LEXER_TRY_READ_FULL(state, error);
        if ((state->result.flags & ZPP_TOKEN_STR) == 0)
        {
            return ZPP_return_error(&state->result.pos,
                                    error, "expected a string");
        }

        ZPP_Token macro_tok = state->result;
        ZPP_String macro_name = ZPP_tok_to_str(&macro_tok);
        if (*macro_name.ptr == 'L')
        {
            return ZPP_return_error(&state->result.pos, error,
                                    "expected a non wide string");
        }

        // skip '"' and ignore final '"'
        ++macro_name.ptr;
        macro_name.len -= 2;
        
        ZPP_LEXER_TRY_READ_FULL(state, error);
        if (state->result.type != ')')
        {
            return ZPP_return_error(&state->result.pos,
                                    error, "expected ')'");
        }

        if (is_push_macro)
        {
            ZPP_Ident *ident =
                ZPP_ident_map_get(state, macro_name);

            if (ident == NULL)
            {
                ident =
                    ZPP_ident_map_set(state,
                                      &(ZPP_Ident) {
                                          .name = macro_name.ptr,
                                          .name_len = (uint32_t)macro_name.len,
                                          .is_macro = false,
                                      });
            }

            ZPP_Ident copy = *ident;
            if (copy.arg_len != 0)
            {
                ZPP_String *new_args =
                    ZPP_gen_alloc(state,
                                  copy.arg_len * sizeof *new_args);

                ZPP_memcpy(new_args, copy.args,
                           copy.arg_len * sizeof *new_args);

                copy.args = new_args;
            }
            
            if (copy.token_len != 0)
            {
                ZPP_Token *new_tokens =
                    ZPP_gen_alloc(state,
                                  copy.token_len *
                                  sizeof *new_tokens);

                ZPP_memcpy(new_tokens,
                           copy.tokens,
                           copy.token_len *
                           sizeof *new_tokens);

                copy.tokens = new_tokens;
            }

            ZPP_MacroStack *stack =
                ZPP_gen_map_get(&state->macro_stack, macro_name);
            
            if (stack == NULL)
            {
                ZPP_MacroStack *new_stack =
                    ZPP_gen_alloc(state, sizeof *new_stack);

                *new_stack = (ZPP_MacroStack) {
                    .macro = ident,
                    .key.name = macro_name.ptr,
                    .key.name_len = (uint32_t)macro_name.len,
                    .val = ZPP_ARRAY_NEW3(sizeof *new_stack->val, 1),
                };
                new_stack->val[0] = copy;
                
                ZPP_gen_map_set(state,
                                &state->macro_stack,
                                (ZPP_GenKey*)new_stack);
            }
            else
            {
                ZPP_ARRAY_GROW(&stack->val, 1);
                stack->val[ZPP_ALEN(stack->val) - 1] = copy;
            }
        }
        else
        {
            ZPP_MacroStack *stack =
                ZPP_gen_map_get(&state->macro_stack, macro_name);

            if (stack == NULL || ZPP_ALEN(stack->val) == 0)
            {
                return 1;
            }
            
            ZPP_gen_free(state, stack->macro->args);
            ZPP_gen_free(state, stack->macro->tokens);
            *stack->macro = stack->val[--ZPP_ALEN(stack->val)];
        }
    }
    else
    {
        *not_found = true;
    }
    
    return 1;
}

static bool ZPP_try_open_file(ZPP_State *state,
                              ZPP_String file_name,
                              ZPP_String dir)
{
    bool has_trail =
        dir.len > 0 && 
        (dir.ptr[dir.len - 1] == '/' ||
         dir.ptr[dir.len - 1] == '\\');
            
    size_t full_path_len =
        dir.len + file_name.len + !has_trail;
    
    char *full_path =
        ZPP_gen_alloc(state, full_path_len + 1);
    full_path[full_path_len] = '\0';

    char *write_ptr = full_path;
    ZPP_memcpy(write_ptr, dir.ptr, dir.len);
    write_ptr += dir.len;

    if (dir.len > 0 && !has_trail) *write_ptr++ = '/';
    ZPP_memcpy(write_ptr, file_name.ptr, file_name.len);
    write_ptr += file_name.len;
    
    ZPP_canonicalize_path(state, full_path);
    char *file_data = ZPP_open_file(state, full_path);
    if (file_data == NULL)
    {
        ZPP_gen_free(state, full_path);
        return false;
    }

    state->cur_file = full_path;
    state->cur_dir = ZPP_parse_path_dir(full_path);
    ZPP_context_push(state,
                     &(ZPP_ContextBlock)
                     {
                         .lexer = {
                             .pos.ptr = file_data,
                             .cur_file = full_path,
                             .flags = ZPP_LEXER_BOL,
                             .cur_dir = state->cur_dir,
                             .base.flags = ZPP_CONTEXT_FILE,
                             .base.cur_len = sizeof(ZPP_Lexer),
                         }
                     });

    return true;
}

static int ZPP_handle_include(ZPP_State *state,
                              ZPP_Error *error,
                              bool use_cur_dir,
                              ZPP_String file_name)
{
    if (use_cur_dir)
    {
        if(ZPP_try_open_file(state, file_name, state->cur_dir))
        {
            return 1;
        }
    }
    
    for (uint32_t i = 0; i < ZPP_ALEN(state->include_paths); ++i)
    {
        ZPP_String dir = state->include_paths[i];
        if (ZPP_try_open_file(state, file_name, dir))
        {
            return 1;
        }
    }

    if (state->no_file_error)
    {
        return
            ZPP_return_error(&state->result.pos, error,
                             "couldn't file not found");
    }
    
    return 1;
}

ZPP_LINKAGE void ZPP_include_path_add(ZPP_State *state, ZPP_String path)
{
    ZPP_ARRAY_GROW(&state->include_paths, 1);
    state->include_paths[ZPP_ALEN(state->include_paths) - 1] = path;
}

ZPP_LINKAGE int ZPP_read_token(ZPP_State *state, ZPP_Error *error)
{
read_token:;
    int ec;
    if ((ec = ZPP_context_lex_direct(state, error)) <= 0)
    {
        return ec;
    }

    int blevel =
        ZPP_lexer_btop(state->context);
    
    if (state->result.pos.ptr[0] != '#' ||
        (state->result.flags & ZPP_TOKEN_BOL) == 0)
    {
        if (blevel == 0) goto read_token;

        // NOTE: very important we do this before expanding macros
        if ((state->result.flags & ZPP_TOKEN_BOL) != 0)
        {
            ZPP_clear_line_buf(state);
        }

        
        bool had_macro = false;
        if ((ec = ZPP_expand_macro(state, error, &had_macro)) < 0)
        {
            return ec;
        }
        
        if (had_macro) goto read_token;
        return 1;
    }
    
    // NOTE: only a file lexer should be able to return a BOL token
    // meaning that we can directly cast our context to a ZPP_Lexer
    ZPP_Lexer *lexer = &state->context->lexer;
    ZPP_Lexer old_lex = *lexer;
    
    lexer->flags |= ZPP_LEXER_PP;
    switch (ec = ZPP_lexer_lex_direct(lexer, error))
    {
        case 1: break;
        case 0:
        {
            lexer->flags &= ~(uint32_t)ZPP_LEXER_PP;
            goto read_token;
        }
              
        default: return ec;
    }
    
#define ZPP_DIRECTIVE_TRY_READ(l_, e_)                              \
    do                                                              \
    {                                                               \
        ec = ZPP_lexer_lex_direct(l_, e_);                          \
        if (ec < 0) return ec;                                      \
        if (ec == 0)                                                \
        {                                                           \
            return ZPP_return_error(&(l_)->pos, e_,                 \
                                    ZPP_ERROR_UNEXPECTED_EOF);      \
        }                                                           \
    } while (false)

    if (blevel == 0) goto pp_level0;
    if (ZPP_string_cmp3(&lexer->result, "define"))
    {
        ZPP_DIRECTIVE_TRY_READ(lexer, error);

        if ((lexer->result.flags & ZPP_TOKEN_IDENT) == 0)
        {
            return ZPP_return_error(&lexer->result.pos, error,
                                    ZPP_ERROR_UNEXPECTED_TOK);
        }

        ZPP_Pos name_pos = lexer->result.pos;
        ZPP_String name_str = ZPP_tok_to_str(&lexer->result);
        ZPP_Ident *macro = ZPP_ident_map_get(state, name_str);

        bool first_token = true;
        ZPP_Ident new_macro = {
            .name = name_str.ptr,
            .name_len = (uint32_t)name_str.len,
            .is_macro = true,
        };

        ZPP_GenArray tok_arr = {0};
        ZPP_Token *tokens = NULL;
        for(;;)
        {
            ec = ZPP_lexer_lex_direct(lexer, error);
            switch (ec)
            {
                case 0:
                {
                    if (tok_arr.len != 0 &&
                        ((tokens[0].len == 2 &&
                          *tokens[0].pos.ptr == '#') ||
                         *tokens[tok_arr.len - 1].pos.ptr == '#'))
                    {
                        return ZPP_return_error(&name_pos, error,
                                                ZPP_ERROR_INVALID_MACRO); 
                    }

                    new_macro.tokens = tokens;
                    new_macro.token_len = (uint32_t)tok_arr.len;
                    
                    lexer->flags &= ~(uint32_t)ZPP_LEXER_PP;
                    if (macro == NULL)
                    {
                        ZPP_ident_map_set(state, &new_macro);
                    }
                    else
                    {
                        new_macro.is_alive = true;
                        new_macro.hash = macro->hash;

                        // prevent already allocated name from leaking
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
                        bool first_read = true;
                        ZPP_String *args = NULL;
                        ZPP_GenArray arg_arr = {0};
                        new_macro.is_fn_macro = true;

                        for(;;)
                        {
                            ZPP_DIRECTIVE_TRY_READ(lexer, error);

                            // if we see an ident or ... add it to the array of args
                            if ((lexer->result.flags & ZPP_TOKEN_IDENT) != 0 ||
                                (new_macro.is_va_args =
                                 lexer->result.len == 3 &&
                                 lexer->result.pos.ptr[0] == '.' &&
                                 lexer->result.pos.ptr[1] == '.' &&
                                 lexer->result.pos.ptr[2] == '.') != false)
                            {
                                if (++arg_arr.len > arg_arr.cap)
                                {
                                    arg_arr.cap = arg_arr.len*3/2;
                                    args = ZPP_gen_realloc(state, args,
                                                           arg_arr.cap *
                                                           sizeof *args);
                                }

                                args[arg_arr.len - 1] =
                                    (ZPP_String)
                                    {
                                        .len = lexer->result.len,
                                        .ptr = lexer->result.pos.ptr,
                                    };
                                
                            }
                            else if (first_read &&
                                     *lexer->result.pos.ptr == ')')
                            {
                                break;
                            }
                            else 
                            {
                                return ZPP_return_error(&lexer->result.pos, error,
                                                        ZPP_ERROR_UNEXPECTED_TOK);
                            }
                            
                            ZPP_DIRECTIVE_TRY_READ(lexer, error);
                            if (new_macro.is_va_args &&
                                *lexer->result.pos.ptr != ')')
                            {
                                return ZPP_return_error(&lexer->result.pos, error,
                                                        ZPP_ERROR_UNEXPECTED_TOK);
                            }

                            if (*lexer->result.pos.ptr == ')')
                            {
                                break;
                            }
                            else if (*lexer->result.pos.ptr != ',')
                            {
                                return ZPP_return_error(&lexer->result.pos, error,
                                                        ZPP_ERROR_UNEXPECTED_TOK);
                            }

                            first_read = false;
                        }

                        new_macro.args = args;
                        new_macro.arg_len = (uint32_t)arg_arr.len;
                        break;
                    }

                    if (++tok_arr.len > tok_arr.cap)
                    {
                        tok_arr.cap = tok_arr.len*3/2;
                        tokens = ZPP_gen_realloc(state, tokens,
                                                 tok_arr.cap *
                                                 sizeof *tokens);
                    }
                    
                    // for any token in the macro body that corrisiponds to a macro argument
                    // replace the token with the respective macro argument index 
                    if (new_macro.is_fn_macro &&
                        (lexer->result.flags & ZPP_TOKEN_IDENT) != 0)
                    {
                        ZPP_String result_str = ZPP_tok_to_str(&lexer->result);
                        for (uint32_t i = 0;
                             i < new_macro.arg_len - new_macro.is_va_args; ++i)
                        {
                            if (ZPP_string_cmp(result_str, new_macro.args[i]))
                            {
                                lexer->result.len = i;
                                lexer->result.flags |= ZPP_TOKEN_MACRO_ARG;
                                break;
                            }
                        }

                        if (new_macro.is_va_args &&
                            ZPP_string_cmp2(result_str, "__VA_ARGS__"))
                        {
                            lexer->result.len = new_macro.arg_len - 1;
                            lexer->result.flags |= ZPP_TOKEN_MACRO_ARG;
                        }
                    }
                    
                    tokens[tok_arr.len - 1] = lexer->result;
                    if (first_token)
                    {
                        tokens[tok_arr.len - 1].flags &=
                            ~(uint32_t)ZPP_TOKEN_SPACE;
                    }

                    first_token = false;
                    break;
                }

                case -1: return -1;
            }
        }
    }
    else if (ZPP_string_cmp3(&lexer->result, "undef"))
    {
        ZPP_DIRECTIVE_TRY_READ(lexer, error);
        
        if ((lexer->result.flags & ZPP_TOKEN_IDENT) == 0)
        {
            return ZPP_return_error(&lexer->result.pos, error,
                                    ZPP_ERROR_UNEXPECTED_TOK);
        }
        
        ZPP_Ident *macro =
            ZPP_ident_map_get(state,
                              ZPP_tok_to_str(&lexer->result));

        // TODO: handle macro not already existing
        if (macro != NULL)
        {
            macro->arg_len = 0;
            macro->token_len = 0;
            macro->is_macro = false;
            ZPP_gen_free(state, macro->args);
            ZPP_gen_free(state, macro->tokens);
            macro->tokens = NULL;
            macro->args = NULL;
        }
        
        lexer->flags &= ~(uint32_t)ZPP_LEXER_PP;
        goto read_token;
    }
    else if (ZPP_string_cmp3(&lexer->result, "include"))
    {
        lexer->flags |= ZPP_LEXER_INC;

        // TODO: better support macro headers
        ZPP_STATE_TRY_READ_FULL(state, error);

        lexer = &state->context->lexer;
        lexer->flags &= ~(uint32_t)ZPP_LEXER_INC;
        lexer->flags &= ~(uint32_t)ZPP_LEXER_PP;
        if ((state->result.flags & ZPP_TOKEN_STR) != 0)
        {
            if (state->result.pos.ptr[0] == 'L')
            {
                return ZPP_return_error(&state->result.pos, error,
                                        "expected a non wide string");
            }

            if ((ec = ZPP_handle_include(state, error, true,
                                         (ZPP_String) {
                                             .len = state->result.len - 2,
                                             .ptr = state->result.pos.ptr + 1,
                                         })) < 0)
            {
                return ec;
            }           
        }
        else if ((state->result.flags & ZPP_TOKEN_INC) != 0)
        {
            if ((ec = ZPP_handle_include(state, error, false,
                                         (ZPP_String) {
                                             .len = state->result.len - 2,
                                             .ptr = state->result.pos.ptr + 1,
                                         })) < 0)
            {
                return ec;
            }               
        }
        else
        {
            return
                ZPP_return_error(&state->result.pos, error,
                                 ZPP_ERROR_UNEXPECTED_TOK);
        }
        
        goto read_token;
    }
    else if (ZPP_string_cmp3(&lexer->result, "ifdef"))
    {
        lexer->is_else_off = false;
        ZPP_DIRECTIVE_TRY_READ(lexer, error);
        
        if ((lexer->result.flags & ZPP_TOKEN_IDENT) == 0)
        {
            return ZPP_return_error(&lexer->result.pos, error,
                                    ZPP_ERROR_UNEXPECTED_TOK);
        }
        
        ZPP_lexer_bpush(lexer, ZPP_is_defined(state, &lexer->result));
        lexer->flags &= ~(uint32_t)ZPP_LEXER_PP;
        goto read_token;
    }
    else if (ZPP_string_cmp3(&lexer->result, "ifndef"))
    {
        lexer->is_else_off = false;
        ZPP_DIRECTIVE_TRY_READ(lexer, error);
        
        if ((lexer->result.flags & ZPP_TOKEN_IDENT) == 0)
        {
            return ZPP_return_error(&lexer->result.pos, error,
                                    ZPP_ERROR_UNEXPECTED_TOK);
        }
        
        ZPP_lexer_bpush(lexer, !ZPP_is_defined(state, &lexer->result));
        lexer->flags &= ~(uint32_t)ZPP_LEXER_PP;
        goto read_token;
    }
    else if (ZPP_string_cmp3(&lexer->result, "if"))
    {
        lexer->is_else_off = false;
        
        // make it so that macros can't escape this line
        state->context->base.flags |= ZPP_CONTEXT_LOCK;

        ZPP_PPNum value; 
        if ((ec = ZPP_handle_if_pp(state, error,
                                   &value, 0, 0)) < 0)
        {
            return ec;
        }
        lexer = &state->context->lexer;
        state->context->base.flags &= ~(uint32_t)ZPP_CONTEXT_LOCK;
        
        ZPP_lexer_bpush(lexer, value.val != 0);
        lexer->flags &= ~(uint32_t)ZPP_LEXER_PP;
        goto read_token;
    }
    else if (ZPP_string_cmp3(&lexer->result, "pragma"))
    {
        bool not_found = false;
        if ((ec = ZPP_handle_pragma(state, error,
                                    &not_found)) < 0)
        {
            return ec;
        }
        lexer = &state->context->lexer;

        if (not_found)
        {
            *lexer = old_lex;
            state->result = lexer->result;
            return 1;
        }
        
        lexer->flags &= ~(uint32_t)ZPP_LEXER_PP;
        goto read_token;
    }
    else if (blevel == -1)
    {
        // TODO: produce errors for #endif, #else, etc. here 
        *lexer = old_lex;
        return 1;
    }

pp_level0:;
    if (ZPP_string_cmp3(&lexer->result, "endif"))
    {
        ZPP_lexer_bpop(lexer);
    }
    else if (ZPP_string_cmp3(&lexer->result, "else"))
    {
        if (ZPP_lexer_belse(lexer))
        {
            // TODO: come with better error message/code
            return ZPP_return_error(&lexer->result.pos, error,
                                    ZPP_ERROR_UNEXPECTED_TOK);
        }
    }
    else if (ZPP_string_cmp3(&lexer->result, "elif"))
    {
        if (ZPP_lexer_btope(lexer))
        {
            // TODO: make better error
            return ZPP_return_error(&lexer->result.pos, error,
                                    ZPP_ERROR_UNEXPECTED_TOK);
        }

        ZPP_lexer_bpop(lexer);
        if (ZPP_lexer_btop(state->context) == 0)
        {
            ZPP_lexer_bpush(lexer, false);
            lexer->flags &= ~(uint32_t)ZPP_LEXER_PP;
            goto read_token;
        }
        
        lexer->is_else_off |= blevel > 0;
        if (lexer->is_else_off)
        {
            ZPP_lexer_bpush(lexer, false);
        }
        else
        {
            // make it so that macros can't escape this line
            state->context->base.flags |= ZPP_CONTEXT_LOCK;
            
            ZPP_PPNum value; 
            if ((ec = ZPP_handle_if_pp(state, error,
                                       &value, 0, 0)) < 0)
            {
                return ec;
            }
            lexer = &state->context->lexer;
            
            state->context->base.flags &= ~(uint32_t)ZPP_CONTEXT_LOCK;
            ZPP_lexer_bpush(lexer, value.val != 0);
        }
    }        
    else if (blevel == 0)
    {
        if ((ZPP_string_cmp3(&lexer->result, "if") ||
             ZPP_string_cmp3(&lexer->result, "ifdef") ||
             ZPP_string_cmp3(&lexer->result, "ifndef")))
        {
            ZPP_lexer_bpush(lexer, false);
        }
    }
    else
    {
        *lexer = old_lex;
        return 1;
    }
    
    lexer->flags &= ~(uint32_t)ZPP_LEXER_PP;
    goto read_token;
#undef ZPP_DIRECTIVE_TRY_READ
}

#undef ZPP_ALEN
#undef ZPP_ARRAY
#undef ZPP_ARRAY_MEM
#undef ZPP_ARRAY_NEW1
#undef ZPP_ARRAY_NEW2
#undef ZPP_ARRAY_NEW3
#undef ZPP_ARRAY_FREE
#undef ZPP_ARRAY_GROW
#undef ZPP_LEXER_TRY_READ
#undef ZPP_DIRECTIVE_READ
#undef ZPP_ERROR_INVALID_MACRO
#undef ZPP_ERROR_INVALID_PASTE
#undef ZPP_LEXER_TRY_READ_FULL
#undef ZPP_ERROR_UNEXPECTED_TOK
#undef ZPP_ERROR_UNEXPECTED_EOF

#endif // ZPP_DEFINE
#endif // ZPP_ZPP_H
