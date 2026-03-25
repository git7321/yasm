#ifndef YASM_BITVECT_H
#define YASM_BITVECT_H
/*****************************************************************************/
/*  MODULE NAME:  BitVector.h                           MODULE TYPE:  (adt)  */
/*****************************************************************************/
/*  MODULE IMPORTS:                                                          */
/*****************************************************************************/

/* ToolBox.h */
/*****************************************************************************/
/*  NOTE: The type names that have been chosen here are somewhat weird on    */
/*        purpose, in order to avoid name clashes with system header files   */
/*        and your own application(s) which might - directly or indirectly - */
/*        include this definitions file.                                     */
/*****************************************************************************/
#ifndef YASM_LIB_DECL
#define YASM_LIB_DECL
#endif

typedef  unsigned   char    N_char;
typedef  unsigned   char    N_byte;
typedef  unsigned   short   N_short;
typedef  unsigned   short   N_shortword;
typedef  unsigned   int     N_int;
typedef  unsigned   int     N_word;
typedef  unsigned   long    N_long;
typedef  unsigned   long    N_longword;

/*  Mnemonic 1:  The natural numbers,  N = { 0, 1, 2, 3, ... }               */
/*  Mnemonic 2:  Nnnn = u_N_signed,  _N_ot signed                            */

typedef  signed     char    Z_char;
typedef  signed     char    Z_byte;
typedef  signed     short   Z_short;
typedef  signed     short   Z_shortword;
typedef  signed     int     Z_int;
typedef  signed     int     Z_word;
typedef  signed     long    Z_long;
typedef  signed     long    Z_longword;

/*  Mnemonic 1:  The whole numbers,  Z = { 0, -1, 1, -2, 2, -3, 3, ... }     */
/*  Mnemonic 2:  Zzzz = Ssss_igned                                           */

typedef  void               *voidptr;
typedef  N_char             *charptr;
typedef  N_byte             *byteptr;
typedef  N_short            *shortptr;
typedef  N_shortword        *shortwordptr;
typedef  N_int              *intptr;
typedef  N_word             *wordptr;
typedef  N_long             *longptr;
typedef  N_longword         *longwordptr;

typedef  N_char             *N_charptr;
typedef  N_byte             *N_byteptr;
typedef  N_short            *N_shortptr;
typedef  N_shortword        *N_shortwordptr;
typedef  N_int              *N_intptr;
typedef  N_word             *N_wordptr;
typedef  N_long             *N_longptr;
typedef  N_longword         *N_longwordptr;

typedef  Z_char             *Z_charptr;
typedef  Z_byte             *Z_byteptr;
typedef  Z_short            *Z_shortptr;
typedef  Z_shortword        *Z_shortwordptr;
typedef  Z_int              *Z_intptr;
typedef  Z_word             *Z_wordptr;
typedef  Z_long             *Z_longptr;
typedef  Z_longword         *Z_longwordptr;

#ifndef FALSE
#define FALSE       (0!=0)
#endif

#ifndef TRUE
#define TRUE        (0==0)
#endif

#ifdef __cplusplus
    typedef bool boolean;
#else
    #ifdef MACOS_TRADITIONAL
        #define boolean Boolean
    #else
        typedef enum boolean { false = FALSE, true = TRUE } boolean;
    #endif
#endif

/*****************************************************************************/
/*  MODULE INTERFACE:                                                        */
/*****************************************************************************/

typedef enum ErrCode
    {
        ErrCode_Ok = 0,    /* everything went allright                       */

        ErrCode_Type,      /* types word and size_t have incompatible sizes  */
        ErrCode_Bits,      /* bits of word and sizeof(word) are inconsistent */
        ErrCode_Word,      /* size of word is less than 16 bits              */
        ErrCode_Long,      /* size of word is greater than size of long      */
        ErrCode_Powr,      /* number of bits of word is not a power of two   */
        ErrCode_Loga,      /* error in calculation of logarithm              */

        ErrCode_Null,      /* unable to allocate memory                      */

        ErrCode_Indx,      /* index out of range                             */
        ErrCode_Ordr,      /* minimum > maximum index                        */
        ErrCode_Size,      /* bit vector size mismatch                       */
        ErrCode_Pars,      /* input string syntax error                      */
        ErrCode_Ovfl,      /* numeric overflow error                         */
        ErrCode_Same,      /* operands must be distinct                      */
        ErrCode_Expo,      /* exponent must be positive                      */
        ErrCode_Zero       /* division by zero error                         */
    } ErrCode;

typedef wordptr *listptr;

/* ===> MISCELLANEOUS BASIC FUNCTIONS: <=== */

YASM_LIB_DECL
const char * BitVector_Error      (ErrCode error);  /* return string for err code */

YASM_LIB_DECL
ErrCode BitVector_Boot       (void);                 /* 0 = ok, 1..7 = error */
YASM_LIB_DECL
void    BitVector_Shutdown   (void);                            /* undo Boot */

YASM_LIB_DECL
N_word  BitVector_Size       (N_int bits);  /* bit vector size (# of words)  */
YASM_LIB_DECL
N_word  BitVector_Mask       (N_int bits);  /* bit vector mask (unused bits) */

/* ===> CLASS METHODS: <=== */

YASM_LIB_DECL
const char * BitVector_Version    (void);          /* returns version string */

YASM_LIB_DECL
N_int   BitVector_Word_Bits  (void);     /* return # of bits in machine word */
YASM_LIB_DECL
N_int   BitVector_Long_Bits  (void);    /* return # of bits in unsigned long */

/* ===> CONSTRUCTOR METHODS: <=== */

YASM_LIB_DECL
/*@only@*/ wordptr BitVector_Create     (N_int bits, boolean clear);          /* malloc */
YASM_LIB_DECL
listptr BitVector_Create_List(N_int bits, boolean clear, N_int count);

YASM_LIB_DECL
wordptr BitVector_Resize     (wordptr oldaddr, N_int bits);       /* realloc */

YASM_LIB_DECL
wordptr BitVector_Shadow     (wordptr addr); /* make new same size but empty */
YASM_LIB_DECL
wordptr BitVector_Clone      (wordptr addr);         /* make exact duplicate */

YASM_LIB_DECL
wordptr BitVector_Concat     (wordptr X, wordptr Y); /* return concatenation */

/* ===> DESTRUCTOR METHODS: <=== */

YASM_LIB_DECL
void    BitVector_Dispose            (/*@only@*/ /*@out@*/ charptr string);             /* string */
YASM_LIB_DECL
void    BitVector_Destroy            (/*@only@*/ wordptr addr);               /* bitvec */
YASM_LIB_DECL
void    BitVector_Destroy_List       (listptr list, N_int count);  /* list   */

/* ===> OBJECT METHODS: <=== */

/* ===> bit vector copy function: */

YASM_LIB_DECL
void    BitVector_Copy       (wordptr X, wordptr Y);              /* X = Y   */

/* ===> bit vector initialization: */

YASM_LIB_DECL
void    BitVector_Empty      (wordptr addr);                      /* X = {}  */
YASM_LIB_DECL
void    BitVector_Fill       (wordptr addr);                      /* X = ~{} */
YASM_LIB_DECL
void    BitVector_Flip       (wordptr addr);                      /* X = ~X  */

YASM_LIB_DECL
void    BitVector_Primes     (wordptr addr);

/* ===> miscellaneous functions: */

YASM_LIB_DECL
void    BitVector_Reverse    (wordptr X, wordptr Y);

/* ===> bit vector interval operations and functions: */

YASM_LIB_DECL
void    BitVector_Interval_Empty     (/*@out@*/ wordptr addr, N_int lower, N_int upper);
YASM_LIB_DECL
void    BitVector_Interval_Fill      (/*@out@*/ wordptr addr, N_int lower, N_int upper);
YASM_LIB_DECL
void    BitVector_Interval_Flip      (/*@out@*/ wordptr addr, N_int lower, N_int upper);
YASM_LIB_DECL
void    BitVector_Interval_Reverse   (/*@out@*/ wordptr addr, N_int lower, N_int upper);

YASM_LIB_DECL
boolean BitVector_interval_scan_inc  (wordptr addr, N_int start,
                                      N_intptr min, N_intptr max);
YASM_LIB_DECL
boolean BitVector_interval_scan_dec  (wordptr addr, N_int start,
                                      N_intptr min, N_intptr max);

YASM_LIB_DECL
void    BitVector_Interval_Copy      (/*@out@*/ wordptr X, wordptr Y, N_int Xoffset,
                                      N_int Yoffset, N_int length);

YASM_LIB_DECL
wordptr BitVector_Interval_Substitute(/*@out@*/ wordptr X, wordptr Y,
                                      N_int Xoffset, N_int Xlength,
                                      N_int Yoffset, N_int Ylength);

/* ===> bit vector test functions: */

YASM_LIB_DECL
boolean BitVector_is_empty   (wordptr addr);                  /* X == {} ?   */
YASM_LIB_DECL
boolean BitVector_is_full    (wordptr addr);                  /* X == ~{} ?  */

YASM_LIB_DECL
boolean BitVector_equal      (wordptr X, wordptr Y);          /* X == Y ?    */
YASM_LIB_DECL
Z_int   BitVector_Lexicompare(wordptr X, wordptr Y);          /* X <,=,> Y ? */
YASM_LIB_DECL
Z_int   BitVector_Compare    (wordptr X, wordptr Y);          /* X <,=,> Y ? */

/* ===> bit vector string conversion functions: */

YASM_LIB_DECL
/*@only@*/ charptr BitVector_to_Hex     (wordptr addr);
YASM_LIB_DECL
ErrCode BitVector_from_Hex   (/*@out@*/wordptr addr, charptr string);

YASM_LIB_DECL
ErrCode BitVector_from_Oct(/*@out@*/ wordptr addr, charptr string);

YASM_LIB_DECL
/*@only@*/ charptr BitVector_to_Bin     (wordptr addr);
YASM_LIB_DECL
ErrCode BitVector_from_Bin   (/*@out@*/ wordptr addr, charptr string);

YASM_LIB_DECL
/*@only@*/ charptr BitVector_to_Dec     (wordptr addr);
YASM_LIB_DECL
ErrCode BitVector_from_Dec   (/*@out@*/ wordptr addr, charptr string);

typedef struct BitVector_from_Dec_static_data BitVector_from_Dec_static_data;
YASM_LIB_DECL
BitVector_from_Dec_static_data *BitVector_from_Dec_static_Boot(N_word bits);
YASM_LIB_DECL
void BitVector_from_Dec_static_Shutdown(/*@null@*/ BitVector_from_Dec_static_data *data);
YASM_LIB_DECL
ErrCode BitVector_from_Dec_static(BitVector_from_Dec_static_data *data,
                                  /*@out@*/ wordptr addr, charptr string);

YASM_LIB_DECL
/*@only@*/ charptr BitVector_to_Enum    (wordptr addr);
YASM_LIB_DECL
ErrCode BitVector_from_Enum  (/*@out@*/ wordptr addr, charptr string);

/* ===> bit vector bit operations, functions & tests: */

YASM_LIB_DECL
void    BitVector_Bit_Off    (/*@out@*/ wordptr addr, N_int indx); /*  X = X \ {x}    */
YASM_LIB_DECL
void    BitVector_Bit_On     (/*@out@*/ wordptr addr, N_int indx); /*  X = X + {x}    */
YASM_LIB_DECL
boolean BitVector_bit_flip   (/*@out@*/ wordptr addr, N_int indx); /* (X+{x})\(X*{x}) */

YASM_LIB_DECL
boolean BitVector_bit_test   (wordptr addr, N_int indx); /*  {x} in X ?     */

YASM_LIB_DECL
void    BitVector_Bit_Copy   (/*@out@*/ wordptr addr, N_int indx, boolean bit);

/* ===> bit vector bit shift & rotate functions: */

YASM_LIB_DECL
void    BitVector_LSB                (/*@out@*/ wordptr addr, boolean bit);
YASM_LIB_DECL
void    BitVector_MSB                (/*@out@*/ wordptr addr, boolean bit);
YASM_LIB_DECL
boolean BitVector_lsb_               (wordptr addr);
YASM_LIB_DECL
boolean BitVector_msb_               (wordptr addr);
YASM_LIB_DECL
boolean /*@alt void@*/ BitVector_rotate_left        (wordptr addr);
YASM_LIB_DECL
boolean /*@alt void@*/ BitVector_rotate_right       (wordptr addr);
YASM_LIB_DECL
boolean /*@alt void@*/ BitVector_shift_left         (wordptr addr, boolean carry_in);
YASM_LIB_DECL
boolean /*@alt void@*/ BitVector_shift_right        (wordptr addr, boolean carry_in);
YASM_LIB_DECL
void    BitVector_Move_Left          (wordptr addr, N_int bits);
YASM_LIB_DECL
void    BitVector_Move_Right         (wordptr addr, N_int bits);

/* ===> bit vector insert/delete bits: */

YASM_LIB_DECL
void    BitVector_Insert     (wordptr addr, N_int offset, N_int count,
                              boolean clear);
YASM_LIB_DECL
void    BitVector_Delete     (wordptr addr, N_int offset, N_int count,
                              boolean clear);

/* ===> bit vector arithmetic: */

YASM_LIB_DECL
boolean /*@alt void@*/ BitVector_increment  (wordptr addr);                        /*  X++  */
YASM_LIB_DECL
boolean /*@alt void@*/ BitVector_decrement  (wordptr addr);                        /*  X--  */

YASM_LIB_DECL
boolean /*@alt void@*/ BitVector_compute    (wordptr X, wordptr Y, wordptr Z, boolean minus,
                                                               boolean *carry);
YASM_LIB_DECL
boolean /*@alt void@*/ BitVector_add        (wordptr X, wordptr Y, wordptr Z, boolean *carry);
YASM_LIB_DECL
boolean /*@alt void@*/ BitVector_sub        (wordptr X, wordptr Y, wordptr Z, boolean *carry);
YASM_LIB_DECL
boolean /*@alt void@*/ BitVector_inc        (wordptr X, wordptr Y);
YASM_LIB_DECL
boolean /*@alt void@*/ BitVector_dec        (wordptr X, wordptr Y);

YASM_LIB_DECL
void    BitVector_Negate     (wordptr X, wordptr Y);
YASM_LIB_DECL
void    BitVector_Absolute   (wordptr X, wordptr Y);
YASM_LIB_DECL
Z_int   BitVector_Sign       (wordptr addr);
YASM_LIB_DECL
ErrCode BitVector_Mul_Pos    (wordptr X, wordptr Y, wordptr Z, boolean strict);
YASM_LIB_DECL
ErrCode BitVector_Multiply   (wordptr X, wordptr Y, wordptr Z);
YASM_LIB_DECL
ErrCode BitVector_Div_Pos    (wordptr Q, wordptr X, wordptr Y, wordptr R);
YASM_LIB_DECL
ErrCode BitVector_Divide     (wordptr Q, wordptr X, wordptr Y, wordptr R);
YASM_LIB_DECL
ErrCode BitVector_GCD        (wordptr X, wordptr Y, wordptr Z);
YASM_LIB_DECL
ErrCode BitVector_GCD2       (wordptr U, wordptr V, wordptr W,      /*   O   */
                                         wordptr X, wordptr Y);     /*   I   */
YASM_LIB_DECL
ErrCode BitVector_Power      (wordptr X, wordptr Y, wordptr Z);

/* ===> direct memory access functions: */

YASM_LIB_DECL
void    BitVector_Block_Store(wordptr addr, charptr buffer, N_int length);
YASM_LIB_DECL
charptr BitVector_Block_Read (wordptr addr, /*@out@*/ N_intptr length);

/* ===> word array functions: */

YASM_LIB_DECL
void    BitVector_Word_Store (wordptr addr, N_int offset, N_int value);
YASM_LIB_DECL
N_int   BitVector_Word_Read  (wordptr addr, N_int offset);

YASM_LIB_DECL
void    BitVector_Word_Insert(wordptr addr, N_int offset, N_int count,
                              boolean clear);
YASM_LIB_DECL
void    BitVector_Word_Delete(wordptr addr, N_int offset, N_int count,
                              boolean clear);

/* ===> arbitrary size chunk functions: */

YASM_LIB_DECL
void    BitVector_Chunk_Store(wordptr addr, N_int chunksize,
                              N_int offset, N_long value);
YASM_LIB_DECL
N_long  BitVector_Chunk_Read (wordptr addr, N_int chunksize,
                              N_int offset);

/* ===> set operations: */

YASM_LIB_DECL
void    Set_Union            (wordptr X, wordptr Y, wordptr Z); /* X = Y + Z */
YASM_LIB_DECL
void    Set_Intersection     (wordptr X, wordptr Y, wordptr Z); /* X = Y * Z */
YASM_LIB_DECL
void    Set_Difference       (wordptr X, wordptr Y, wordptr Z); /* X = Y \ Z */
YASM_LIB_DECL
void    Set_ExclusiveOr      (wordptr X, wordptr Y, wordptr Z); /*(Y+Z)\(Y*Z)*/
YASM_LIB_DECL
void    Set_Complement       (wordptr X, wordptr Y);            /* X = ~Y    */

/* ===> set functions: */

YASM_LIB_DECL
boolean Set_subset           (wordptr X, wordptr Y);            /* X in Y ?  */

YASM_LIB_DECL
N_int   Set_Norm             (wordptr addr);                    /* = | X |   */
YASM_LIB_DECL
N_int   Set_Norm2            (wordptr addr);                    /* = | X |   */
YASM_LIB_DECL
N_int   Set_Norm3            (wordptr addr);                    /* = | X |   */
YASM_LIB_DECL
Z_long  Set_Min              (wordptr addr);                    /* = min(X)  */
YASM_LIB_DECL
Z_long  Set_Max              (wordptr addr);                    /* = max(X)  */

/* ===> matrix-of-booleans operations: */

YASM_LIB_DECL
void    Matrix_Multiplication(wordptr X, N_int rowsX, N_int colsX,
                              wordptr Y, N_int rowsY, N_int colsY,
                              wordptr Z, N_int rowsZ, N_int colsZ);

YASM_LIB_DECL
void    Matrix_Product       (wordptr X, N_int rowsX, N_int colsX,
                              wordptr Y, N_int rowsY, N_int colsY,
                              wordptr Z, N_int rowsZ, N_int colsZ);

YASM_LIB_DECL
void    Matrix_Closure       (wordptr addr, N_int rows, N_int cols);

YASM_LIB_DECL
void    Matrix_Transpose     (wordptr X, N_int rowsX, N_int colsX,
                              wordptr Y, N_int rowsY, N_int colsY);

#endif
