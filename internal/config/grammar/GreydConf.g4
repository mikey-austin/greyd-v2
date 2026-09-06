/*
 * Copyright (c) 2014-2026 Mikey Austin <mikey@greyd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * The greyd.conf(5) configuration language.
 *
 *   # A string value.
 *   variable = "value"
 *
 *   # A number value.
 *   variable = 10  # Another comment.
 *
 *   # A list value may contain strings or numbers.
 *   variable = [ 10, "value", ]
 *
 *   section sectionname {
 *       var1 = "val1"
 *       var2 = 10
 *   }
 *
 *   blacklist name { ... }
 *   whitelist name { ... }
 *
 *   include "/etc/greyd/conf.d/*.conf"
 *
 * Statements are terminated by a newline or ';'. Assignments inside a
 * section may additionally be separated by commas. Keywords are case
 * insensitive and variable/section names are lowercased by the listener.
 */
grammar GreydConf;

config
    : EOL* (statement (EOL+ statement)*)? EOL* EOF
    ;

statement
    : assignment
    | section
    | include
    ;

assignment
    : NAME EQ value
    ;

value
    : INT       # intValue
    | STRING    # strValue
    | list      # listValue
    ;

list
    : LSQ EOL* (value (EOL* COMMA EOL* value)* EOL* COMMA? EOL*)? RSQ
    ;

section
    : sectionType NAME EOL* LBR EOL* (assignment (separator assignment)* separator?)? EOL* RBR
    ;

separator
    : (COMMA | EOL)+
    ;

sectionType
    : SECTION
    | BLACKLIST
    | WHITELIST
    ;

include
    : INCLUDE STRING
    ;

SECTION   : S E C T I O N ;
INCLUDE   : I N C L U D E ;
BLACKLIST : B L A C K L I S T ;
WHITELIST : W H I T E L I S T ;

NAME      : [A-Za-z] [A-Za-z0-9_]* ;
INT       : [0-9]+ ;

// Strings may span lines. A backslash escapes the following character; the
// listener removes the backslash and keeps the character, as the C lexer did.
STRING    : '"' ( '\\' . | ~["\\] )* '"' ;

EQ        : '=' ;
COMMA     : ',' ;
LBR       : '{' ;
RBR       : '}' ;
LSQ       : '[' ;
RSQ       : ']' ;

EOL       : '\n' | ';' ;
COMMENT   : '#' ~[\n]* -> skip ;
WS        : [ \t\r]+ -> skip ;

fragment A : [aA] ;
fragment B : [bB] ;
fragment C : [cC] ;
fragment D : [dD] ;
fragment E : [eE] ;
fragment H : [hH] ;
fragment I : [iI] ;
fragment K : [kK] ;
fragment L : [lL] ;
fragment N : [nN] ;
fragment O : [oO] ;
fragment S : [sS] ;
fragment T : [tT] ;
fragment U : [uU] ;
fragment W : [wW] ;
