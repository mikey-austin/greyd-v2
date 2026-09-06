// Code generated from internal/config/grammar/GreydConf.g4 by ANTLR 4.13.1. DO NOT EDIT.

package grammar

import (
	"fmt"
	"github.com/antlr4-go/antlr/v4"
	"sync"
	"unicode"
)

// Suppress unused import error
var _ = fmt.Printf
var _ = sync.Once{}
var _ = unicode.IsLetter

type GreydConfLexer struct {
	*antlr.BaseLexer
	channelNames []string
	modeNames    []string
	// TODO: EOF string
}

var GreydConfLexerLexerStaticData struct {
	once                   sync.Once
	serializedATN          []int32
	ChannelNames           []string
	ModeNames              []string
	LiteralNames           []string
	SymbolicNames          []string
	RuleNames              []string
	PredictionContextCache *antlr.PredictionContextCache
	atn                    *antlr.ATN
	decisionToDFA          []*antlr.DFA
}

func greydconflexerLexerInit() {
	staticData := &GreydConfLexerLexerStaticData
	staticData.ChannelNames = []string{
		"DEFAULT_TOKEN_CHANNEL", "HIDDEN",
	}
	staticData.ModeNames = []string{
		"DEFAULT_MODE",
	}
	staticData.LiteralNames = []string{
		"", "", "", "", "", "", "", "", "'='", "','", "'{'", "'}'", "'['", "']'",
	}
	staticData.SymbolicNames = []string{
		"", "SECTION", "INCLUDE", "BLACKLIST", "WHITELIST", "NAME", "INT", "STRING",
		"EQ", "COMMA", "LBR", "RBR", "LSQ", "RSQ", "EOL", "COMMENT", "WS",
	}
	staticData.RuleNames = []string{
		"SECTION", "INCLUDE", "BLACKLIST", "WHITELIST", "NAME", "INT", "STRING",
		"EQ", "COMMA", "LBR", "RBR", "LSQ", "RSQ", "EOL", "COMMENT", "WS", "A",
		"B", "C", "D", "E", "H", "I", "K", "L", "N", "O", "S", "T", "U", "W",
	}
	staticData.PredictionContextCache = antlr.NewPredictionContextCache()
	staticData.serializedATN = []int32{
		4, 0, 16, 182, 6, -1, 2, 0, 7, 0, 2, 1, 7, 1, 2, 2, 7, 2, 2, 3, 7, 3, 2,
		4, 7, 4, 2, 5, 7, 5, 2, 6, 7, 6, 2, 7, 7, 7, 2, 8, 7, 8, 2, 9, 7, 9, 2,
		10, 7, 10, 2, 11, 7, 11, 2, 12, 7, 12, 2, 13, 7, 13, 2, 14, 7, 14, 2, 15,
		7, 15, 2, 16, 7, 16, 2, 17, 7, 17, 2, 18, 7, 18, 2, 19, 7, 19, 2, 20, 7,
		20, 2, 21, 7, 21, 2, 22, 7, 22, 2, 23, 7, 23, 2, 24, 7, 24, 2, 25, 7, 25,
		2, 26, 7, 26, 2, 27, 7, 27, 2, 28, 7, 28, 2, 29, 7, 29, 2, 30, 7, 30, 1,
		0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1, 2, 1,
		2, 1, 2, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1, 3, 1,
		4, 1, 4, 5, 4, 102, 8, 4, 10, 4, 12, 4, 105, 9, 4, 1, 5, 4, 5, 108, 8,
		5, 11, 5, 12, 5, 109, 1, 6, 1, 6, 1, 6, 1, 6, 5, 6, 116, 8, 6, 10, 6, 12,
		6, 119, 9, 6, 1, 6, 1, 6, 1, 7, 1, 7, 1, 8, 1, 8, 1, 9, 1, 9, 1, 10, 1,
		10, 1, 11, 1, 11, 1, 12, 1, 12, 1, 13, 1, 13, 1, 14, 1, 14, 5, 14, 139,
		8, 14, 10, 14, 12, 14, 142, 9, 14, 1, 14, 1, 14, 1, 15, 4, 15, 147, 8,
		15, 11, 15, 12, 15, 148, 1, 15, 1, 15, 1, 16, 1, 16, 1, 17, 1, 17, 1, 18,
		1, 18, 1, 19, 1, 19, 1, 20, 1, 20, 1, 21, 1, 21, 1, 22, 1, 22, 1, 23, 1,
		23, 1, 24, 1, 24, 1, 25, 1, 25, 1, 26, 1, 26, 1, 27, 1, 27, 1, 28, 1, 28,
		1, 29, 1, 29, 1, 30, 1, 30, 0, 0, 31, 1, 1, 3, 2, 5, 3, 7, 4, 9, 5, 11,
		6, 13, 7, 15, 8, 17, 9, 19, 10, 21, 11, 23, 12, 25, 13, 27, 14, 29, 15,
		31, 16, 33, 0, 35, 0, 37, 0, 39, 0, 41, 0, 43, 0, 45, 0, 47, 0, 49, 0,
		51, 0, 53, 0, 55, 0, 57, 0, 59, 0, 61, 0, 1, 0, 22, 2, 0, 65, 90, 97, 122,
		4, 0, 48, 57, 65, 90, 95, 95, 97, 122, 1, 0, 48, 57, 2, 0, 34, 34, 92,
		92, 2, 0, 10, 10, 59, 59, 1, 0, 10, 10, 3, 0, 9, 9, 13, 13, 32, 32, 2,
		0, 65, 65, 97, 97, 2, 0, 66, 66, 98, 98, 2, 0, 67, 67, 99, 99, 2, 0, 68,
		68, 100, 100, 2, 0, 69, 69, 101, 101, 2, 0, 72, 72, 104, 104, 2, 0, 73,
		73, 105, 105, 2, 0, 75, 75, 107, 107, 2, 0, 76, 76, 108, 108, 2, 0, 78,
		78, 110, 110, 2, 0, 79, 79, 111, 111, 2, 0, 83, 83, 115, 115, 2, 0, 84,
		84, 116, 116, 2, 0, 85, 85, 117, 117, 2, 0, 87, 87, 119, 119, 172, 0, 1,
		1, 0, 0, 0, 0, 3, 1, 0, 0, 0, 0, 5, 1, 0, 0, 0, 0, 7, 1, 0, 0, 0, 0, 9,
		1, 0, 0, 0, 0, 11, 1, 0, 0, 0, 0, 13, 1, 0, 0, 0, 0, 15, 1, 0, 0, 0, 0,
		17, 1, 0, 0, 0, 0, 19, 1, 0, 0, 0, 0, 21, 1, 0, 0, 0, 0, 23, 1, 0, 0, 0,
		0, 25, 1, 0, 0, 0, 0, 27, 1, 0, 0, 0, 0, 29, 1, 0, 0, 0, 0, 31, 1, 0, 0,
		0, 1, 63, 1, 0, 0, 0, 3, 71, 1, 0, 0, 0, 5, 79, 1, 0, 0, 0, 7, 89, 1, 0,
		0, 0, 9, 99, 1, 0, 0, 0, 11, 107, 1, 0, 0, 0, 13, 111, 1, 0, 0, 0, 15,
		122, 1, 0, 0, 0, 17, 124, 1, 0, 0, 0, 19, 126, 1, 0, 0, 0, 21, 128, 1,
		0, 0, 0, 23, 130, 1, 0, 0, 0, 25, 132, 1, 0, 0, 0, 27, 134, 1, 0, 0, 0,
		29, 136, 1, 0, 0, 0, 31, 146, 1, 0, 0, 0, 33, 152, 1, 0, 0, 0, 35, 154,
		1, 0, 0, 0, 37, 156, 1, 0, 0, 0, 39, 158, 1, 0, 0, 0, 41, 160, 1, 0, 0,
		0, 43, 162, 1, 0, 0, 0, 45, 164, 1, 0, 0, 0, 47, 166, 1, 0, 0, 0, 49, 168,
		1, 0, 0, 0, 51, 170, 1, 0, 0, 0, 53, 172, 1, 0, 0, 0, 55, 174, 1, 0, 0,
		0, 57, 176, 1, 0, 0, 0, 59, 178, 1, 0, 0, 0, 61, 180, 1, 0, 0, 0, 63, 64,
		3, 55, 27, 0, 64, 65, 3, 41, 20, 0, 65, 66, 3, 37, 18, 0, 66, 67, 3, 57,
		28, 0, 67, 68, 3, 45, 22, 0, 68, 69, 3, 53, 26, 0, 69, 70, 3, 51, 25, 0,
		70, 2, 1, 0, 0, 0, 71, 72, 3, 45, 22, 0, 72, 73, 3, 51, 25, 0, 73, 74,
		3, 37, 18, 0, 74, 75, 3, 49, 24, 0, 75, 76, 3, 59, 29, 0, 76, 77, 3, 39,
		19, 0, 77, 78, 3, 41, 20, 0, 78, 4, 1, 0, 0, 0, 79, 80, 3, 35, 17, 0, 80,
		81, 3, 49, 24, 0, 81, 82, 3, 33, 16, 0, 82, 83, 3, 37, 18, 0, 83, 84, 3,
		47, 23, 0, 84, 85, 3, 49, 24, 0, 85, 86, 3, 45, 22, 0, 86, 87, 3, 55, 27,
		0, 87, 88, 3, 57, 28, 0, 88, 6, 1, 0, 0, 0, 89, 90, 3, 61, 30, 0, 90, 91,
		3, 43, 21, 0, 91, 92, 3, 45, 22, 0, 92, 93, 3, 57, 28, 0, 93, 94, 3, 41,
		20, 0, 94, 95, 3, 49, 24, 0, 95, 96, 3, 45, 22, 0, 96, 97, 3, 55, 27, 0,
		97, 98, 3, 57, 28, 0, 98, 8, 1, 0, 0, 0, 99, 103, 7, 0, 0, 0, 100, 102,
		7, 1, 0, 0, 101, 100, 1, 0, 0, 0, 102, 105, 1, 0, 0, 0, 103, 101, 1, 0,
		0, 0, 103, 104, 1, 0, 0, 0, 104, 10, 1, 0, 0, 0, 105, 103, 1, 0, 0, 0,
		106, 108, 7, 2, 0, 0, 107, 106, 1, 0, 0, 0, 108, 109, 1, 0, 0, 0, 109,
		107, 1, 0, 0, 0, 109, 110, 1, 0, 0, 0, 110, 12, 1, 0, 0, 0, 111, 117, 5,
		34, 0, 0, 112, 113, 5, 92, 0, 0, 113, 116, 9, 0, 0, 0, 114, 116, 8, 3,
		0, 0, 115, 112, 1, 0, 0, 0, 115, 114, 1, 0, 0, 0, 116, 119, 1, 0, 0, 0,
		117, 115, 1, 0, 0, 0, 117, 118, 1, 0, 0, 0, 118, 120, 1, 0, 0, 0, 119,
		117, 1, 0, 0, 0, 120, 121, 5, 34, 0, 0, 121, 14, 1, 0, 0, 0, 122, 123,
		5, 61, 0, 0, 123, 16, 1, 0, 0, 0, 124, 125, 5, 44, 0, 0, 125, 18, 1, 0,
		0, 0, 126, 127, 5, 123, 0, 0, 127, 20, 1, 0, 0, 0, 128, 129, 5, 125, 0,
		0, 129, 22, 1, 0, 0, 0, 130, 131, 5, 91, 0, 0, 131, 24, 1, 0, 0, 0, 132,
		133, 5, 93, 0, 0, 133, 26, 1, 0, 0, 0, 134, 135, 7, 4, 0, 0, 135, 28, 1,
		0, 0, 0, 136, 140, 5, 35, 0, 0, 137, 139, 8, 5, 0, 0, 138, 137, 1, 0, 0,
		0, 139, 142, 1, 0, 0, 0, 140, 138, 1, 0, 0, 0, 140, 141, 1, 0, 0, 0, 141,
		143, 1, 0, 0, 0, 142, 140, 1, 0, 0, 0, 143, 144, 6, 14, 0, 0, 144, 30,
		1, 0, 0, 0, 145, 147, 7, 6, 0, 0, 146, 145, 1, 0, 0, 0, 147, 148, 1, 0,
		0, 0, 148, 146, 1, 0, 0, 0, 148, 149, 1, 0, 0, 0, 149, 150, 1, 0, 0, 0,
		150, 151, 6, 15, 0, 0, 151, 32, 1, 0, 0, 0, 152, 153, 7, 7, 0, 0, 153,
		34, 1, 0, 0, 0, 154, 155, 7, 8, 0, 0, 155, 36, 1, 0, 0, 0, 156, 157, 7,
		9, 0, 0, 157, 38, 1, 0, 0, 0, 158, 159, 7, 10, 0, 0, 159, 40, 1, 0, 0,
		0, 160, 161, 7, 11, 0, 0, 161, 42, 1, 0, 0, 0, 162, 163, 7, 12, 0, 0, 163,
		44, 1, 0, 0, 0, 164, 165, 7, 13, 0, 0, 165, 46, 1, 0, 0, 0, 166, 167, 7,
		14, 0, 0, 167, 48, 1, 0, 0, 0, 168, 169, 7, 15, 0, 0, 169, 50, 1, 0, 0,
		0, 170, 171, 7, 16, 0, 0, 171, 52, 1, 0, 0, 0, 172, 173, 7, 17, 0, 0, 173,
		54, 1, 0, 0, 0, 174, 175, 7, 18, 0, 0, 175, 56, 1, 0, 0, 0, 176, 177, 7,
		19, 0, 0, 177, 58, 1, 0, 0, 0, 178, 179, 7, 20, 0, 0, 179, 60, 1, 0, 0,
		0, 180, 181, 7, 21, 0, 0, 181, 62, 1, 0, 0, 0, 7, 0, 103, 109, 115, 117,
		140, 148, 1, 6, 0, 0,
	}
	deserializer := antlr.NewATNDeserializer(nil)
	staticData.atn = deserializer.Deserialize(staticData.serializedATN)
	atn := staticData.atn
	staticData.decisionToDFA = make([]*antlr.DFA, len(atn.DecisionToState))
	decisionToDFA := staticData.decisionToDFA
	for index, state := range atn.DecisionToState {
		decisionToDFA[index] = antlr.NewDFA(state, index)
	}
}

// GreydConfLexerInit initializes any static state used to implement GreydConfLexer. By default the
// static state used to implement the lexer is lazily initialized during the first call to
// NewGreydConfLexer(). You can call this function if you wish to initialize the static state ahead
// of time.
func GreydConfLexerInit() {
	staticData := &GreydConfLexerLexerStaticData
	staticData.once.Do(greydconflexerLexerInit)
}

// NewGreydConfLexer produces a new lexer instance for the optional input antlr.CharStream.
func NewGreydConfLexer(input antlr.CharStream) *GreydConfLexer {
	GreydConfLexerInit()
	l := new(GreydConfLexer)
	l.BaseLexer = antlr.NewBaseLexer(input)
	staticData := &GreydConfLexerLexerStaticData
	l.Interpreter = antlr.NewLexerATNSimulator(l, staticData.atn, staticData.decisionToDFA, staticData.PredictionContextCache)
	l.channelNames = staticData.ChannelNames
	l.modeNames = staticData.ModeNames
	l.RuleNames = staticData.RuleNames
	l.LiteralNames = staticData.LiteralNames
	l.SymbolicNames = staticData.SymbolicNames
	l.GrammarFileName = "GreydConf.g4"
	// TODO: l.EOF = antlr.TokenEOF

	return l
}

// GreydConfLexer tokens.
const (
	GreydConfLexerSECTION   = 1
	GreydConfLexerINCLUDE   = 2
	GreydConfLexerBLACKLIST = 3
	GreydConfLexerWHITELIST = 4
	GreydConfLexerNAME      = 5
	GreydConfLexerINT       = 6
	GreydConfLexerSTRING    = 7
	GreydConfLexerEQ        = 8
	GreydConfLexerCOMMA     = 9
	GreydConfLexerLBR       = 10
	GreydConfLexerRBR       = 11
	GreydConfLexerLSQ       = 12
	GreydConfLexerRSQ       = 13
	GreydConfLexerEOL       = 14
	GreydConfLexerCOMMENT   = 15
	GreydConfLexerWS        = 16
)
