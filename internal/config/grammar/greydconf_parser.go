// Code generated from internal/config/grammar/GreydConf.g4 by ANTLR 4.13.1. DO NOT EDIT.

package grammar // GreydConf
import (
	"fmt"
	"strconv"
	"sync"

	"github.com/antlr4-go/antlr/v4"
)

// Suppress unused import errors
var _ = fmt.Printf
var _ = strconv.Itoa
var _ = sync.Once{}

type GreydConfParser struct {
	*antlr.BaseParser
}

var GreydConfParserStaticData struct {
	once                   sync.Once
	serializedATN          []int32
	LiteralNames           []string
	SymbolicNames          []string
	RuleNames              []string
	PredictionContextCache *antlr.PredictionContextCache
	atn                    *antlr.ATN
	decisionToDFA          []*antlr.DFA
}

func greydconfParserInit() {
	staticData := &GreydConfParserStaticData
	staticData.LiteralNames = []string{
		"", "", "", "", "", "", "", "", "'='", "','", "'{'", "'}'", "'['", "']'",
	}
	staticData.SymbolicNames = []string{
		"", "SECTION", "INCLUDE", "BLACKLIST", "WHITELIST", "NAME", "INT", "STRING",
		"EQ", "COMMA", "LBR", "RBR", "LSQ", "RSQ", "EOL", "COMMENT", "WS",
	}
	staticData.RuleNames = []string{
		"config", "statement", "assignment", "value", "list", "section", "separator",
		"sectionType", "include",
	}
	staticData.PredictionContextCache = antlr.NewPredictionContextCache()
	staticData.serializedATN = []int32{
		4, 1, 16, 154, 2, 0, 7, 0, 2, 1, 7, 1, 2, 2, 7, 2, 2, 3, 7, 3, 2, 4, 7,
		4, 2, 5, 7, 5, 2, 6, 7, 6, 2, 7, 7, 7, 2, 8, 7, 8, 1, 0, 5, 0, 20, 8, 0,
		10, 0, 12, 0, 23, 9, 0, 1, 0, 1, 0, 4, 0, 27, 8, 0, 11, 0, 12, 0, 28, 1,
		0, 5, 0, 32, 8, 0, 10, 0, 12, 0, 35, 9, 0, 3, 0, 37, 8, 0, 1, 0, 5, 0,
		40, 8, 0, 10, 0, 12, 0, 43, 9, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 3, 1, 50,
		8, 1, 1, 2, 1, 2, 1, 2, 1, 2, 1, 3, 1, 3, 1, 3, 3, 3, 59, 8, 3, 1, 4, 1,
		4, 5, 4, 63, 8, 4, 10, 4, 12, 4, 66, 9, 4, 1, 4, 1, 4, 5, 4, 70, 8, 4,
		10, 4, 12, 4, 73, 9, 4, 1, 4, 1, 4, 5, 4, 77, 8, 4, 10, 4, 12, 4, 80, 9,
		4, 1, 4, 5, 4, 83, 8, 4, 10, 4, 12, 4, 86, 9, 4, 1, 4, 5, 4, 89, 8, 4,
		10, 4, 12, 4, 92, 9, 4, 1, 4, 3, 4, 95, 8, 4, 1, 4, 5, 4, 98, 8, 4, 10,
		4, 12, 4, 101, 9, 4, 3, 4, 103, 8, 4, 1, 4, 1, 4, 1, 5, 1, 5, 1, 5, 5,
		5, 110, 8, 5, 10, 5, 12, 5, 113, 9, 5, 1, 5, 1, 5, 5, 5, 117, 8, 5, 10,
		5, 12, 5, 120, 9, 5, 1, 5, 1, 5, 1, 5, 1, 5, 5, 5, 126, 8, 5, 10, 5, 12,
		5, 129, 9, 5, 1, 5, 3, 5, 132, 8, 5, 3, 5, 134, 8, 5, 1, 5, 5, 5, 137,
		8, 5, 10, 5, 12, 5, 140, 9, 5, 1, 5, 1, 5, 1, 6, 4, 6, 145, 8, 6, 11, 6,
		12, 6, 146, 1, 7, 1, 7, 1, 8, 1, 8, 1, 8, 1, 8, 0, 0, 9, 0, 2, 4, 6, 8,
		10, 12, 14, 16, 0, 2, 2, 0, 9, 9, 14, 14, 2, 0, 1, 1, 3, 4, 168, 0, 21,
		1, 0, 0, 0, 2, 49, 1, 0, 0, 0, 4, 51, 1, 0, 0, 0, 6, 58, 1, 0, 0, 0, 8,
		60, 1, 0, 0, 0, 10, 106, 1, 0, 0, 0, 12, 144, 1, 0, 0, 0, 14, 148, 1, 0,
		0, 0, 16, 150, 1, 0, 0, 0, 18, 20, 5, 14, 0, 0, 19, 18, 1, 0, 0, 0, 20,
		23, 1, 0, 0, 0, 21, 19, 1, 0, 0, 0, 21, 22, 1, 0, 0, 0, 22, 36, 1, 0, 0,
		0, 23, 21, 1, 0, 0, 0, 24, 33, 3, 2, 1, 0, 25, 27, 5, 14, 0, 0, 26, 25,
		1, 0, 0, 0, 27, 28, 1, 0, 0, 0, 28, 26, 1, 0, 0, 0, 28, 29, 1, 0, 0, 0,
		29, 30, 1, 0, 0, 0, 30, 32, 3, 2, 1, 0, 31, 26, 1, 0, 0, 0, 32, 35, 1,
		0, 0, 0, 33, 31, 1, 0, 0, 0, 33, 34, 1, 0, 0, 0, 34, 37, 1, 0, 0, 0, 35,
		33, 1, 0, 0, 0, 36, 24, 1, 0, 0, 0, 36, 37, 1, 0, 0, 0, 37, 41, 1, 0, 0,
		0, 38, 40, 5, 14, 0, 0, 39, 38, 1, 0, 0, 0, 40, 43, 1, 0, 0, 0, 41, 39,
		1, 0, 0, 0, 41, 42, 1, 0, 0, 0, 42, 44, 1, 0, 0, 0, 43, 41, 1, 0, 0, 0,
		44, 45, 5, 0, 0, 1, 45, 1, 1, 0, 0, 0, 46, 50, 3, 4, 2, 0, 47, 50, 3, 10,
		5, 0, 48, 50, 3, 16, 8, 0, 49, 46, 1, 0, 0, 0, 49, 47, 1, 0, 0, 0, 49,
		48, 1, 0, 0, 0, 50, 3, 1, 0, 0, 0, 51, 52, 5, 5, 0, 0, 52, 53, 5, 8, 0,
		0, 53, 54, 3, 6, 3, 0, 54, 5, 1, 0, 0, 0, 55, 59, 5, 6, 0, 0, 56, 59, 5,
		7, 0, 0, 57, 59, 3, 8, 4, 0, 58, 55, 1, 0, 0, 0, 58, 56, 1, 0, 0, 0, 58,
		57, 1, 0, 0, 0, 59, 7, 1, 0, 0, 0, 60, 64, 5, 12, 0, 0, 61, 63, 5, 14,
		0, 0, 62, 61, 1, 0, 0, 0, 63, 66, 1, 0, 0, 0, 64, 62, 1, 0, 0, 0, 64, 65,
		1, 0, 0, 0, 65, 102, 1, 0, 0, 0, 66, 64, 1, 0, 0, 0, 67, 84, 3, 6, 3, 0,
		68, 70, 5, 14, 0, 0, 69, 68, 1, 0, 0, 0, 70, 73, 1, 0, 0, 0, 71, 69, 1,
		0, 0, 0, 71, 72, 1, 0, 0, 0, 72, 74, 1, 0, 0, 0, 73, 71, 1, 0, 0, 0, 74,
		78, 5, 9, 0, 0, 75, 77, 5, 14, 0, 0, 76, 75, 1, 0, 0, 0, 77, 80, 1, 0,
		0, 0, 78, 76, 1, 0, 0, 0, 78, 79, 1, 0, 0, 0, 79, 81, 1, 0, 0, 0, 80, 78,
		1, 0, 0, 0, 81, 83, 3, 6, 3, 0, 82, 71, 1, 0, 0, 0, 83, 86, 1, 0, 0, 0,
		84, 82, 1, 0, 0, 0, 84, 85, 1, 0, 0, 0, 85, 90, 1, 0, 0, 0, 86, 84, 1,
		0, 0, 0, 87, 89, 5, 14, 0, 0, 88, 87, 1, 0, 0, 0, 89, 92, 1, 0, 0, 0, 90,
		88, 1, 0, 0, 0, 90, 91, 1, 0, 0, 0, 91, 94, 1, 0, 0, 0, 92, 90, 1, 0, 0,
		0, 93, 95, 5, 9, 0, 0, 94, 93, 1, 0, 0, 0, 94, 95, 1, 0, 0, 0, 95, 99,
		1, 0, 0, 0, 96, 98, 5, 14, 0, 0, 97, 96, 1, 0, 0, 0, 98, 101, 1, 0, 0,
		0, 99, 97, 1, 0, 0, 0, 99, 100, 1, 0, 0, 0, 100, 103, 1, 0, 0, 0, 101,
		99, 1, 0, 0, 0, 102, 67, 1, 0, 0, 0, 102, 103, 1, 0, 0, 0, 103, 104, 1,
		0, 0, 0, 104, 105, 5, 13, 0, 0, 105, 9, 1, 0, 0, 0, 106, 107, 3, 14, 7,
		0, 107, 111, 5, 5, 0, 0, 108, 110, 5, 14, 0, 0, 109, 108, 1, 0, 0, 0, 110,
		113, 1, 0, 0, 0, 111, 109, 1, 0, 0, 0, 111, 112, 1, 0, 0, 0, 112, 114,
		1, 0, 0, 0, 113, 111, 1, 0, 0, 0, 114, 118, 5, 10, 0, 0, 115, 117, 5, 14,
		0, 0, 116, 115, 1, 0, 0, 0, 117, 120, 1, 0, 0, 0, 118, 116, 1, 0, 0, 0,
		118, 119, 1, 0, 0, 0, 119, 133, 1, 0, 0, 0, 120, 118, 1, 0, 0, 0, 121,
		127, 3, 4, 2, 0, 122, 123, 3, 12, 6, 0, 123, 124, 3, 4, 2, 0, 124, 126,
		1, 0, 0, 0, 125, 122, 1, 0, 0, 0, 126, 129, 1, 0, 0, 0, 127, 125, 1, 0,
		0, 0, 127, 128, 1, 0, 0, 0, 128, 131, 1, 0, 0, 0, 129, 127, 1, 0, 0, 0,
		130, 132, 3, 12, 6, 0, 131, 130, 1, 0, 0, 0, 131, 132, 1, 0, 0, 0, 132,
		134, 1, 0, 0, 0, 133, 121, 1, 0, 0, 0, 133, 134, 1, 0, 0, 0, 134, 138,
		1, 0, 0, 0, 135, 137, 5, 14, 0, 0, 136, 135, 1, 0, 0, 0, 137, 140, 1, 0,
		0, 0, 138, 136, 1, 0, 0, 0, 138, 139, 1, 0, 0, 0, 139, 141, 1, 0, 0, 0,
		140, 138, 1, 0, 0, 0, 141, 142, 5, 11, 0, 0, 142, 11, 1, 0, 0, 0, 143,
		145, 7, 0, 0, 0, 144, 143, 1, 0, 0, 0, 145, 146, 1, 0, 0, 0, 146, 144,
		1, 0, 0, 0, 146, 147, 1, 0, 0, 0, 147, 13, 1, 0, 0, 0, 148, 149, 7, 1,
		0, 0, 149, 15, 1, 0, 0, 0, 150, 151, 5, 2, 0, 0, 151, 152, 5, 7, 0, 0,
		152, 17, 1, 0, 0, 0, 22, 21, 28, 33, 36, 41, 49, 58, 64, 71, 78, 84, 90,
		94, 99, 102, 111, 118, 127, 131, 133, 138, 146,
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

// GreydConfParserInit initializes any static state used to implement GreydConfParser. By default the
// static state used to implement the parser is lazily initialized during the first call to
// NewGreydConfParser(). You can call this function if you wish to initialize the static state ahead
// of time.
func GreydConfParserInit() {
	staticData := &GreydConfParserStaticData
	staticData.once.Do(greydconfParserInit)
}

// NewGreydConfParser produces a new parser instance for the optional input antlr.TokenStream.
func NewGreydConfParser(input antlr.TokenStream) *GreydConfParser {
	GreydConfParserInit()
	this := new(GreydConfParser)
	this.BaseParser = antlr.NewBaseParser(input)
	staticData := &GreydConfParserStaticData
	this.Interpreter = antlr.NewParserATNSimulator(this, staticData.atn, staticData.decisionToDFA, staticData.PredictionContextCache)
	this.RuleNames = staticData.RuleNames
	this.LiteralNames = staticData.LiteralNames
	this.SymbolicNames = staticData.SymbolicNames
	this.GrammarFileName = "GreydConf.g4"

	return this
}

// GreydConfParser tokens.
const (
	GreydConfParserEOF       = antlr.TokenEOF
	GreydConfParserSECTION   = 1
	GreydConfParserINCLUDE   = 2
	GreydConfParserBLACKLIST = 3
	GreydConfParserWHITELIST = 4
	GreydConfParserNAME      = 5
	GreydConfParserINT       = 6
	GreydConfParserSTRING    = 7
	GreydConfParserEQ        = 8
	GreydConfParserCOMMA     = 9
	GreydConfParserLBR       = 10
	GreydConfParserRBR       = 11
	GreydConfParserLSQ       = 12
	GreydConfParserRSQ       = 13
	GreydConfParserEOL       = 14
	GreydConfParserCOMMENT   = 15
	GreydConfParserWS        = 16
)

// GreydConfParser rules.
const (
	GreydConfParserRULE_config      = 0
	GreydConfParserRULE_statement   = 1
	GreydConfParserRULE_assignment  = 2
	GreydConfParserRULE_value       = 3
	GreydConfParserRULE_list        = 4
	GreydConfParserRULE_section     = 5
	GreydConfParserRULE_separator   = 6
	GreydConfParserRULE_sectionType = 7
	GreydConfParserRULE_include     = 8
)

// IConfigContext is an interface to support dynamic dispatch.
type IConfigContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	EOF() antlr.TerminalNode
	AllEOL() []antlr.TerminalNode
	EOL(i int) antlr.TerminalNode
	AllStatement() []IStatementContext
	Statement(i int) IStatementContext

	// IsConfigContext differentiates from other interfaces.
	IsConfigContext()
}

type ConfigContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyConfigContext() *ConfigContext {
	var p = new(ConfigContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_config
	return p
}

func InitEmptyConfigContext(p *ConfigContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_config
}

func (*ConfigContext) IsConfigContext() {}

func NewConfigContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ConfigContext {
	var p = new(ConfigContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = GreydConfParserRULE_config

	return p
}

func (s *ConfigContext) GetParser() antlr.Parser { return s.parser }

func (s *ConfigContext) EOF() antlr.TerminalNode {
	return s.GetToken(GreydConfParserEOF, 0)
}

func (s *ConfigContext) AllEOL() []antlr.TerminalNode {
	return s.GetTokens(GreydConfParserEOL)
}

func (s *ConfigContext) EOL(i int) antlr.TerminalNode {
	return s.GetToken(GreydConfParserEOL, i)
}

func (s *ConfigContext) AllStatement() []IStatementContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IStatementContext); ok {
			len++
		}
	}

	tst := make([]IStatementContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IStatementContext); ok {
			tst[i] = t.(IStatementContext)
			i++
		}
	}

	return tst
}

func (s *ConfigContext) Statement(i int) IStatementContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IStatementContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IStatementContext)
}

func (s *ConfigContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ConfigContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ConfigContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.EnterConfig(s)
	}
}

func (s *ConfigContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.ExitConfig(s)
	}
}

func (p *GreydConfParser) Config() (localctx IConfigContext) {
	localctx = NewConfigContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 0, GreydConfParserRULE_config)
	var _la int

	var _alt int

	p.EnterOuterAlt(localctx, 1)
	p.SetState(21)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}
	_alt = p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 0, p.GetParserRuleContext())
	if p.HasError() {
		goto errorExit
	}
	for _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
		if _alt == 1 {
			{
				p.SetState(18)
				p.Match(GreydConfParserEOL)
				if p.HasError() {
					// Recognition error - abort rule
					goto errorExit
				}
			}

		}
		p.SetState(23)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_alt = p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 0, p.GetParserRuleContext())
		if p.HasError() {
			goto errorExit
		}
	}
	p.SetState(36)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}
	_la = p.GetTokenStream().LA(1)

	if (int64(_la) & ^0x3f) == 0 && ((int64(1)<<_la)&62) != 0 {
		{
			p.SetState(24)
			p.Statement()
		}
		p.SetState(33)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_alt = p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 2, p.GetParserRuleContext())
		if p.HasError() {
			goto errorExit
		}
		for _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
			if _alt == 1 {
				p.SetState(26)
				p.GetErrorHandler().Sync(p)
				if p.HasError() {
					goto errorExit
				}
				_la = p.GetTokenStream().LA(1)

				for ok := true; ok; ok = _la == GreydConfParserEOL {
					{
						p.SetState(25)
						p.Match(GreydConfParserEOL)
						if p.HasError() {
							// Recognition error - abort rule
							goto errorExit
						}
					}

					p.SetState(28)
					p.GetErrorHandler().Sync(p)
					if p.HasError() {
						goto errorExit
					}
					_la = p.GetTokenStream().LA(1)
				}
				{
					p.SetState(30)
					p.Statement()
				}

			}
			p.SetState(35)
			p.GetErrorHandler().Sync(p)
			if p.HasError() {
				goto errorExit
			}
			_alt = p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 2, p.GetParserRuleContext())
			if p.HasError() {
				goto errorExit
			}
		}

	}
	p.SetState(41)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}
	_la = p.GetTokenStream().LA(1)

	for _la == GreydConfParserEOL {
		{
			p.SetState(38)
			p.Match(GreydConfParserEOL)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}

		p.SetState(43)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_la = p.GetTokenStream().LA(1)
	}
	{
		p.SetState(44)
		p.Match(GreydConfParserEOF)
		if p.HasError() {
			// Recognition error - abort rule
			goto errorExit
		}
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// IStatementContext is an interface to support dynamic dispatch.
type IStatementContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	Assignment() IAssignmentContext
	Section() ISectionContext
	Include() IIncludeContext

	// IsStatementContext differentiates from other interfaces.
	IsStatementContext()
}

type StatementContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyStatementContext() *StatementContext {
	var p = new(StatementContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_statement
	return p
}

func InitEmptyStatementContext(p *StatementContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_statement
}

func (*StatementContext) IsStatementContext() {}

func NewStatementContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *StatementContext {
	var p = new(StatementContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = GreydConfParserRULE_statement

	return p
}

func (s *StatementContext) GetParser() antlr.Parser { return s.parser }

func (s *StatementContext) Assignment() IAssignmentContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IAssignmentContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IAssignmentContext)
}

func (s *StatementContext) Section() ISectionContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(ISectionContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(ISectionContext)
}

func (s *StatementContext) Include() IIncludeContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IIncludeContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IIncludeContext)
}

func (s *StatementContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *StatementContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *StatementContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.EnterStatement(s)
	}
}

func (s *StatementContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.ExitStatement(s)
	}
}

func (p *GreydConfParser) Statement() (localctx IStatementContext) {
	localctx = NewStatementContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 2, GreydConfParserRULE_statement)
	p.SetState(49)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}

	switch p.GetTokenStream().LA(1) {
	case GreydConfParserNAME:
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(46)
			p.Assignment()
		}

	case GreydConfParserSECTION, GreydConfParserBLACKLIST, GreydConfParserWHITELIST:
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(47)
			p.Section()
		}

	case GreydConfParserINCLUDE:
		p.EnterOuterAlt(localctx, 3)
		{
			p.SetState(48)
			p.Include()
		}

	default:
		p.SetError(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
		goto errorExit
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// IAssignmentContext is an interface to support dynamic dispatch.
type IAssignmentContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	NAME() antlr.TerminalNode
	EQ() antlr.TerminalNode
	Value() IValueContext

	// IsAssignmentContext differentiates from other interfaces.
	IsAssignmentContext()
}

type AssignmentContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyAssignmentContext() *AssignmentContext {
	var p = new(AssignmentContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_assignment
	return p
}

func InitEmptyAssignmentContext(p *AssignmentContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_assignment
}

func (*AssignmentContext) IsAssignmentContext() {}

func NewAssignmentContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *AssignmentContext {
	var p = new(AssignmentContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = GreydConfParserRULE_assignment

	return p
}

func (s *AssignmentContext) GetParser() antlr.Parser { return s.parser }

func (s *AssignmentContext) NAME() antlr.TerminalNode {
	return s.GetToken(GreydConfParserNAME, 0)
}

func (s *AssignmentContext) EQ() antlr.TerminalNode {
	return s.GetToken(GreydConfParserEQ, 0)
}

func (s *AssignmentContext) Value() IValueContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IValueContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IValueContext)
}

func (s *AssignmentContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *AssignmentContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *AssignmentContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.EnterAssignment(s)
	}
}

func (s *AssignmentContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.ExitAssignment(s)
	}
}

func (p *GreydConfParser) Assignment() (localctx IAssignmentContext) {
	localctx = NewAssignmentContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 4, GreydConfParserRULE_assignment)
	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(51)
		p.Match(GreydConfParserNAME)
		if p.HasError() {
			// Recognition error - abort rule
			goto errorExit
		}
	}
	{
		p.SetState(52)
		p.Match(GreydConfParserEQ)
		if p.HasError() {
			// Recognition error - abort rule
			goto errorExit
		}
	}
	{
		p.SetState(53)
		p.Value()
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// IValueContext is an interface to support dynamic dispatch.
type IValueContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser
	// IsValueContext differentiates from other interfaces.
	IsValueContext()
}

type ValueContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyValueContext() *ValueContext {
	var p = new(ValueContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_value
	return p
}

func InitEmptyValueContext(p *ValueContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_value
}

func (*ValueContext) IsValueContext() {}

func NewValueContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ValueContext {
	var p = new(ValueContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = GreydConfParserRULE_value

	return p
}

func (s *ValueContext) GetParser() antlr.Parser { return s.parser }

func (s *ValueContext) CopyAll(ctx *ValueContext) {
	s.CopyFrom(&ctx.BaseParserRuleContext)
}

func (s *ValueContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ValueContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

type ListValueContext struct {
	ValueContext
}

func NewListValueContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *ListValueContext {
	var p = new(ListValueContext)

	InitEmptyValueContext(&p.ValueContext)
	p.parser = parser
	p.CopyAll(ctx.(*ValueContext))

	return p
}

func (s *ListValueContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ListValueContext) List() IListContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IListContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(IListContext)
}

func (s *ListValueContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.EnterListValue(s)
	}
}

func (s *ListValueContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.ExitListValue(s)
	}
}

type IntValueContext struct {
	ValueContext
}

func NewIntValueContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *IntValueContext {
	var p = new(IntValueContext)

	InitEmptyValueContext(&p.ValueContext)
	p.parser = parser
	p.CopyAll(ctx.(*ValueContext))

	return p
}

func (s *IntValueContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *IntValueContext) INT() antlr.TerminalNode {
	return s.GetToken(GreydConfParserINT, 0)
}

func (s *IntValueContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.EnterIntValue(s)
	}
}

func (s *IntValueContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.ExitIntValue(s)
	}
}

type StrValueContext struct {
	ValueContext
}

func NewStrValueContext(parser antlr.Parser, ctx antlr.ParserRuleContext) *StrValueContext {
	var p = new(StrValueContext)

	InitEmptyValueContext(&p.ValueContext)
	p.parser = parser
	p.CopyAll(ctx.(*ValueContext))

	return p
}

func (s *StrValueContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *StrValueContext) STRING() antlr.TerminalNode {
	return s.GetToken(GreydConfParserSTRING, 0)
}

func (s *StrValueContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.EnterStrValue(s)
	}
}

func (s *StrValueContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.ExitStrValue(s)
	}
}

func (p *GreydConfParser) Value() (localctx IValueContext) {
	localctx = NewValueContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 6, GreydConfParserRULE_value)
	p.SetState(58)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}

	switch p.GetTokenStream().LA(1) {
	case GreydConfParserINT:
		localctx = NewIntValueContext(p, localctx)
		p.EnterOuterAlt(localctx, 1)
		{
			p.SetState(55)
			p.Match(GreydConfParserINT)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}

	case GreydConfParserSTRING:
		localctx = NewStrValueContext(p, localctx)
		p.EnterOuterAlt(localctx, 2)
		{
			p.SetState(56)
			p.Match(GreydConfParserSTRING)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}

	case GreydConfParserLSQ:
		localctx = NewListValueContext(p, localctx)
		p.EnterOuterAlt(localctx, 3)
		{
			p.SetState(57)
			p.List()
		}

	default:
		p.SetError(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
		goto errorExit
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// IListContext is an interface to support dynamic dispatch.
type IListContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	LSQ() antlr.TerminalNode
	RSQ() antlr.TerminalNode
	AllEOL() []antlr.TerminalNode
	EOL(i int) antlr.TerminalNode
	AllValue() []IValueContext
	Value(i int) IValueContext
	AllCOMMA() []antlr.TerminalNode
	COMMA(i int) antlr.TerminalNode

	// IsListContext differentiates from other interfaces.
	IsListContext()
}

type ListContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyListContext() *ListContext {
	var p = new(ListContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_list
	return p
}

func InitEmptyListContext(p *ListContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_list
}

func (*ListContext) IsListContext() {}

func NewListContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *ListContext {
	var p = new(ListContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = GreydConfParserRULE_list

	return p
}

func (s *ListContext) GetParser() antlr.Parser { return s.parser }

func (s *ListContext) LSQ() antlr.TerminalNode {
	return s.GetToken(GreydConfParserLSQ, 0)
}

func (s *ListContext) RSQ() antlr.TerminalNode {
	return s.GetToken(GreydConfParserRSQ, 0)
}

func (s *ListContext) AllEOL() []antlr.TerminalNode {
	return s.GetTokens(GreydConfParserEOL)
}

func (s *ListContext) EOL(i int) antlr.TerminalNode {
	return s.GetToken(GreydConfParserEOL, i)
}

func (s *ListContext) AllValue() []IValueContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IValueContext); ok {
			len++
		}
	}

	tst := make([]IValueContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IValueContext); ok {
			tst[i] = t.(IValueContext)
			i++
		}
	}

	return tst
}

func (s *ListContext) Value(i int) IValueContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IValueContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IValueContext)
}

func (s *ListContext) AllCOMMA() []antlr.TerminalNode {
	return s.GetTokens(GreydConfParserCOMMA)
}

func (s *ListContext) COMMA(i int) antlr.TerminalNode {
	return s.GetToken(GreydConfParserCOMMA, i)
}

func (s *ListContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *ListContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *ListContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.EnterList(s)
	}
}

func (s *ListContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.ExitList(s)
	}
}

func (p *GreydConfParser) List() (localctx IListContext) {
	localctx = NewListContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 8, GreydConfParserRULE_list)
	var _la int

	var _alt int

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(60)
		p.Match(GreydConfParserLSQ)
		if p.HasError() {
			// Recognition error - abort rule
			goto errorExit
		}
	}
	p.SetState(64)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}
	_la = p.GetTokenStream().LA(1)

	for _la == GreydConfParserEOL {
		{
			p.SetState(61)
			p.Match(GreydConfParserEOL)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}

		p.SetState(66)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_la = p.GetTokenStream().LA(1)
	}
	p.SetState(102)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}
	_la = p.GetTokenStream().LA(1)

	if (int64(_la) & ^0x3f) == 0 && ((int64(1)<<_la)&4288) != 0 {
		{
			p.SetState(67)
			p.Value()
		}
		p.SetState(84)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_alt = p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 10, p.GetParserRuleContext())
		if p.HasError() {
			goto errorExit
		}
		for _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
			if _alt == 1 {
				p.SetState(71)
				p.GetErrorHandler().Sync(p)
				if p.HasError() {
					goto errorExit
				}
				_la = p.GetTokenStream().LA(1)

				for _la == GreydConfParserEOL {
					{
						p.SetState(68)
						p.Match(GreydConfParserEOL)
						if p.HasError() {
							// Recognition error - abort rule
							goto errorExit
						}
					}

					p.SetState(73)
					p.GetErrorHandler().Sync(p)
					if p.HasError() {
						goto errorExit
					}
					_la = p.GetTokenStream().LA(1)
				}
				{
					p.SetState(74)
					p.Match(GreydConfParserCOMMA)
					if p.HasError() {
						// Recognition error - abort rule
						goto errorExit
					}
				}
				p.SetState(78)
				p.GetErrorHandler().Sync(p)
				if p.HasError() {
					goto errorExit
				}
				_la = p.GetTokenStream().LA(1)

				for _la == GreydConfParserEOL {
					{
						p.SetState(75)
						p.Match(GreydConfParserEOL)
						if p.HasError() {
							// Recognition error - abort rule
							goto errorExit
						}
					}

					p.SetState(80)
					p.GetErrorHandler().Sync(p)
					if p.HasError() {
						goto errorExit
					}
					_la = p.GetTokenStream().LA(1)
				}
				{
					p.SetState(81)
					p.Value()
				}

			}
			p.SetState(86)
			p.GetErrorHandler().Sync(p)
			if p.HasError() {
				goto errorExit
			}
			_alt = p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 10, p.GetParserRuleContext())
			if p.HasError() {
				goto errorExit
			}
		}
		p.SetState(90)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_alt = p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 11, p.GetParserRuleContext())
		if p.HasError() {
			goto errorExit
		}
		for _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
			if _alt == 1 {
				{
					p.SetState(87)
					p.Match(GreydConfParserEOL)
					if p.HasError() {
						// Recognition error - abort rule
						goto errorExit
					}
				}

			}
			p.SetState(92)
			p.GetErrorHandler().Sync(p)
			if p.HasError() {
				goto errorExit
			}
			_alt = p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 11, p.GetParserRuleContext())
			if p.HasError() {
				goto errorExit
			}
		}
		p.SetState(94)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_la = p.GetTokenStream().LA(1)

		if _la == GreydConfParserCOMMA {
			{
				p.SetState(93)
				p.Match(GreydConfParserCOMMA)
				if p.HasError() {
					// Recognition error - abort rule
					goto errorExit
				}
			}

		}
		p.SetState(99)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_la = p.GetTokenStream().LA(1)

		for _la == GreydConfParserEOL {
			{
				p.SetState(96)
				p.Match(GreydConfParserEOL)
				if p.HasError() {
					// Recognition error - abort rule
					goto errorExit
				}
			}

			p.SetState(101)
			p.GetErrorHandler().Sync(p)
			if p.HasError() {
				goto errorExit
			}
			_la = p.GetTokenStream().LA(1)
		}

	}
	{
		p.SetState(104)
		p.Match(GreydConfParserRSQ)
		if p.HasError() {
			// Recognition error - abort rule
			goto errorExit
		}
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// ISectionContext is an interface to support dynamic dispatch.
type ISectionContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	SectionType() ISectionTypeContext
	NAME() antlr.TerminalNode
	LBR() antlr.TerminalNode
	RBR() antlr.TerminalNode
	AllEOL() []antlr.TerminalNode
	EOL(i int) antlr.TerminalNode
	AllAssignment() []IAssignmentContext
	Assignment(i int) IAssignmentContext
	AllSeparator() []ISeparatorContext
	Separator(i int) ISeparatorContext

	// IsSectionContext differentiates from other interfaces.
	IsSectionContext()
}

type SectionContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptySectionContext() *SectionContext {
	var p = new(SectionContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_section
	return p
}

func InitEmptySectionContext(p *SectionContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_section
}

func (*SectionContext) IsSectionContext() {}

func NewSectionContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *SectionContext {
	var p = new(SectionContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = GreydConfParserRULE_section

	return p
}

func (s *SectionContext) GetParser() antlr.Parser { return s.parser }

func (s *SectionContext) SectionType() ISectionTypeContext {
	var t antlr.RuleContext
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(ISectionTypeContext); ok {
			t = ctx.(antlr.RuleContext)
			break
		}
	}

	if t == nil {
		return nil
	}

	return t.(ISectionTypeContext)
}

func (s *SectionContext) NAME() antlr.TerminalNode {
	return s.GetToken(GreydConfParserNAME, 0)
}

func (s *SectionContext) LBR() antlr.TerminalNode {
	return s.GetToken(GreydConfParserLBR, 0)
}

func (s *SectionContext) RBR() antlr.TerminalNode {
	return s.GetToken(GreydConfParserRBR, 0)
}

func (s *SectionContext) AllEOL() []antlr.TerminalNode {
	return s.GetTokens(GreydConfParserEOL)
}

func (s *SectionContext) EOL(i int) antlr.TerminalNode {
	return s.GetToken(GreydConfParserEOL, i)
}

func (s *SectionContext) AllAssignment() []IAssignmentContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(IAssignmentContext); ok {
			len++
		}
	}

	tst := make([]IAssignmentContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(IAssignmentContext); ok {
			tst[i] = t.(IAssignmentContext)
			i++
		}
	}

	return tst
}

func (s *SectionContext) Assignment(i int) IAssignmentContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(IAssignmentContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(IAssignmentContext)
}

func (s *SectionContext) AllSeparator() []ISeparatorContext {
	children := s.GetChildren()
	len := 0
	for _, ctx := range children {
		if _, ok := ctx.(ISeparatorContext); ok {
			len++
		}
	}

	tst := make([]ISeparatorContext, len)
	i := 0
	for _, ctx := range children {
		if t, ok := ctx.(ISeparatorContext); ok {
			tst[i] = t.(ISeparatorContext)
			i++
		}
	}

	return tst
}

func (s *SectionContext) Separator(i int) ISeparatorContext {
	var t antlr.RuleContext
	j := 0
	for _, ctx := range s.GetChildren() {
		if _, ok := ctx.(ISeparatorContext); ok {
			if j == i {
				t = ctx.(antlr.RuleContext)
				break
			}
			j++
		}
	}

	if t == nil {
		return nil
	}

	return t.(ISeparatorContext)
}

func (s *SectionContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *SectionContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *SectionContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.EnterSection(s)
	}
}

func (s *SectionContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.ExitSection(s)
	}
}

func (p *GreydConfParser) Section() (localctx ISectionContext) {
	localctx = NewSectionContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 10, GreydConfParserRULE_section)
	var _la int

	var _alt int

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(106)
		p.SectionType()
	}
	{
		p.SetState(107)
		p.Match(GreydConfParserNAME)
		if p.HasError() {
			// Recognition error - abort rule
			goto errorExit
		}
	}
	p.SetState(111)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}
	_la = p.GetTokenStream().LA(1)

	for _la == GreydConfParserEOL {
		{
			p.SetState(108)
			p.Match(GreydConfParserEOL)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}

		p.SetState(113)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_la = p.GetTokenStream().LA(1)
	}
	{
		p.SetState(114)
		p.Match(GreydConfParserLBR)
		if p.HasError() {
			// Recognition error - abort rule
			goto errorExit
		}
	}
	p.SetState(118)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}
	_alt = p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 16, p.GetParserRuleContext())
	if p.HasError() {
		goto errorExit
	}
	for _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
		if _alt == 1 {
			{
				p.SetState(115)
				p.Match(GreydConfParserEOL)
				if p.HasError() {
					// Recognition error - abort rule
					goto errorExit
				}
			}

		}
		p.SetState(120)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_alt = p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 16, p.GetParserRuleContext())
		if p.HasError() {
			goto errorExit
		}
	}
	p.SetState(133)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}
	_la = p.GetTokenStream().LA(1)

	if _la == GreydConfParserNAME {
		{
			p.SetState(121)
			p.Assignment()
		}
		p.SetState(127)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_alt = p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 17, p.GetParserRuleContext())
		if p.HasError() {
			goto errorExit
		}
		for _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
			if _alt == 1 {
				{
					p.SetState(122)
					p.Separator()
				}
				{
					p.SetState(123)
					p.Assignment()
				}

			}
			p.SetState(129)
			p.GetErrorHandler().Sync(p)
			if p.HasError() {
				goto errorExit
			}
			_alt = p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 17, p.GetParserRuleContext())
			if p.HasError() {
				goto errorExit
			}
		}
		p.SetState(131)
		p.GetErrorHandler().Sync(p)

		if p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 18, p.GetParserRuleContext()) == 1 {
			{
				p.SetState(130)
				p.Separator()
			}

		} else if p.HasError() { // JIM
			goto errorExit
		}

	}
	p.SetState(138)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}
	_la = p.GetTokenStream().LA(1)

	for _la == GreydConfParserEOL {
		{
			p.SetState(135)
			p.Match(GreydConfParserEOL)
			if p.HasError() {
				// Recognition error - abort rule
				goto errorExit
			}
		}

		p.SetState(140)
		p.GetErrorHandler().Sync(p)
		if p.HasError() {
			goto errorExit
		}
		_la = p.GetTokenStream().LA(1)
	}
	{
		p.SetState(141)
		p.Match(GreydConfParserRBR)
		if p.HasError() {
			// Recognition error - abort rule
			goto errorExit
		}
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// ISeparatorContext is an interface to support dynamic dispatch.
type ISeparatorContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	AllCOMMA() []antlr.TerminalNode
	COMMA(i int) antlr.TerminalNode
	AllEOL() []antlr.TerminalNode
	EOL(i int) antlr.TerminalNode

	// IsSeparatorContext differentiates from other interfaces.
	IsSeparatorContext()
}

type SeparatorContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptySeparatorContext() *SeparatorContext {
	var p = new(SeparatorContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_separator
	return p
}

func InitEmptySeparatorContext(p *SeparatorContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_separator
}

func (*SeparatorContext) IsSeparatorContext() {}

func NewSeparatorContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *SeparatorContext {
	var p = new(SeparatorContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = GreydConfParserRULE_separator

	return p
}

func (s *SeparatorContext) GetParser() antlr.Parser { return s.parser }

func (s *SeparatorContext) AllCOMMA() []antlr.TerminalNode {
	return s.GetTokens(GreydConfParserCOMMA)
}

func (s *SeparatorContext) COMMA(i int) antlr.TerminalNode {
	return s.GetToken(GreydConfParserCOMMA, i)
}

func (s *SeparatorContext) AllEOL() []antlr.TerminalNode {
	return s.GetTokens(GreydConfParserEOL)
}

func (s *SeparatorContext) EOL(i int) antlr.TerminalNode {
	return s.GetToken(GreydConfParserEOL, i)
}

func (s *SeparatorContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *SeparatorContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *SeparatorContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.EnterSeparator(s)
	}
}

func (s *SeparatorContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.ExitSeparator(s)
	}
}

func (p *GreydConfParser) Separator() (localctx ISeparatorContext) {
	localctx = NewSeparatorContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 12, GreydConfParserRULE_separator)
	var _la int

	var _alt int

	p.EnterOuterAlt(localctx, 1)
	p.SetState(144)
	p.GetErrorHandler().Sync(p)
	if p.HasError() {
		goto errorExit
	}
	_alt = 1
	for ok := true; ok; ok = _alt != 2 && _alt != antlr.ATNInvalidAltNumber {
		switch _alt {
		case 1:
			{
				p.SetState(143)
				_la = p.GetTokenStream().LA(1)

				if !(_la == GreydConfParserCOMMA || _la == GreydConfParserEOL) {
					p.GetErrorHandler().RecoverInline(p)
				} else {
					p.GetErrorHandler().ReportMatch(p)
					p.Consume()
				}
			}

		default:
			p.SetError(antlr.NewNoViableAltException(p, nil, nil, nil, nil, nil))
			goto errorExit
		}

		p.SetState(146)
		p.GetErrorHandler().Sync(p)
		_alt = p.GetInterpreter().AdaptivePredict(p.BaseParser, p.GetTokenStream(), 21, p.GetParserRuleContext())
		if p.HasError() {
			goto errorExit
		}
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// ISectionTypeContext is an interface to support dynamic dispatch.
type ISectionTypeContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	SECTION() antlr.TerminalNode
	BLACKLIST() antlr.TerminalNode
	WHITELIST() antlr.TerminalNode

	// IsSectionTypeContext differentiates from other interfaces.
	IsSectionTypeContext()
}

type SectionTypeContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptySectionTypeContext() *SectionTypeContext {
	var p = new(SectionTypeContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_sectionType
	return p
}

func InitEmptySectionTypeContext(p *SectionTypeContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_sectionType
}

func (*SectionTypeContext) IsSectionTypeContext() {}

func NewSectionTypeContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *SectionTypeContext {
	var p = new(SectionTypeContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = GreydConfParserRULE_sectionType

	return p
}

func (s *SectionTypeContext) GetParser() antlr.Parser { return s.parser }

func (s *SectionTypeContext) SECTION() antlr.TerminalNode {
	return s.GetToken(GreydConfParserSECTION, 0)
}

func (s *SectionTypeContext) BLACKLIST() antlr.TerminalNode {
	return s.GetToken(GreydConfParserBLACKLIST, 0)
}

func (s *SectionTypeContext) WHITELIST() antlr.TerminalNode {
	return s.GetToken(GreydConfParserWHITELIST, 0)
}

func (s *SectionTypeContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *SectionTypeContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *SectionTypeContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.EnterSectionType(s)
	}
}

func (s *SectionTypeContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.ExitSectionType(s)
	}
}

func (p *GreydConfParser) SectionType() (localctx ISectionTypeContext) {
	localctx = NewSectionTypeContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 14, GreydConfParserRULE_sectionType)
	var _la int

	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(148)
		_la = p.GetTokenStream().LA(1)

		if !((int64(_la) & ^0x3f) == 0 && ((int64(1)<<_la)&26) != 0) {
			p.GetErrorHandler().RecoverInline(p)
		} else {
			p.GetErrorHandler().ReportMatch(p)
			p.Consume()
		}
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}

// IIncludeContext is an interface to support dynamic dispatch.
type IIncludeContext interface {
	antlr.ParserRuleContext

	// GetParser returns the parser.
	GetParser() antlr.Parser

	// Getter signatures
	INCLUDE() antlr.TerminalNode
	STRING() antlr.TerminalNode

	// IsIncludeContext differentiates from other interfaces.
	IsIncludeContext()
}

type IncludeContext struct {
	antlr.BaseParserRuleContext
	parser antlr.Parser
}

func NewEmptyIncludeContext() *IncludeContext {
	var p = new(IncludeContext)
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_include
	return p
}

func InitEmptyIncludeContext(p *IncludeContext) {
	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, nil, -1)
	p.RuleIndex = GreydConfParserRULE_include
}

func (*IncludeContext) IsIncludeContext() {}

func NewIncludeContext(parser antlr.Parser, parent antlr.ParserRuleContext, invokingState int) *IncludeContext {
	var p = new(IncludeContext)

	antlr.InitBaseParserRuleContext(&p.BaseParserRuleContext, parent, invokingState)

	p.parser = parser
	p.RuleIndex = GreydConfParserRULE_include

	return p
}

func (s *IncludeContext) GetParser() antlr.Parser { return s.parser }

func (s *IncludeContext) INCLUDE() antlr.TerminalNode {
	return s.GetToken(GreydConfParserINCLUDE, 0)
}

func (s *IncludeContext) STRING() antlr.TerminalNode {
	return s.GetToken(GreydConfParserSTRING, 0)
}

func (s *IncludeContext) GetRuleContext() antlr.RuleContext {
	return s
}

func (s *IncludeContext) ToStringTree(ruleNames []string, recog antlr.Recognizer) string {
	return antlr.TreesStringTree(s, ruleNames, recog)
}

func (s *IncludeContext) EnterRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.EnterInclude(s)
	}
}

func (s *IncludeContext) ExitRule(listener antlr.ParseTreeListener) {
	if listenerT, ok := listener.(GreydConfListener); ok {
		listenerT.ExitInclude(s)
	}
}

func (p *GreydConfParser) Include() (localctx IIncludeContext) {
	localctx = NewIncludeContext(p, p.GetParserRuleContext(), p.GetState())
	p.EnterRule(localctx, 16, GreydConfParserRULE_include)
	p.EnterOuterAlt(localctx, 1)
	{
		p.SetState(150)
		p.Match(GreydConfParserINCLUDE)
		if p.HasError() {
			// Recognition error - abort rule
			goto errorExit
		}
	}
	{
		p.SetState(151)
		p.Match(GreydConfParserSTRING)
		if p.HasError() {
			// Recognition error - abort rule
			goto errorExit
		}
	}

errorExit:
	if p.HasError() {
		v := p.GetError()
		localctx.SetException(v)
		p.GetErrorHandler().ReportError(p, v)
		p.GetErrorHandler().Recover(p, v)
		p.SetError(nil)
	}
	p.ExitRule()
	return localctx
	goto errorExit // Trick to prevent compiler error if the label is not used
}
