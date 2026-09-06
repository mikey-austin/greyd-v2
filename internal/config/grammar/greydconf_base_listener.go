// Code generated from internal/config/grammar/GreydConf.g4 by ANTLR 4.13.1. DO NOT EDIT.

package grammar // GreydConf
import "github.com/antlr4-go/antlr/v4"

// BaseGreydConfListener is a complete listener for a parse tree produced by GreydConfParser.
type BaseGreydConfListener struct{}

var _ GreydConfListener = &BaseGreydConfListener{}

// VisitTerminal is called when a terminal node is visited.
func (s *BaseGreydConfListener) VisitTerminal(node antlr.TerminalNode) {}

// VisitErrorNode is called when an error node is visited.
func (s *BaseGreydConfListener) VisitErrorNode(node antlr.ErrorNode) {}

// EnterEveryRule is called when any rule is entered.
func (s *BaseGreydConfListener) EnterEveryRule(ctx antlr.ParserRuleContext) {}

// ExitEveryRule is called when any rule is exited.
func (s *BaseGreydConfListener) ExitEveryRule(ctx antlr.ParserRuleContext) {}

// EnterConfig is called when production config is entered.
func (s *BaseGreydConfListener) EnterConfig(ctx *ConfigContext) {}

// ExitConfig is called when production config is exited.
func (s *BaseGreydConfListener) ExitConfig(ctx *ConfigContext) {}

// EnterStatement is called when production statement is entered.
func (s *BaseGreydConfListener) EnterStatement(ctx *StatementContext) {}

// ExitStatement is called when production statement is exited.
func (s *BaseGreydConfListener) ExitStatement(ctx *StatementContext) {}

// EnterAssignment is called when production assignment is entered.
func (s *BaseGreydConfListener) EnterAssignment(ctx *AssignmentContext) {}

// ExitAssignment is called when production assignment is exited.
func (s *BaseGreydConfListener) ExitAssignment(ctx *AssignmentContext) {}

// EnterIntValue is called when production intValue is entered.
func (s *BaseGreydConfListener) EnterIntValue(ctx *IntValueContext) {}

// ExitIntValue is called when production intValue is exited.
func (s *BaseGreydConfListener) ExitIntValue(ctx *IntValueContext) {}

// EnterStrValue is called when production strValue is entered.
func (s *BaseGreydConfListener) EnterStrValue(ctx *StrValueContext) {}

// ExitStrValue is called when production strValue is exited.
func (s *BaseGreydConfListener) ExitStrValue(ctx *StrValueContext) {}

// EnterListValue is called when production listValue is entered.
func (s *BaseGreydConfListener) EnterListValue(ctx *ListValueContext) {}

// ExitListValue is called when production listValue is exited.
func (s *BaseGreydConfListener) ExitListValue(ctx *ListValueContext) {}

// EnterList is called when production list is entered.
func (s *BaseGreydConfListener) EnterList(ctx *ListContext) {}

// ExitList is called when production list is exited.
func (s *BaseGreydConfListener) ExitList(ctx *ListContext) {}

// EnterSection is called when production section is entered.
func (s *BaseGreydConfListener) EnterSection(ctx *SectionContext) {}

// ExitSection is called when production section is exited.
func (s *BaseGreydConfListener) ExitSection(ctx *SectionContext) {}

// EnterSeparator is called when production separator is entered.
func (s *BaseGreydConfListener) EnterSeparator(ctx *SeparatorContext) {}

// ExitSeparator is called when production separator is exited.
func (s *BaseGreydConfListener) ExitSeparator(ctx *SeparatorContext) {}

// EnterSectionType is called when production sectionType is entered.
func (s *BaseGreydConfListener) EnterSectionType(ctx *SectionTypeContext) {}

// ExitSectionType is called when production sectionType is exited.
func (s *BaseGreydConfListener) ExitSectionType(ctx *SectionTypeContext) {}

// EnterInclude is called when production include is entered.
func (s *BaseGreydConfListener) EnterInclude(ctx *IncludeContext) {}

// ExitInclude is called when production include is exited.
func (s *BaseGreydConfListener) ExitInclude(ctx *IncludeContext) {}
