// Code generated from internal/config/grammar/GreydConf.g4 by ANTLR 4.13.1. DO NOT EDIT.

package grammar // GreydConf
import "github.com/antlr4-go/antlr/v4"

// GreydConfListener is a complete listener for a parse tree produced by GreydConfParser.
type GreydConfListener interface {
	antlr.ParseTreeListener

	// EnterConfig is called when entering the config production.
	EnterConfig(c *ConfigContext)

	// EnterStatement is called when entering the statement production.
	EnterStatement(c *StatementContext)

	// EnterAssignment is called when entering the assignment production.
	EnterAssignment(c *AssignmentContext)

	// EnterIntValue is called when entering the intValue production.
	EnterIntValue(c *IntValueContext)

	// EnterStrValue is called when entering the strValue production.
	EnterStrValue(c *StrValueContext)

	// EnterListValue is called when entering the listValue production.
	EnterListValue(c *ListValueContext)

	// EnterList is called when entering the list production.
	EnterList(c *ListContext)

	// EnterSection is called when entering the section production.
	EnterSection(c *SectionContext)

	// EnterSeparator is called when entering the separator production.
	EnterSeparator(c *SeparatorContext)

	// EnterSectionType is called when entering the sectionType production.
	EnterSectionType(c *SectionTypeContext)

	// EnterInclude is called when entering the include production.
	EnterInclude(c *IncludeContext)

	// ExitConfig is called when exiting the config production.
	ExitConfig(c *ConfigContext)

	// ExitStatement is called when exiting the statement production.
	ExitStatement(c *StatementContext)

	// ExitAssignment is called when exiting the assignment production.
	ExitAssignment(c *AssignmentContext)

	// ExitIntValue is called when exiting the intValue production.
	ExitIntValue(c *IntValueContext)

	// ExitStrValue is called when exiting the strValue production.
	ExitStrValue(c *StrValueContext)

	// ExitListValue is called when exiting the listValue production.
	ExitListValue(c *ListValueContext)

	// ExitList is called when exiting the list production.
	ExitList(c *ListContext)

	// ExitSection is called when exiting the section production.
	ExitSection(c *SectionContext)

	// ExitSeparator is called when exiting the separator production.
	ExitSeparator(c *SeparatorContext)

	// ExitSectionType is called when exiting the sectionType production.
	ExitSectionType(c *SectionTypeContext)

	// ExitInclude is called when exiting the include production.
	ExitInclude(c *IncludeContext)
}
