package cmd

import (
	"regexp"
	"strings"
)

type WhereFilter struct {
	Key        string
	Operand    string
	Value      string
	ValueRegEx *regexp.Regexp
}

func (filter *WhereFilter) GetNormalizeKey() (normalizedKey string) {
	normalizedKey = strings.ToLower(filter.Key)
	// Note: accounts for changes in JSON annotations (e.g., "bom-ref", etc.)
	normalizedKey = strings.Replace(normalizedKey, "-", "", -1)
	return
}
