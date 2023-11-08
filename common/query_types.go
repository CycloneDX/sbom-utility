package common

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/CycloneDX/sbom-utility/utils"
)

// Named tokens
const (
	QUERY_TOKEN_WILDCARD       = "*"
	QUERY_FROM_CLAUSE_SEP      = "."
	QUERY_SELECT_CLAUSE_SEP    = ","
	QUERY_WHERE_EXPRESSION_SEP = ","
	QUERY_WHERE_OPERAND_EQUALS = "="
)

// query JSON map and return selected subset using SQL-like syntax:
// SELECT: <key.1>, <key.2>, ... // "firstname, lastname, email" || * (default)
// FROM: <key path>              // "product.customers"
// WHERE: <key.X> == <value>     // "country='Germany'"
// ORDERBY: <key.N>              // "lastname"
// e.g.,SELECT * FROM product.customers WHERE country="Germany";
type QueryRequest struct {
	selectFieldsRaw     string
	selectFields        []string
	fromObjectsRaw      string
	fromObjectSelectors []string
	WhereValuesRaw      string
	whereClauses        []string
	whereFilters        []WhereFilter
	rawOrderByKeys      string
	//orderByKeys       []string // TODO
	IsFromObjectAMap    bool
	IsFromObjectAnArray bool
}

func NewQueryRequestSelectFromWhere(rawSelect string, rawFrom string, rawWhere string) (qr *QueryRequest, err error) {
	qr = new(QueryRequest)
	qr.selectFieldsRaw = rawSelect
	qr.fromObjectsRaw = rawFrom
	qr.WhereValuesRaw = rawWhere
	err = qr.ParseQueryClauses()
	return
}

func NewQueryRequestSelectFrom(rawSelect string, rawFrom string) (qr *QueryRequest, err error) {
	qr = new(QueryRequest)
	qr.selectFieldsRaw = rawSelect
	qr.fromObjectsRaw = rawFrom
	err = qr.ParseQueryClauses()
	return
}

func NewQueryRequestSelectWildcardFrom(rawFrom string) (qr *QueryRequest, err error) {
	qr = new(QueryRequest)
	qr.selectFieldsRaw = QUERY_TOKEN_WILDCARD
	qr.fromObjectsRaw = rawFrom
	err = qr.ParseQueryClauses()
	return
}

// Implement the Stringer interface for QueryRequest
func (qr *QueryRequest) String() string {
	sb := new(strings.Builder)
	sb.WriteString(fmt.Sprintf("--select: %s\n", qr.selectFields))
	sb.WriteString(fmt.Sprintf("--from: %s\n", qr.fromObjectsRaw))
	sb.WriteString(fmt.Sprintf("--where: %s\n", qr.WhereValuesRaw))
	sb.WriteString(fmt.Sprintf("--orderby: %s\n", qr.rawOrderByKeys))
	return sb.String()
}

func (qr *QueryRequest) GetSelectKeys() []string {
	if len(qr.selectFields) == 0 && len(qr.selectFieldsRaw) > 0 {
		qr.selectFields = strings.Split(qr.selectFieldsRaw, QUERY_SELECT_CLAUSE_SEP)
	}
	return qr.selectFields
}

func (qr *QueryRequest) GetFromKeys() []string {
	if len(qr.fromObjectSelectors) == 0 && len(qr.fromObjectSelectors) > 0 {
		qr.fromObjectSelectors = strings.Split(qr.fromObjectsRaw, QUERY_FROM_CLAUSE_SEP)
	}
	return qr.fromObjectSelectors
}

func (qr *QueryRequest) GetWhereFilters() ([]WhereFilter, error) {
	if len(qr.whereClauses) == 0 && len(qr.whereFilters) > 0 {
		// TODO: consider if we really need error handling
		err := qr.parseWhereFilterExpressions()
		if err != nil {
			return nil, err
		}
	}
	return qr.whereFilters, nil
}

func (qr *QueryRequest) ParseQueryClauses() (err error) {

	// parse out path (selectors) to JSON object from raw '--from' flag's value
	if qr.fromObjectsRaw != "" {
		qr.fromObjectSelectors = strings.Split(qr.fromObjectsRaw, QUERY_FROM_CLAUSE_SEP)
		//getLogger().Tracef("FROM json object (path): %v\n", qr.fromObjectSelectors)
	}

	// parse out field (keys) from raw '--select' flag's value
	if qr.selectFieldsRaw != "" {
		qr.selectFields = strings.Split(qr.selectFieldsRaw, QUERY_SELECT_CLAUSE_SEP)
		//getLogger().Tracef("SELECT keys (fields): %v\n", qr.selectFields)
	}

	// parse out `key=<regex>` filters from raw `-where` flag's value
	if qr.WhereValuesRaw != "" {
		qr.whereClauses = strings.Split(qr.WhereValuesRaw, QUERY_WHERE_EXPRESSION_SEP)
		//getLogger().Tracef("WHERE selectors (key=value): %v\n", qr.whereExpressions)
		err = qr.parseWhereFilterExpressions()
		// NOTE: we return here on error as more logic may follow for orderby
		if err != nil {
			return
		}
	}

	return
}

// Parse/validate each key=<regex> expression found on WHERE clause
func (qr *QueryRequest) parseWhereFilterExpressions() (err error) {

	if len(qr.whereClauses) == 0 {
		return NewQueryWhereClauseError(qr, qr.WhereValuesRaw)
	}

	var filter *WhereFilter
	for _, clause := range qr.whereClauses {

		filter = ParseWhereFilter(clause)

		if filter == nil {
			err = NewQueryWhereClauseError(qr, clause)
			return
		}

		qr.whereFilters = append(qr.whereFilters, *filter)
	}

	return
}

// TODO: generate more specific error messages on why parsing failed
func ParseWhereFilter(rawExpression string) (pWhereSelector *WhereFilter) {

	if rawExpression == "" {
		return // nil
	}

	tokens := strings.Split(rawExpression, QUERY_WHERE_OPERAND_EQUALS)

	if len(tokens) != 2 {
		return // nil
	}

	var whereFilter = WhereFilter{}
	whereFilter.Operand = QUERY_WHERE_OPERAND_EQUALS
	whereFilter.Key = tokens[0]
	whereFilter.Value = tokens[1]

	if whereFilter.Value == "" {
		return // nil
	}

	var errCompile error
	whereFilter.ValueRegEx, errCompile = utils.CompileRegex(whereFilter.Value)
	//getLogger().Debugf(">> Regular expression: `%v`...", whereFilter.ValueRegEx)

	if errCompile != nil {
		return // nil
	}

	return &whereFilter
}

type QueryResponse struct {
	resultMap map[string]interface{}
}

func NewQueryResponse() *QueryResponse {
	qr := new(QueryResponse)
	qr.resultMap = make(map[string]interface{})
	return qr
}

type WhereFilter struct {
	Key        string
	Operand    string
	Value      string
	ValueRegEx *regexp.Regexp
}

// Note: Used to normalize key lookups in maps accounting for changes in
// key names on CDX structures created from annotations during JSON unmarshal
// TODO: unused as of now
func (filter *WhereFilter) GetNormalizeKey() (normalizedKey string) {
	normalizedKey = strings.ToLower(filter.Key)
	// Note: accounts for changes in JSON annotations (e.g., "bom-ref", etc.)
	normalizedKey = strings.Replace(normalizedKey, "-", "", -1)
	return
}
