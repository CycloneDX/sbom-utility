package common

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/CycloneDX/sbom-utility/utils"
)

// ------------------------------------------------
// Query error type
// ------------------------------------------------

// Named tokens
const (
	QUERY_TOKEN_WILDCARD       = "*"
	QUERY_FROM_CLAUSE_SEP      = "."
	QUERY_SELECT_CLAUSE_SEP    = ","
	QUERY_WHERE_EXPRESSION_SEP = ","
	QUERY_WHERE_OPERAND_EQUALS = "="
)

// Query error messages
const (
	ERR_TYPE_INVALID_QUERY            = "invalid query"
	MSG_QUERY_INVALID_FROM_CLAUSE     = "invalid FROM clause"
	MSG_QUERY_INVALID_SELECT_CLAUSE   = "invalid SELECT clause"
	MSG_QUERY_INVALID_WHERE_CLAUSE    = "invalid WHERE clause"
	MSG_QUERY_INVALID_ORDER_BY_CLAUSE = "invalid ORDERBY clause"
)

type QueryError struct {
	//TODO: use BaseError type for its common fields
	Type    string
	Message string
	request *QueryRequest
	detail  string
}

func NewQueryError(qr *QueryRequest, m string, d string) *QueryError {
	var err = new(QueryError)
	err.Type = ERR_TYPE_INVALID_QUERY
	err.request = qr
	err.Message = m
	err.detail = d
	return err
}

func NewQueryFromClauseError(qr *QueryRequest, detail string) *QueryError {
	var err = NewQueryError(qr, MSG_QUERY_INVALID_FROM_CLAUSE, detail)
	return err
}

func NewQuerySelectClauseError(qr *QueryRequest, detail string) *QueryError {
	var err = NewQueryError(qr, MSG_QUERY_INVALID_SELECT_CLAUSE, detail)
	return err
}

func NewQueryWhereClauseError(qr *QueryRequest, detail string) *QueryError {
	var err = NewQueryError(qr, MSG_QUERY_INVALID_WHERE_CLAUSE, detail)
	return err
}

// QueryError error interface
func (err QueryError) Error() string {
	// TODO: use a string buffer to build error message
	var detail string
	if err.detail != "" {
		// TODO: use ERR_FORMAT_DETAIL_SEP instead of hardcoded one
		//detail = fmt.Sprintf("%s%s", ERR_FORMAT_DETAIL_SEP, err.detail)
		detail = fmt.Sprintf("%s%s", ": ", err.detail)
	}
	formattedMessage := fmt.Sprintf("%s: %s%s", err.Type, err.Message, detail)

	// NOTE: the QueryRequest has a custom String() interface to self format
	if err.request != nil {
		formattedMessage = fmt.Sprintf("%s\n%s", formattedMessage, err.request)
	}
	return formattedMessage
}

// query JSON map and return selected subset
// SELECT
//
//	<key.1>, <key.2>, ... // "firstname, lastname, email" || * (default)
//
// FROM
//
//	<key path>            // "product.customers"
//
// WHERE
//
//	<key.X> == <value>    // "country='Germany'"
//
// ORDER BY
//
//	<key.N>               // "lastname"
//
// e.g.,SELECT * FROM product.customers WHERE country="Germany";
type QueryRequest struct {
	SelectFieldsRaw     string
	SelectFields        []string
	FromObjectsRaw      string
	FromObjectSelectors []string
	WhereValuesRaw      string
	whereExpressions    []string
	WhereFilters        []WhereFilter
	OrderByKeysRaw      string
	//orderByKeys       []string // TODO
	IsFromObjectAMap    bool
	IsFromObjectAnArray bool
}

// Implement the Stringer interface for QueryRequest
func (qr *QueryRequest) String() string {
	sb := new(strings.Builder)
	sb.WriteString(fmt.Sprintf("--select: %s\n", qr.SelectFieldsRaw))
	sb.WriteString(fmt.Sprintf("--from: %s\n", qr.FromObjectsRaw))
	sb.WriteString(fmt.Sprintf("--where: %s\n", qr.WhereValuesRaw))
	sb.WriteString(fmt.Sprintf("--orderby: %s\n", qr.OrderByKeysRaw))
	return sb.String()
}

func NewQueryRequestParseRaw(rawSelect string, rawFrom string, rawWhere string) (qr *QueryRequest, err error) {
	qr = new(QueryRequest)
	qr.SelectFieldsRaw = rawSelect
	qr.FromObjectsRaw = rawFrom
	qr.WhereValuesRaw = rawWhere
	err = qr.ParseQueryClauses()
	return
}

func (qr *QueryRequest) ParseQueryClauses() (err error) {

	// parse out path (selectors) to JSON object from raw '--from' flag's value
	if qr.FromObjectsRaw != "" {
		qr.FromObjectSelectors = strings.Split(qr.FromObjectsRaw, QUERY_FROM_CLAUSE_SEP)
		//getLogger().Tracef("FROM json object (path): %v\n", qr.fromObjectSelectors)
	}

	// parse out field (keys) from raw '--select' flag's value
	if qr.SelectFieldsRaw != "" {
		qr.SelectFields = strings.Split(qr.SelectFieldsRaw, QUERY_SELECT_CLAUSE_SEP)
		//getLogger().Tracef("SELECT keys (fields): %v\n", qr.selectFields)
	}

	// parse out `key=<regex>` filters from raw `-where` flag's value
	if qr.WhereValuesRaw != "" {
		qr.whereExpressions = strings.Split(qr.WhereValuesRaw, QUERY_WHERE_EXPRESSION_SEP)
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

	if len(qr.whereExpressions) == 0 {
		return NewQueryWhereClauseError(qr, qr.WhereValuesRaw)
	}

	var filter *WhereFilter
	for _, clause := range qr.whereExpressions {

		filter = ParseWhereFilter(clause)

		if filter == nil {
			err = NewQueryWhereClauseError(qr, clause)
			return
		}

		qr.WhereFilters = append(qr.WhereFilters, *filter)
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
