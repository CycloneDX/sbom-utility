// SPDX-License-Identifier: Apache-2.0
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common

import "fmt"

// ------------------------------------------------
// Query error type
// ------------------------------------------------

// Query error messages
const (
	ERR_TYPE_INVALID_QUERY            = "invalid query"
	MSG_QUERY_INVALID_FROM_CLAUSE     = "invalid FROM clause"
	MSG_QUERY_INVALID_SELECT_CLAUSE   = "invalid SELECT clause"
	MSG_QUERY_INVALID_WHERE_CLAUSE    = "invalid WHERE clause"
	MSG_QUERY_INVALID_ORDER_BY_CLAUSE = "invalid ORDERBY clause"
	MSG_QUERY_INVALID_REQUEST         = "invalid query request"
	MSG_QUERY_INVALID_RESPONSE        = "invalid query response"
	MSG_QUERY_INVALID_DATATYPE        = "invalid result data type"
)

// Query error formatting
const (
	ERR_FORMAT_DETAIL_SEP = ": "
)

type QueryError struct {
	Type    string
	Message string
	request *QueryRequest
	detail  string
}

type QueryResultInvalidTypeError struct {
	QueryError
}

func NewQueryError(qr *QueryRequest, m string, d string) *QueryError {
	var err = new(QueryError)
	err.Type = ERR_TYPE_INVALID_QUERY
	err.request = qr
	err.Message = m
	err.detail = d
	return err
}

func NewQueryResultInvalidTypeError(qr *QueryRequest, value interface{}) (err *QueryResultInvalidTypeError) {
	err = new(QueryResultInvalidTypeError)
	err.Type = ERR_TYPE_INVALID_QUERY
	err.request = qr
	err.Message = MSG_QUERY_INVALID_DATATYPE
	err.detail = fmt.Sprintf("value: %v (%T)", value, value)
	return err
}

func NewQueryFromClauseError(qr *QueryRequest, detail string) *QueryError {
	var err = NewQueryError(qr, MSG_QUERY_INVALID_FROM_CLAUSE, detail)
	return err
}

func NewQueryFromUnexpectedTypeError(qr *QueryRequest, detail string) *QueryError {
	var err = NewQueryError(qr, MSG_QUERY_INVALID_FROM_CLAUSE, MSG_QUERY_INVALID_DATATYPE)
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
		detail = fmt.Sprintf("%s%s", ERR_FORMAT_DETAIL_SEP, err.detail)
	}
	formattedMessage := fmt.Sprintf("%s: %s%s", err.Type, err.Message, detail)

	// NOTE: the QueryRequest has a custom String() interface to self format
	if err.request != nil {
		formattedMessage = fmt.Sprintf("%s\n%s", formattedMessage, err.request)
	}
	return formattedMessage
}
