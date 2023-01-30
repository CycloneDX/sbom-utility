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

package log

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/fatih/color"
)

type Level int

// Skip 2 on call stack
// i.e., skip public (Caller) method (e.g., "Trace()" and internal
// "dumpInterface()" function
const (
	STACK_SKIP int  = 2
	MAX_INDENT uint = 8
)

// WARNING: some functional logic may assume incremental ordering of levels
const (
	ERROR   Level = iota // 0 - Always output errors (stop execution)
	WARNING              // 1 - Always output warnings (continue executing)
	INFO                 // 2 - General processing information (processing milestones)
	TRACE                // 3 - In addition to INFO, output functional info. (signature, parameter)
	DEBUG                // 4 - In addition to TRACE, output internal logic and intra-functional data
)

// Assure default ENTER and EXIT default tags have same fixed-length chars.
// for better output alignment
const (
	DEFAULT_ENTER_TAG = "ENTER"
	DEFAULT_EXIT_TAG  = "EXIT "
)

// TODO: Allow colorization to be a configurable option.
// on (default): for human-readable targets (e.g., console);
// off: for (remote) logging targets (file, network) stream
// See colors here: https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
var LevelNames = map[Level]string{
	DEBUG:   color.GreenString("DEBUG"),
	TRACE:   color.CyanString("TRACE"),
	INFO:    color.WhiteString("INFO"),
	WARNING: color.HiYellowString("WARN"),
	ERROR:   color.HiRedString("ERROR"),
}

var DEFAULT_LEVEL = INFO
var DEFAULT_INDENT_RUNE = []rune("")
var DEFAULT_INCREMENT_RUNE = []rune("")

// TODO: allow timestamps to be turned on/off regardless of defaults
// TODO: allow colors to be set for each constituent part of the (TRACE) output
// TODO: allow multiple tags (with diff. colors) that can be enabled/disabled from the calling code
type MiniLogger struct {
	logLevel        Level
	indentEnabled   bool
	indentRunes     []rune
	spacesIncrement []rune
	tagEnter        string
	tagExit         string
	tagColor        *color.Color
	quietMode       bool
	outputFile      io.Writer
	outputWriter    *bufio.Writer
	maxStrLength    int
}

func NewDefaultLogger() *MiniLogger {
	logger := &MiniLogger{
		logLevel:        DEFAULT_LEVEL,
		indentEnabled:   false,
		indentRunes:     DEFAULT_INDENT_RUNE,
		spacesIncrement: DEFAULT_INCREMENT_RUNE,
		tagEnter:        DEFAULT_ENTER_TAG,
		tagExit:         DEFAULT_EXIT_TAG,
		tagColor:        color.New(color.FgMagenta),
		outputFile:      os.Stdout,
		maxStrLength:    64,
	}

	// TODO: Use this instead of fmt.Print() variant functions
	logger.outputWriter = bufio.NewWriter(logger.outputFile)

	return logger
}

func NewLogger(level Level) *MiniLogger {
	newLogger := NewDefaultLogger()
	newLogger.SetLevel(level)

	return newLogger
}

func (log *MiniLogger) EnableIndent(enable bool) {
	log.indentEnabled = enable
}

func (log *MiniLogger) SetLevel(level Level) {
	log.logLevel = level
}

func (log *MiniLogger) GetLevel() Level {
	return log.logLevel
}

func (log *MiniLogger) SetQuietMode(on bool) {
	log.quietMode = on
}

func (log *MiniLogger) QuietModeOn() bool {
	return log.quietMode
}

func (log *MiniLogger) GetLevelName() string {
	return LevelNames[log.logLevel]
}

// Helper method to check for and set typical log-related flags
// NOTE: Assumes these do not collide with existing flags set by importing application
// NOTE: "go test" utilizes the Go "flags" package and allows
// test packages to declare additional command line arguments
// which can be used to set log/trace levels (e.g., `--args --trace).
// The values for these variables are only avail. after init() processing is completed.
// See: https://go.dev/doc/go1.13#testing
// "Testing flags are now registered in the new Init function, which is invoked by the
// generated main function for the test. As a result, testing flags are now only registered
// when running a test binary, and packages that call flag.Parse during package initialization
// may cause tests to fail."
func (log *MiniLogger) InitLogLevelAndModeFromFlags() Level {

	// NOTE: Uncomment to debug avail. args. during init.
	// log.DumpArgs()

	// Check for log-related flags (anywhere) and apply to logger
	// as early as possible (before customary Cobra flag formalization)
	// NOTE: the last log-level flag found, in order of appearance "wins"
	// NOTE: Always use the `--args` flag of `go test` as this will assure non-conflict
	// with built-in flags.
	// NOTE: flags MUST be defined within the "test" package or `go test` will error
	// e.g., var TestLogLevelError = flag.Bool("error", false, "")
	for _, arg := range os.Args[1:] {
		switch {
		case arg == "-q" || arg == "-quiet" || arg == "--quiet" || arg == "quiet":
			log.SetQuietMode(true)
		case arg == "-t" || arg == "-trace" || arg == "--trace" || arg == "trace":
			log.SetLevel(TRACE)
		case arg == "-d" || arg == "-debug" || arg == "--debug" || arg == "debug":
			log.SetLevel(DEBUG)
		case arg == "--indent":
			log.EnableIndent(true)
		}
	}

	return log.GetLevel()
}

func (log *MiniLogger) Flush() (err error) {
	if log.outputWriter != nil {
		err = log.outputWriter.Flush()
	}
	return
}

func (log MiniLogger) Trace(value interface{}) {
	log.dumpInterface(TRACE, "", value, STACK_SKIP)
}

func (log MiniLogger) Tracef(format string, value ...interface{}) {
	message := fmt.Sprintf(format, value...)
	log.dumpInterface(TRACE, "", message, STACK_SKIP)
}

func (log MiniLogger) Debug(value interface{}) {
	log.dumpInterface(DEBUG, "", value, STACK_SKIP)
}

func (log MiniLogger) Debugf(format string, value ...interface{}) {
	message := fmt.Sprintf(format, value...)
	log.dumpInterface(DEBUG, "", message, STACK_SKIP)
}

func (log MiniLogger) Info(value interface{}) {
	log.dumpInterface(INFO, "", value, STACK_SKIP)
}

func (log MiniLogger) Infof(format string, value ...interface{}) {
	message := fmt.Sprintf(format, value...)
	log.dumpInterface(INFO, "", message, STACK_SKIP)
}

func (log MiniLogger) Warning(value interface{}) {
	log.dumpInterface(WARNING, "", value, STACK_SKIP)
}

func (log MiniLogger) Warningf(format string, value ...interface{}) {
	message := fmt.Sprintf(format, value...)
	log.dumpInterface(WARNING, "", message, STACK_SKIP)
}

// TODO: use fmt.fError in some manner and/or os.Stderr
func (log MiniLogger) Error(value interface{}) {
	log.dumpInterface(ERROR, "", value, STACK_SKIP)
}

func (log MiniLogger) Errorf(format string, value ...interface{}) error {
	err := fmt.Errorf(format, value...)
	log.dumpInterface(ERROR, "", err, STACK_SKIP)
	return err
}

// Specialized function entry/exit trace
// Note: can pass in "args[]" or params as needed to have a single logging line
func (log *MiniLogger) Enter(values ...interface{}) {

	if log.logLevel >= TRACE {
		sb := bytes.NewBufferString("")
		if len(values) > 0 {
			sb.WriteByte('(')
			for index, value := range values {
				sb.WriteString(fmt.Sprintf("(%T):%+v", value, value))
				if (index + 1) < len(values) {
					sb.WriteString(", ")
				}

			}
			sb.WriteByte(')')
		}
		log.dumpInterface(TRACE, log.tagColor.Sprintf(log.tagEnter), sb.String(), STACK_SKIP)

		if log.indentEnabled {
			// increase stack indent
			log.indentRunes = append(log.indentRunes, ' ', ' ')
		}
	}
}

// exit and print returned values (typed)
// Note: can function "returns" as needed to have a single logging line
func (log *MiniLogger) Exit(values ...interface{}) {

	if log.logLevel >= TRACE {
		sb := bytes.NewBufferString("")
		if len(values) > 0 {
			sb.WriteByte('(')
			for index, value := range values {
				sb.WriteString(fmt.Sprintf("(%T): %+v", value, value))
				if (index + 1) < len(values) {
					sb.WriteString(", ")
				}
			}
			sb.WriteByte(')')
		}

		if log.indentEnabled {
			// decrease stack indent
			if length := len(log.indentRunes) - 2; length >= 0 {
				log.indentRunes = log.indentRunes[:len(log.indentRunes)-2]
			}
		}

		log.dumpInterface(TRACE, log.tagColor.Sprintf(log.tagExit), sb.String(), STACK_SKIP)
	}
}

// Note: currently, "dump" methods output directly to stdout (stderr)
// Note: we comment out any "self-logging" or 'debug" for performance for release builds
// compose log output using a "byte buffer" for performance
func (log MiniLogger) dumpInterface(lvl Level, tag string, value interface{}, skip int) {

	// Check for quiet mode enabled;
	// if so, suppress any logging that is not an error
	// Note: Quiet mode even means NO error output... that is, caller MUST
	// use application return code value to detect an error condition
	//fmt.Printf("Quiet mode: %t", log.quietMode)
	if log.quietMode {
		return
	}

	sb := bytes.NewBufferString("")

	// indent based upon current callstack (as incremented/decremented via Enter/Exit funcs.)
	if log.indentEnabled {
		sb.WriteString(string(log.indentRunes))
	}

	// Only (prepare to) output if intended log level is less than
	// the current globally set log level
	if lvl <= log.logLevel {
		// retrieve all the info we might need
		pc, fn, line, ok := runtime.Caller(skip)

		// TODO: Provide means to order component output;
		// for example, to add Timestamp component first (on each line) before Level
		if ok {
			// Setup "string builder" and initialize with log-level prefix
			sb.WriteString(fmt.Sprintf("[%s] ", LevelNames[lvl]))

			// Append UTC timestamp if level is TRACE or DEBUG
			if log.logLevel == TRACE || log.logLevel == DEBUG {
				// Append (optional) tag
				if tag != "" {
					sb.WriteString(fmt.Sprintf("[%s] ", tag))
				}

				// UTC time shows fractions of a second
				// TODO: add setting to show milli or micro seconds supported by "time" package
				tmp := time.Now().UTC().String()
				// create a (left) slice of the timestamp omitting the " +0000 UTC" portion
				//ts = fmt.Sprintf("[%s] ", tmp[:strings.Index(tmp, "+")-1])
				sb.WriteString(fmt.Sprintf("[%s] ", tmp[:strings.Index(tmp, "+")-1]))
			}

			// Append calling callstack/function information
			// for log levels used for developer problem determination
			if log.logLevel == TRACE || log.logLevel == DEBUG || log.logLevel == ERROR {

				// Append basic filename, line number, function name
				basicFile := fn[strings.LastIndex(fn, "/")+1:]
				sb.WriteString(fmt.Sprintf("%s(%d) ", basicFile, line))

				// TODO: add logger flag to show full module paths (not just module.function)\
				function := runtime.FuncForPC(pc)
				basicModFnName := function.Name()[strings.LastIndex(function.Name(), "/")+1:]
				sb.WriteString(fmt.Sprintf("%s() ", basicModFnName))
			}

			// Append (optional) value if supplied
			// Note: callers SHOULD resolve to string when possible to avoid empty output from interfaces
			if value != nil && value != "" {
				sb.WriteString(fmt.Sprintf("%+v", value))
			}

			// TODO: use a general output writer (set to stdout, stderr, or file stream)
			fmt.Println(sb.String())
		} else {
			os.Stderr.WriteString("Error: Unable to retrieve call stack. Exiting...")
			os.Exit(-2)
		}
	}
}

func (log MiniLogger) DumpString(value string) {
	fmt.Print(value)
}

func (log MiniLogger) DumpStruct(structName string, field interface{}) error {

	sb := bytes.NewBufferString("")
	formattedStruct, err := log.FormatStructE(field)

	if err != nil {
		return err
	}

	if structName != "" {
		sb.WriteString(fmt.Sprintf("`%s` (%T) = %s", structName, reflect.TypeOf(field), formattedStruct))
	} else {
		sb.WriteString(formattedStruct)
	}

	// TODO: print to output stream
	fmt.Println(sb.String())

	return nil
}

func (log MiniLogger) DumpArgs() {
	args := os.Args
	for i, a := range args {
		// TODO: print to output stream
		fmt.Print(log.indentRunes)
		fmt.Printf("os.Arg[%d]: `%v`\n", i, a)
	}
}

func (log MiniLogger) DumpSeparator(sep byte, repeat int) (string, error) {
	if repeat <= 80 {
		sb := bytes.NewBufferString("")
		for i := 0; i < repeat; i++ {
			sb.WriteByte(sep)
		}
		fmt.Println(sb.String())
		return sb.String(), nil
	} else {
		return "", errors.New("invalid repeat length (>80)")
	}
}

func (log *MiniLogger) DumpStackTrace() {
	fmt.Println(string(debug.Stack()))
}
