// Copyright (c) 2017 Uber Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package log

import (
	"encoding/base64"
	"encoding/binary"
	"math"
	"time"

	"go.opencensus.io/trace"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Logger is a logger that knows about tracing spans
type Logger struct {
	logger *zap.Logger
	span   *trace.Span
}

// New Logger
func New(logger *zap.Logger, span *trace.Span) *Logger {
	stx := span.SpanContext()
	traceID := binary.BigEndian.Uint64(stx.TraceID[8:])
	spanID := binary.BigEndian.Uint64(stx.SpanID[:])

	return &Logger{
		logger: logger.
			WithOptions(zap.AddCallerSkip(1)).
			With(zap.Uint64("dd.trace_id", traceID), zap.Uint64("dd.span_id", spanID)),
		span: span,
	}
}

// Debug messages
func (sl Logger) Debug(msg string, fields ...zapcore.Field) {
	sl.logToSpan("debug", msg, fields...)
	sl.logger.Debug(msg, fields...)
}

// Info messages
func (sl Logger) Info(msg string, fields ...zapcore.Field) {
	sl.logToSpan("info", msg, fields...)
	sl.logger.Info(msg, fields...)
}

// Warn messages
func (sl Logger) Warn(msg string, fields ...zapcore.Field) {
	sl.logToSpan("warn", msg, fields...)
	sl.logger.Warn(msg, fields...)
}

// Error messages
func (sl Logger) Error(msg string, fields ...zapcore.Field) {
	sl.logToSpan("error", msg, fields...)
	sl.logger.Error(msg, fields...)
}

// Fatal messages
func (sl Logger) Fatal(msg string, fields ...zapcore.Field) {
	sl.logToSpan("fatal", msg, fields...)

	sl.logger.Fatal(msg, fields...)
}

func (sl Logger) logToSpan(level string, msg string, fields ...zapcore.Field) {
	if sl.span == nil {
		return
	}
	fa := fieldAdapter(make([]trace.Attribute, 0, 1+len(fields)))
	fa = append(fa, trace.StringAttribute("level", level))
	for _, field := range fields {
		field.AddTo(&fa)
	}
	sl.span.Annotate(fa, msg)
	sl.span.AddAttributes(fa...)
}

type fieldAdapter []trace.Attribute

func (fa *fieldAdapter) AddBool(key string, value bool) {
	*fa = append(*fa, trace.BoolAttribute(key, value))
}

func (fa *fieldAdapter) AddFloat64(key string, value float64) {
	*fa = append(*fa, trace.Int64Attribute(key, int64(math.Float64bits(value))))
}

func (fa *fieldAdapter) AddFloat32(key string, value float32) {
	*fa = append(*fa, trace.Int64Attribute(key, int64(math.Float64bits(float64(value)))))
}

func (fa *fieldAdapter) AddInt(key string, value int) {
	*fa = append(*fa, trace.Int64Attribute(key, int64(value)))
}

func (fa *fieldAdapter) AddInt64(key string, value int64) {
	*fa = append(*fa, trace.Int64Attribute(key, value))
}

func (fa *fieldAdapter) AddInt32(key string, value int32) {
	*fa = append(*fa, trace.Int64Attribute(key, int64(value)))
}

func (fa *fieldAdapter) AddInt16(key string, value int16) {
	*fa = append(*fa, trace.Int64Attribute(key, int64(value)))
}

func (fa *fieldAdapter) AddInt8(key string, value int8) {
	*fa = append(*fa, trace.Int64Attribute(key, int64(value)))
}

func (fa *fieldAdapter) AddUint(key string, value uint) {
	*fa = append(*fa, trace.Int64Attribute(key, int64(value)))
}

func (fa *fieldAdapter) AddUint64(key string, value uint64) {
	*fa = append(*fa, trace.Int64Attribute(key, int64(value)))
}

func (fa *fieldAdapter) AddUint32(key string, value uint32) {
	*fa = append(*fa, trace.Int64Attribute(key, int64(value)))
}

func (fa *fieldAdapter) AddUint16(key string, value uint16) {
	*fa = append(*fa, trace.Int64Attribute(key, int64(value)))
}

func (fa *fieldAdapter) AddUint8(key string, value uint8) {
	*fa = append(*fa, trace.Int64Attribute(key, int64(value)))
}

func (fa *fieldAdapter) AddUintptr(key string, value uintptr)                        {}
func (fa *fieldAdapter) AddArray(key string, marshaler zapcore.ArrayMarshaler) error { return nil }
func (fa *fieldAdapter) AddComplex128(key string, value complex128)                  {}
func (fa *fieldAdapter) AddComplex64(key string, value complex64)                    {}
func (fa *fieldAdapter) AddObject(key string, value zapcore.ObjectMarshaler) error   { return nil }
func (fa *fieldAdapter) AddReflected(key string, value interface{}) error            { return nil }
func (fa *fieldAdapter) OpenNamespace(key string)                                    {}

func (fa *fieldAdapter) AddDuration(key string, value time.Duration) {
	*fa = append(*fa, trace.StringAttribute(key, value.String()))
}

func (fa *fieldAdapter) AddTime(key string, value time.Time) {
	*fa = append(*fa, trace.StringAttribute(key, value.String()))
}

func (fa *fieldAdapter) AddBinary(key string, value []byte) {
	*fa = append(*fa, trace.StringAttribute(key, base64.StdEncoding.EncodeToString(value)))
}

func (fa *fieldAdapter) AddByteString(key string, value []byte) {
	*fa = append(*fa, trace.StringAttribute(key, string(value)))
}

func (fa *fieldAdapter) AddString(key, value string) {
	if key != "" && value != "" {
		*fa = append(*fa, trace.StringAttribute(key, value))
	}
}
