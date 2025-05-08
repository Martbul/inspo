package server

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type LoggingFormat int8

const (
	JSONFormat LoggingFormat = iota - 1
	StackdriverFormat
)

func NewJSONLogger(output *os.File, level zapcore.Level, format LoggingFormat) *zap.Logger {
	jsonEncoder := newJSONEncoder(format)

	core := zapcore.NewCore(jsonEncoder, zapcore.Lock(output), level)
	outputs := []zap.Option{zap.AddCaller()}
	return zap.New(core, outputs...)
}

// Create a new JSON log encoder with the correct settings.
func newJSONEncoder(format LoggingFormat) zapcore.Encoder {
	if format == StackdriverFormat {
		return zapcore.NewJSONEncoder(zapcore.EncoderConfig{
			TimeKey:        "time",
			LevelKey:       "severity",
			NameKey:        "logger",
			CallerKey:      "caller",
			MessageKey:     "message",
			StacktraceKey:  "stacktrace",
			EncodeLevel:    StackdriverLevelEncoder,
			EncodeTime:     zapcore.RFC3339NanoTimeEncoder,
			EncodeDuration: zapcore.StringDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		})
	}

	return zapcore.NewJSONEncoder(zapcore.EncoderConfig{
		TimeKey:        "ts",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		EncodeLevel:    zapcore.LowercaseLevelEncoder,
		EncodeTime:     zapcore.ISO8601TimeEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
		EncodeCaller:   zapcore.ShortCallerEncoder,
	})
}

func StackdriverLevelEncoder(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
	switch l {
	case zapcore.DebugLevel:
		enc.AppendString("DEBUG")
	case zapcore.InfoLevel:
		enc.AppendString("INFO")
	case zapcore.WarnLevel:
		enc.AppendString("WARNING")
	case zapcore.ErrorLevel:
		enc.AppendString("ERROR")
	case zapcore.DPanicLevel:
		enc.AppendString("CRITICAL")
	case zapcore.PanicLevel:
		enc.AppendString("CRITICAL")
	case zapcore.FatalLevel:
		enc.AppendString("CRITICAL")
	default:
		enc.AppendString("DEFAULT")
	}
}
