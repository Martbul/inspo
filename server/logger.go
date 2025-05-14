package server

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

type LoggingFormat int8

const (
	JSONFormat LoggingFormat = iota - 1
	StackdriverFormat
)

func SetupLogging(tmpLogger *zap.Logger, config Config) (*zap.Logger, *zap.Logger) {
	zapLevel := zapcore.InfoLevel
	switch strings.ToLower(config.GetLogger().Level) {
	case "debug":
		zapLevel = zapcore.DebugLevel
	case "info":
		zapLevel = zapcore.InfoLevel
	case "warn":
		zapLevel = zapcore.WarnLevel
	case "error":
		zapLevel = zapcore.ErrorLevel
	default:
		tmpLogger.Fatal("Logger level invalid, must be one of: DEBUG, INFO, WARN, or ERROR")
	}

	format := JSONFormat
	switch strings.ToLower(config.GetLogger().Format) {
	case "", "json":
		format = JSONFormat
	case "stackdriver":
		format = StackdriverFormat
	default:
		tmpLogger.Fatal("Logger mode invalid, must be one of: '', 'json', or 'stackdriver")
	}

	consoleLogger := NewJSONLogger(os.Stdout, zapLevel, format)
	var fileLogger *zap.Logger
	if config.GetLogger().Rotation {
		fileLogger = NewRotatingJSONFileLogger(consoleLogger, config, zapLevel, format)
	} else {
		fileLogger = NewJSONFileLogger(consoleLogger, config.GetLogger().File, zapLevel, format)
	}

	if fileLogger != nil {
		multiLogger := NewMultiLogger(consoleLogger, fileLogger)

		if config.GetLogger().Stdout {
			RedirectStdLog(multiLogger)
			return multiLogger, multiLogger
		}
		RedirectStdLog(fileLogger)
		return fileLogger, multiLogger
	}

	RedirectStdLog(consoleLogger)
	return consoleLogger, consoleLogger

}

func NewMultiLogger(loggers ...*zap.Logger) *zap.Logger {
	cores := make([]zapcore.Core, 0, len(loggers))
	for _, logger := range loggers {
		cores = append(cores, logger.Core())
	}

	teeCore := zapcore.NewTee(cores...)
	options := []zap.Option{zap.AddCaller()}
	return zap.New(teeCore, options...)
}

type RedirectStdLogWriter struct {
	logger *zap.Logger
}

func (r *RedirectStdLogWriter) Write(p []byte) (int, error) {
	s := string(bytes.TrimSpace(p))
	if strings.HasPrefix(s, "http: panic serving") {
		r.logger.Error(s)
	} else {
		r.logger.Info(s)
	}
	return len(s), nil
}

func RedirectStdLog(logger *zap.Logger) {
	log.SetFlags(0)
	log.SetPrefix("")
	skipLogger := logger.WithOptions(zap.AddCallerSkip(3))
	log.SetOutput(&RedirectStdLogWriter{skipLogger})
}

type grpcCustomLogger struct {
	*zap.SugaredLogger
}

func NewJSONFileLogger(consoleLogger *zap.Logger, fileName string, level zapcore.Level, format LoggingFormat) *zap.Logger {
	if len(fileName) == 0 {
		return nil
	}

	output, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		consoleLogger.Fatal("Could not create log file", zap.Error(err))
		return nil
	}

	return NewJSONLogger(output, level, format)
}

func NewRotatingJSONFileLogger(consoleLogger *zap.Logger, config Config, level zapcore.Level, format LoggingFormat) *zap.Logger {
	fileName := config.GetLogger().File
	if len(fileName) == 0 {
		consoleLogger.Fatal("rotating log file is enabled but log file name is empty")
		return nil
	}

	logDir := filepath.Dir(fileName)
	if _, err := os.Stat(logDir); os.IsNotExist(err) {
		if err := os.MkdirAll(logDir, 0755); err != nil {
			consoleLogger.Fatal("could not create log dir", zap.Error(err))
			return nil
		}
	}

	jsonEncoder := newJSONEncoder(format)

	// lumberjack.Logger is already safe for concurrent use, so we don't need to lock it.
	writeSyncer := zapcore.AddSync(&lumberjack.Logger{
		Filename:   fileName,
		MaxSize:    config.GetLogger().MaxSize,
		MaxAge:     config.GetLogger().MaxAge,
		MaxBackups: config.GetLogger().MaxBackups,
		LocalTime:  config.GetLogger().LocalTime,
		Compress:   config.GetLogger().Compress,
	})
	core := zapcore.NewCore(jsonEncoder, writeSyncer, level)
	options := []zap.Option{zap.AddCaller()}
	return zap.New(core, options...)
}

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
