package logger

import (
	"fmt"
	"github.com/sirupsen/logrus"
	"time"
)

type BlueFormatter struct {
	logrus.TextFormatter
}

// NewBlueFormatter returns a pointer to a BlueFormatter with sane defaults.
func NewBlueFormatter() *BlueFormatter {
	return &BlueFormatter{
		TextFormatter: logrus.TextFormatter{
			ForceColors:     true,             // always output color codes
			FullTimestamp:   true,             // include full timestamp
			TimestampFormat: time.RFC3339Nano, // use RFC3339Nano format
		},
	}
}

// Format implements logrus.Formatter interface.
// It wraps the output of the embedded TextFormatter with ANSI color codes.
func (f *BlueFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	// first generate the base log line
	base, err := f.TextFormatter.Format(entry)
	if err != nil {
		return nil, err
	}

	// choose color based on level; you can adjust or extend this switch
	var code int
	switch entry.Level {
	case logrus.InfoLevel:
		code = 34 // blue
	case logrus.WarnLevel:
		code = 33 // yellow
	case logrus.ErrorLevel, logrus.FatalLevel, logrus.PanicLevel:
		code = 31 // red
	default:
		code = 37 // white/default
	}

	// wrap with ANSI escape sequences: \x1b[<code>m ... \x1b[0m resets
	return []byte(fmt.Sprintf("\x1b[%dm%s\x1b[0m", code, string(base))), nil
}
