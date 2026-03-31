package proxy

import (
	"fmt"
	"io"

	"github.com/aws/session-manager-plugin/src/log"
)

type SSMDebugLogger struct {
	// Writers to write logging output to
	Writers []io.Writer
}

func (l *SSMDebugLogger) WithContext(context ...string) (contextLogger log.T) {
	msg := fmt.Sprint(context)
	for _, writer := range l.Writers {
		_, _ = writer.Write([]byte(msg))
	}
	return l
}
func (l *SSMDebugLogger) Close() {}
func (l *SSMDebugLogger) Critical(v ...interface{}) error {
	msg := fmt.Sprint(v...)
	for _, writer := range l.Writers {
		_, _ = writer.Write([]byte(msg))
	}
	return nil
}
func (l *SSMDebugLogger) Criticalf(format string, params ...interface{}) error {
	msg := fmt.Sprintf(format, params...)
	for _, writer := range l.Writers {
		_, _ = writer.Write([]byte(msg))
	}
	return nil
}
func (l *SSMDebugLogger) Debug(v ...interface{}) {
	msg := fmt.Sprint(v...)
	for _, writer := range l.Writers {
		_, _ = writer.Write([]byte(msg))
	}
}
func (l *SSMDebugLogger) Debugf(format string, params ...interface{}) {
	msg := fmt.Sprintf(format, params...)
	for _, writer := range l.Writers {
		_, _ = writer.Write([]byte(msg))
	}
}
func (l *SSMDebugLogger) Error(v ...interface{}) error {
	msg := fmt.Sprint(v...)
	for _, writer := range l.Writers {
		_, _ = writer.Write([]byte(msg))
	}
	return nil
}
func (l *SSMDebugLogger) Errorf(format string, params ...interface{}) error {
	msg := fmt.Sprintf(format, params...)
	for _, writer := range l.Writers {
		_, _ = writer.Write([]byte(msg))
	}
	return nil
}
func (l *SSMDebugLogger) Flush() {}
func (l *SSMDebugLogger) Info(v ...interface{}) {
	msg := fmt.Sprint(v...)
	for _, writer := range l.Writers {
		_, _ = writer.Write([]byte(msg))
	}
}
func (l *SSMDebugLogger) Infof(format string, params ...interface{}) {
	msg := fmt.Sprintf(format, params...)
	for _, writer := range l.Writers {
		_, _ = writer.Write([]byte(msg))
	}
}
func (l *SSMDebugLogger) Trace(v ...interface{}) {
	msg := fmt.Sprint(v...)
	for _, writer := range l.Writers {
		_, _ = writer.Write([]byte(msg))
	}
}
func (l *SSMDebugLogger) Tracef(format string, params ...interface{}) {
	msg := fmt.Sprintf(format, params...)
	for _, writer := range l.Writers {
		_, _ = writer.Write([]byte(msg))
	}
}
func (l *SSMDebugLogger) Warn(v ...interface{}) error {
	msg := fmt.Sprint(v...)
	for _, writer := range l.Writers {
		_, _ = writer.Write([]byte(msg))
	}
	return nil
}
func (l *SSMDebugLogger) Warnf(format string, params ...interface{}) error {
	msg := fmt.Sprintf(format, params...)
	for _, writer := range l.Writers {
		_, _ = writer.Write([]byte(msg))
	}
	return nil
}
