package logger

import (
	"fmt"
	"runtime/debug"
	"time"

	"github.com/gin-gonic/gin"
)

// GinLogger writes one structured request log through the project's logger.
func GinLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		status := c.Writer.Status()
		level := Info
		if status >= 500 {
			level = Error
		} else if status >= 400 {
			level = Warn
		}

		args := []any{
			"method", c.Request.Method,
			"path", c.Request.URL.Path,
			"status", status,
			"latency", time.Since(start).String(),
			"client_ip", c.ClientIP(),
		}
		if rawQuery := c.Request.URL.RawQuery; rawQuery != "" {
			args = append(args, "query", rawQuery)
		}
		if len(c.Errors) > 0 {
			args = append(args, "errors", c.Errors.String())
		}

		level("HTTP request", args...)
	}
}

// GinRecovery reports panics through the project's logger before returning 500.
func GinRecovery() gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if recovered := recover(); recovered != nil {
				Error("HTTP panic recovered", "err", fmt.Sprint(recovered), "stack", string(debug.Stack()))
				c.AbortWithStatus(500)
			}
		}()

		c.Next()
	}
}
