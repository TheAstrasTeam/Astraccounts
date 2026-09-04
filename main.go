package main

import (
	"log/slog"

	"Astraccounts/logger"
	"github.com/gin-gonic/gin"
)

func main() {
	logger.Init(&logger.Options{
		Level: slog.LevelDebug,
	})

	r := gin.New()
	r.Use(logger.GinLogger(), logger.GinRecovery())

	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": 200})
	})

	logger.Info("HTTP server starting", "addr", ":8080")
	if err := r.Run(":8080"); err != nil {
		logger.Error("HTTP server stopped", "err", err)
	}
}
