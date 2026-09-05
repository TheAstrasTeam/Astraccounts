package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"Astraccounts/auth"
	"Astraccounts/logger"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		logger.Init(&logger.Options{Level: slog.LevelDebug})
		logger.Warn("Unable to load .env file", "err", err)
	} else {
		logger.Init(&logger.Options{Level: slog.LevelDebug})
	}

	configureGinMode()
	store := auth.NewUserStore(filepath.Join("data", "user"))

	r := gin.New()
	r.Use(logger.GinLogger(), logger.GinRecovery())
	if err := configureTrustedProxies(r); err != nil {
		logger.Error("Invalid GIN_TRUSTED_PROXIES configuration", "err", err)
		return
	}

	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": 200})
	})
	r.POST("/api/register", auth.RegisterHandler(store))
	r.POST("/api/login", auth.LoginHandler(store))

	logger.Info("HTTP server starting", "addr", ":8080")
	if err := r.Run(":8080"); err != nil {
		logger.Error("HTTP server stopped", "err", err)
	}
}

func configureGinMode() {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("GIN_MODE")))
	switch mode {
	case "", gin.DebugMode:
		gin.SetMode(gin.DebugMode)
	case gin.ReleaseMode:
		gin.SetMode(gin.ReleaseMode)
	case gin.TestMode:
		gin.SetMode(gin.TestMode)
	default:
		logger.Warn("Invalid GIN_MODE, using debug mode", "mode", mode)
		gin.SetMode(gin.DebugMode)
	}
}

func configureTrustedProxies(r *gin.Engine) error {
	value := strings.TrimSpace(os.Getenv("GIN_TRUSTED_PROXIES"))
	if value == "" {
		return r.SetTrustedProxies(nil)
	}

	proxies := make([]string, 0)
	for _, proxy := range strings.Split(value, ",") {
		proxy = strings.TrimSpace(proxy)
		if proxy != "" {
			proxies = append(proxies, proxy)
		}
	}
	return r.SetTrustedProxies(proxies)
}
