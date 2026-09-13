package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"Astraccounts/auth"
	"Astraccounts/logger"
	"Astraccounts/mail"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

// defaultTokenValidSecs is used when TOKEN_VALID_SECS is not set.
const defaultTokenValidSecs = 3600

func main() {
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		logger.Init(&logger.Options{Level: slog.LevelDebug})
		logger.Warn("Unable to load .env file", "err", err)
	} else {
		logger.Init(&logger.Options{Level: slog.LevelDebug})
	}

	configureGinMode()
	dataDir := "data"
	store := auth.NewUserStore(filepath.Join(dataDir, "user"))
	issuer, err := tokenIssuerFromEnv()
	if err != nil {
		logger.Error("Invalid token configuration", "err", err)
		return
	}

	schema, err := auth.ParseProfileSchema(os.Getenv("ALLOWED_PROFILE_KEY"))
	if err != nil {
		logger.Error("Invalid ALLOWED_PROFILE_KEY configuration", "err", err)
		return
	}
	logger.Info("Profile schema loaded", "keys", schema.Len())

	mailConfig, err := mail.ConfigFromEnv()
	if err != nil {
		logger.Error("Invalid mail configuration", "err", err)
		return
	}
	mailServer, err := startMail(mailConfig, store, dataDir)
	if err != nil {
		logger.Error("Mail server failed to start", "err", err)
		return
	}

	r := gin.New()
	r.Use(logger.GinLogger(), logger.GinRecovery())
	if err := configureTrustedProxies(r); err != nil {
		logger.Error("Invalid GIN_TRUSTED_PROXIES configuration", "err", err)
		return
	}

	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": 200})
	})
	r.POST("/api/register", auth.RegisterHandler(store, mailConfig.Domain))
	r.POST("/api/login", auth.LoginHandler(store, issuer))
	r.POST("/api/login/totp", auth.TotpLoginHandler(store, issuer))
	r.POST("/api/login/recovery_code", auth.RecoveryCodeLoginHandler(store, issuer))
	r.POST("/api/totp/sign", auth.TotpSignHandler(store))
	r.POST("/api/totp/verify", auth.TotpVerifyHandler(store))
	r.POST("/api/totp/unsign", auth.TotpUnsignHandler(store))
	r.POST("/api/profile/edit", auth.ProfileEditHandler(store, issuer, schema))
	r.POST("/api/profile/view", auth.ProfileViewHandler(store, issuer, schema))

	serve(r, mailServer)
}

// serve runs the HTTP server until it fails or the process is asked to stop,
// then shuts the HTTP and mail servers down in an orderly fashion.
func serve(handler *gin.Engine, mailServer *mail.Server) {
	httpServer := &http.Server{Addr: ":8080", Handler: handler}

	failed := make(chan error, 1)
	go func() {
		logger.Info("HTTP server starting", "addr", ":8080")
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			failed <- err
			return
		}
		failed <- nil
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-failed:
		if err != nil {
			logger.Error("HTTP server stopped", "err", err)
		}
	case received := <-signals:
		logger.Info("Shutdown requested", "signal", received.String())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpServer.Shutdown(ctx); err != nil {
		logger.Error("HTTP server shutdown failed", "err", err)
	}
	if mailServer != nil {
		if err := mailServer.Shutdown(ctx); err != nil {
			logger.Error("Mail server shutdown failed", "err", err)
		}
	}
}

// startMail brings up the SMTP, POP3 and IMAP listeners. Mail is opt-in: with
// no MAIL_DOMAIN configured the service runs exactly as it did before.
func startMail(config *mail.Config, store *auth.UserStore, dataDir string) (*mail.Server, error) {
	if !config.Enabled() {
		logger.Info("Mail server disabled, set MAIL_DOMAIN to enable it")
		return nil, nil
	}

	server, err := mail.New(config, store, dataDir)
	if err != nil {
		return nil, err
	}
	if err := server.Start(); err != nil {
		return nil, err
	}
	return server, nil
}

// tokenIssuerFromEnv builds the login token issuer from TOKEN_VALID_SECS and
// TOKEN_SECRET.
func tokenIssuerFromEnv() (*auth.TokenIssuer, error) {
	validSecs := int64(defaultTokenValidSecs)
	if raw := strings.TrimSpace(os.Getenv("TOKEN_VALID_SECS")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed <= 0 {
			return nil, fmt.Errorf("TOKEN_VALID_SECS must be a positive integer, got %q", raw)
		}
		validSecs = parsed
	}

	secret := []byte(os.Getenv("TOKEN_SECRET"))
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
		logger.Warn("TOKEN_SECRET is not set, generated a random one; tokens stop working after a restart")
	}

	logger.Info("Login tokens configured", "valid_secs", validSecs)
	return auth.NewTokenIssuer(secret, validSecs), nil
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
