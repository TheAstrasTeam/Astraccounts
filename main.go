package main

import (
	"log/slog"

	"Astraccounts/logger"
)

func main() {
	logger.Init(&logger.Options{
		Level: slog.LevelDebug,
	})

	logger.Info("Hello, world!")
}
