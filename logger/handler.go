package logger

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorGray   = "\033[37m"
)

type ColorConsoleHandler struct {
	opts  slog.HandlerOptions
	out   io.Writer
	mu    *sync.Mutex
	attrs []slog.Attr
	group string
}

func newColorConsoleHandler(out io.Writer, opts *slog.HandlerOptions) *ColorConsoleHandler {
	h := &ColorConsoleHandler{
		out: out,
		mu:  &sync.Mutex{},
	}
	if opts != nil {
		h.opts = *opts
	}
	return h
}

func (h *ColorConsoleHandler) Enabled(_ context.Context, level slog.Level) bool {
	minLevel := slog.LevelInfo
	if h.opts.Level != nil {
		minLevel = h.opts.Level.Level()
	}
	return level >= minLevel
}

func (h *ColorConsoleHandler) Handle(ctx context.Context, r slog.Record) error {
	levelColor := colorGray
	switch {
	case r.Level >= slog.LevelError:
		levelColor = colorRed
	case r.Level >= slog.LevelWarn:
		levelColor = colorYellow
	case r.Level >= slog.LevelInfo:
		levelColor = colorBlue
	}

	timeStr := r.Time.Format("2006-01-02 15:04:05")
	buf := fmt.Sprintf("%s[%s]%s %s[%s]%s %s%s%s",
		colorGray, timeStr, colorReset,
		levelColor, r.Level.String(), colorReset,
		levelColor, r.Message, colorReset)

	if traceID := FromTraceID(ctx); traceID != "" {
		buf += formatAttr(slog.String("trace_id", traceID))
	}

	for _, a := range h.attrs {
		buf += formatAttr(a)
	}

	r.Attrs(func(a slog.Attr) bool {
		key := a.Key
		if h.group != "" {
			key = h.group + "." + key
		}
		a.Key = key
		buf += formatAttr(a)
		return true
	})

	buf += "\n"

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := h.out.Write([]byte(buf))
	return err
}

func formatAttr(a slog.Attr) string {
	return fmt.Sprintf(" %s%s=%v%s", colorGray, a.Key, a.Value.Any(), colorReset)
}

func (h *ColorConsoleHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	newAttrs := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	newAttrs = append(newAttrs, h.attrs...)
	newAttrs = append(newAttrs, attrs...)

	return &ColorConsoleHandler{
		opts:  h.opts,
		out:   h.out,
		mu:    h.mu,
		attrs: newAttrs,
		group: h.group,
	}
}

func (h *ColorConsoleHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	newGroup := name
	if h.group != "" {
		newGroup = h.group + "." + name
	}

	return &ColorConsoleHandler{
		opts:  h.opts,
		out:   h.out,
		mu:    h.mu,
		attrs: h.attrs,
		group: newGroup,
	}
}
