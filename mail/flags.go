package mail

import "strings"

// IMAP system flags used across the mail server. They are declared here rather
// than taken from go-imap so the store and the POP3 server do not depend on the
// IMAP library.
const (
	FlagSeen     = "\\Seen"
	FlagAnswered = "\\Answered"
	FlagFlagged  = "\\Flagged"
	FlagDeleted  = "\\Deleted"
	FlagDraft    = "\\Draft"
)

// FlagOp selects how SetFlags combines the given flags with the stored ones.
type FlagOp int

const (
	// FlagsSet replaces the stored flags.
	FlagsSet FlagOp = iota
	// FlagsAdd adds flags that are not present yet.
	FlagsAdd
	// FlagsRemove removes the given flags.
	FlagsRemove
)

func hasFlag(flags []string, want string) bool {
	for _, flag := range flags {
		if strings.EqualFold(flag, want) {
			return true
		}
	}
	return false
}

// normaliseFlags drops duplicates and \Recent, which this server does not
// track, and guarantees a non-nil slice so index.json never holds a JSON null.
func normaliseFlags(flags []string) []string {
	out := make([]string, 0, len(flags))
	for _, flag := range flags {
		if flag == "" || strings.EqualFold(flag, "\\Recent") {
			continue
		}
		if !hasFlag(out, flag) {
			out = append(out, flag)
		}
	}
	return out
}

func applyFlags(current, flags []string, op FlagOp) []string {
	switch op {
	case FlagsSet:
		return normaliseFlags(flags)
	case FlagsAdd:
		return normaliseFlags(append(append([]string(nil), current...), flags...))
	case FlagsRemove:
		kept := make([]string, 0, len(current))
		for _, flag := range current {
			if !hasFlag(flags, flag) {
				kept = append(kept, flag)
			}
		}
		return kept
	default:
		return current
	}
}
