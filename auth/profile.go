package auth

import (
	"errors"
	"fmt"
	"strings"

	"Astraccounts/logger"
	"github.com/gin-gonic/gin"
)

// errProfileDenied marks a missing user or a token that does not belong to the
// requested UID.
var errProfileDenied = errors.New("profile edit denied")

// profileValueType is the JSON type a profile key accepts.
type profileValueType string

const (
	profileTypeString profileValueType = "string"
	profileTypeNumber profileValueType = "number"
	profileTypeBool   profileValueType = "bool"
)

// Built-in profile keys. The server fills these in at registration time and
// they are always available regardless of ALLOWED_PROFILE_KEY.
const (
	// ProfileKeyUsername holds the display name and stays editable.
	ProfileKeyUsername = "username"
	// ProfileKeyRegister holds the registration timestamp and is immutable.
	ProfileKeyRegister = "register"
)

// profileField describes one allowed profile key.
type profileField struct {
	valueType profileValueType
	private   bool
	// immutable keys are written by the server and rejected in client edits.
	immutable bool
	// builtin keys cannot be redeclared or removed through configuration.
	builtin bool
}

// builtinFields are merged into every schema.
var builtinFields = map[string]profileField{
	ProfileKeyUsername: {valueType: profileTypeString, builtin: true},
	ProfileKeyRegister: {valueType: profileTypeNumber, immutable: true, builtin: true},
}

// ProfileSchema holds the profile keys a client is allowed to write, the type
// each key accepts, and whether the key is hidden from anonymous viewers.
type ProfileSchema struct {
	fields map[string]profileField
}

// ParseProfileSchema reads the ALLOWED_PROFILE_KEY specification.
//
// Format: comma separated entries of "name:type[:visibility]" where type is
// string, number or bool, and visibility is public (default) or private.
//
//	ALLOWED_PROFILE_KEY=bio:string,age:number,vip:bool,phone:string:private
//
// The built-in keys username and register are always present and must not be
// declared here.
func ParseProfileSchema(raw string) (*ProfileSchema, error) {
	schema := &ProfileSchema{fields: make(map[string]profileField, len(builtinFields))}
	for name, field := range builtinFields {
		schema.fields[name] = field
	}

	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		parts := strings.Split(entry, ":")
		if len(parts) < 2 || len(parts) > 3 {
			return nil, fmt.Errorf("entry %q must look like name:type[:visibility]", entry)
		}

		name := strings.TrimSpace(parts[0])
		if name == "" {
			return nil, fmt.Errorf("entry %q has an empty key name", entry)
		}
		if existing, exists := schema.fields[name]; exists {
			if existing.builtin {
				return nil, fmt.Errorf("key %q is built in and must not be declared", name)
			}
			return nil, fmt.Errorf("key %q is declared more than once", name)
		}

		field := profileField{}
		switch profileValueType(strings.ToLower(strings.TrimSpace(parts[1]))) {
		case profileTypeString:
			field.valueType = profileTypeString
		case profileTypeNumber:
			field.valueType = profileTypeNumber
		case profileTypeBool:
			field.valueType = profileTypeBool
		default:
			return nil, fmt.Errorf("key %q has unknown type %q, want string, number or bool", name, parts[1])
		}

		if len(parts) == 3 {
			switch strings.ToLower(strings.TrimSpace(parts[2])) {
			case "public":
			case "private":
				field.private = true
			default:
				return nil, fmt.Errorf("key %q has unknown visibility %q, want public or private", name, parts[2])
			}
		}

		schema.fields[name] = field
	}

	return schema, nil
}

// Len reports how many keys the schema allows.
func (s *ProfileSchema) Len() int {
	return len(s.fields)
}

// accepts reports whether a client may write key with value: the key must be
// allowed, must not be immutable, and value must match the declared type.
func (s *ProfileSchema) accepts(key string, value any) bool {
	field, ok := s.fields[key]
	if !ok || field.immutable {
		return false
	}

	switch field.valueType {
	case profileTypeString:
		_, ok = value.(string)
	case profileTypeNumber:
		// encoding/json decodes every JSON number into float64.
		_, ok = value.(float64)
	case profileTypeBool:
		_, ok = value.(bool)
	default:
		ok = false
	}
	return ok
}

// visible reports whether key may be shown to a viewer.
func (s *ProfileSchema) visible(key string, authenticated bool) bool {
	field, ok := s.fields[key]
	if !ok {
		// Keys dropped from the configuration stay hidden.
		return false
	}
	return authenticated || !field.private
}

// profileEntry is one requested change. Key is decoded as any so a non-string
// key can still be reported back to the client.
type profileEntry struct {
	Key   any `json:"key"`
	Value any `json:"value"`
}

type profileEditRequest struct {
	UID     int            `json:"UID"`
	Token   string         `json:"token"`
	Content []profileEntry `json:"content"`
}

type profileViewRequest struct {
	UID   int    `json:"UID"`
	Token string `json:"token"`
}

// ProfileEditHandler handles POST /api/profile/edit.
func ProfileEditHandler(store *UserStore, issuer *TokenIssuer, schema *ProfileSchema) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req profileEditRequest
		if c.ShouldBindJSON(&req) != nil {
			c.JSON(400, gin.H{"status": 400})
			return
		}

		// Collect every rejected key before touching the stored profile so a
		// failed request never writes a partial update.
		invalid := make([]any, 0, len(req.Content))
		updates := make(map[string]any, len(req.Content))
		for _, entry := range req.Content {
			key, ok := entry.Key.(string)
			if !ok || !schema.accepts(key, entry.Value) {
				invalid = append(invalid, entry.Key)
				continue
			}
			updates[key] = entry.Value
		}
		if len(invalid) > 0 {
			c.JSON(400, gin.H{"status": 400, "invalid": invalid})
			return
		}

		if err := store.updateProfile(req.UID, req.Token, issuer, updates); err != nil {
			if errors.Is(err, errProfileDenied) {
				c.JSON(400, gin.H{"status": 400})
				return
			}
			logger.Error("Failed to update profile", "err", err, "uid", req.UID)
			c.JSON(500, gin.H{"status": 500})
			return
		}
		c.JSON(200, gin.H{"status": 200})
	}
}

// ProfileViewHandler handles POST /api/profile/view. A valid token belonging to
// the requested UID also reveals the keys marked private.
func ProfileViewHandler(store *UserStore, issuer *TokenIssuer, schema *ProfileSchema) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req profileViewRequest
		if c.ShouldBindJSON(&req) != nil {
			c.JSON(400, gin.H{"status": 400})
			return
		}

		target, found, err := store.readUser(req.UID)
		if err != nil {
			logger.Error("Failed to read user", "err", err, "uid", req.UID)
			c.JSON(500, gin.H{"status": 500})
			return
		}
		if !found {
			c.JSON(400, gin.H{"status": 400})
			return
		}

		authenticated := false
		if req.Token != "" {
			if id, ok := issuer.Verify(req.Token); ok && id == target.ID {
				authenticated = true
			}
		}

		content := make(map[string]any, len(target.Profile))
		for key, value := range target.Profile {
			if schema.visible(key, authenticated) {
				content[key] = value
			}
		}
		c.JSON(200, gin.H{"status": 200, "content": content})
	}
}
