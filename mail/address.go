package mail

import "strings"

// SplitAddress splits an address into its local part and domain.
//
// go-smtp already unwraps the <> of a reverse/forward path, but a bare address
// is accepted too so the same helper works on header values and on queue
// entries. The domain is lowercased; the local part is returned verbatim
// because only the account lookup is allowed to fold its case.
func SplitAddress(addr string) (local, domain string, ok bool) {
	addr = strings.TrimSpace(addr)
	addr = strings.TrimPrefix(addr, "<")
	addr = strings.TrimSuffix(addr, ">")

	at := strings.LastIndex(addr, "@")
	if at <= 0 || at == len(addr)-1 {
		return "", "", false
	}
	local, domain = addr[:at], strings.ToLower(addr[at+1:])
	if strings.ContainsAny(local, " \t\r\n") || strings.ContainsAny(domain, " \t\r\n@") {
		return "", "", false
	}
	return local, domain, true
}

// isLocalDomain reports whether domain is served by this instance.
func (s *Server) isLocalDomain(domain string) bool {
	if strings.EqualFold(domain, s.cfg.Domain) {
		return true
	}
	for _, extra := range s.cfg.ExtraDomains {
		if strings.EqualFold(domain, extra) {
			return true
		}
	}
	return false
}
