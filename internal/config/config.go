// Package config defines the on-disk configuration for both pds (client) and pdsd
// (server), and loads it from systemd-style layered tiers.
//
// Tiers, lowest to highest precedence:
//
//	/usr/lib/pds/<role>   (vendor/package defaults)
//	/etc/pds/<role>       (system administrator)
//	$XDG_CONFIG_HOME/pds/<role>  (per-user; default ~/.config)
//
// Within each tier, config.yaml is applied first, then every config.d/*.yaml in
// lexical order (so drop-ins override the tier's base file). Nothing is required to
// exist. An optional --config FILE is merged last as the highest-precedence layer.
//
// On-disk YAML keys are camelCase; Go fields are PascalCase with yaml tags.
package config

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"petris.dev/pds/internal/validate"
)

// Role selects which program's config tree to load.
type Role string

const (
	RoleClient Role = "client"
	RoleServer Role = "server"
)

// Reserved virtual path segments. Bucket names may not begin with '.', which keeps
// them disjoint from these.
const (
	NameSelf = ".self"
	NameMeta = ".meta"
	NamePush = ".push"
	NamePDS  = ".pds"
	NameExec = "exec" // child of .pds
)

// AnonymousUser is the SSH user name an unauthenticated client connects as. The
// server's anonymous fallback only accepts the "none" auth method for this user, so
// authenticated clients (which use any other user name) still fall through to public-
// key auth and keep their host identity.
const AnonymousUser = "anonymous"

// DefaultDialTimeout is the maximum time a client waits for one endpoint to become
// usable when dialTimeout is omitted.
const DefaultDialTimeout = 10 * time.Second

// ClientEndpoint is one server candidate. Candidates are tried in order. HTTPPort is
// optional and is only used to build read URLs (pds endpoint --http).
type ClientEndpoint struct {
	Host     string `yaml:"host"`
	SSHPort  int    `yaml:"sshPort"`
	HTTPPort int    `yaml:"httpPort"`
}

// Client is the pds configuration. Endpoints are ordered from most to least
// preferred. A nil DialTimeout means DefaultDialTimeout.
type Client struct {
	Endpoints   []ClientEndpoint `yaml:"endpoints"`
	DialTimeout *time.Duration   `yaml:"dialTimeout"`
	TrustedKeys []string         `yaml:"trustedKeys"`
	Identities  []string         `yaml:"identities"`
}

// EffectiveDialTimeout returns the configured per-endpoint timeout, or the default
// when no timeout was configured. Validation rejects explicit non-positive values.
func (c *Client) EffectiveDialTimeout() time.Duration {
	if c == nil || c.DialTimeout == nil {
		return DefaultDialTimeout
	}
	return *c.DialTimeout
}

// Server is the pdsd configuration.
type Server struct {
	SSHListen      string            `yaml:"sshListen"`
	HTTPListen     string            `yaml:"httpListen"`
	AuthorizedKeys []ClientEntry     `yaml:"authorizedKeys"`
	AllowAnonymous bool              `yaml:"allowAnonymous"`
	ExecBucket     string            `yaml:"execBucket"`
	Buckets        map[string]Bucket `yaml:"buckets"`
}

// ClientEntry maps one host name to the public key(s) that authenticate as it.
type ClientEntry struct {
	Host string   `yaml:"host"`
	Keys []string `yaml:"keys"`
}

// ifacePrefix marks a listen value as a network interface to track dynamically
// (e.g. "iface:eth0:2222") rather than a literal address or hostname. An explicit
// marker is required because an interface name and a hostname can collide (e.g.
// "tailscale0") and the interface may not exist yet when pdsd starts, so the two
// cannot be told apart by inspection.
const ifacePrefix = "iface:"

// EndpointSpec is the parsed form of a listen value. A static endpoint binds a
// fixed address once (passed straight to net.Listen, covering ":port", IP
// literals, and hostnames). An interface endpoint instead tracks a named
// interface's addresses over time.
type EndpointSpec struct {
	Iface string // "" => static; otherwise the interface name to track
	Addr  string // static: the full host:port handed to net.Listen
	Port  string // interface: the port joined with each interface address
}

// Static reports whether the endpoint binds a fixed address rather than tracking
// a network interface.
func (e EndpointSpec) Static() bool { return e.Iface == "" }

// parseEndpoint classifies a listen value. With the iface: prefix it names an
// interface to track; otherwise it is a static address or hostname bound once.
func parseEndpoint(value string) (EndpointSpec, error) {
	if rest, ok := strings.CutPrefix(value, ifacePrefix); ok {
		name, port, err := net.SplitHostPort(rest)
		if err != nil {
			return EndpointSpec{}, fmt.Errorf("interface listen %q: %w", value, err)
		}
		if name == "" {
			return EndpointSpec{}, fmt.Errorf("interface listen %q: missing interface name", value)
		}
		if strings.ContainsAny(name, "/%[]") {
			return EndpointSpec{}, fmt.Errorf("interface listen %q: invalid interface name %q", value, name)
		}
		if _, err := net.LookupPort("tcp", port); err != nil {
			return EndpointSpec{}, fmt.Errorf("interface listen %q: invalid port %q", value, port)
		}
		return EndpointSpec{Iface: name, Port: port}, nil
	}
	// Static: require a host:port shape with a port. The host (IP, hostname, or
	// empty for all interfaces) is left for net.Listen to resolve and bind.
	_, port, err := net.SplitHostPort(value)
	if err != nil {
		return EndpointSpec{}, fmt.Errorf("listen %q: %w", value, err)
	}
	if port == "" {
		return EndpointSpec{}, fmt.Errorf("listen %q: missing port", value)
	}
	return EndpointSpec{Addr: value}, nil
}

// SSHEndpoint returns the parsed primary (SSH/SFTP) listen endpoint.
func (s *Server) SSHEndpoint() (EndpointSpec, error) { return parseEndpoint(s.SSHListen) }

// HTTPEndpoint returns the parsed read-only HTTP endpoint and whether one is
// configured at all.
func (s *Server) HTTPEndpoint() (EndpointSpec, bool, error) {
	if s.HTTPListen == "" {
		return EndpointSpec{}, false, nil
	}
	spec, err := parseEndpoint(s.HTTPListen)
	return spec, true, err
}

// Bucket is one named storage area. mode "ro" (default) is read-only; "rw" also
// accepts pushes.
type Bucket struct {
	Path      string `yaml:"path"`
	Mode      string `yaml:"mode"`
	Versioned bool   `yaml:"versioned"`
	ByHost    bool   `yaml:"byHost"`
	Extension string `yaml:"extension"`
	Validator string `yaml:"validator"`
}

// Writable reports whether the bucket accepts pushes.
func (b Bucket) Writable() bool { return strings.EqualFold(b.Mode, "rw") }

// LoadClientUnvalidated loads the pds configuration without enforcing the full client
// contract. It is for commands (e.g. pds endpoint) that need only a subset of fields and
// should not require a usable SSH setup such as trustedKeys. Unknown keys are still
// rejected.
func LoadClientUnvalidated(override string) (*Client, error) {
	merged, err := loadMerged(RoleClient, override)
	if err != nil {
		return nil, err
	}
	var c Client
	if err := decode(merged, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// LoadClient loads and validates the pds configuration.
func LoadClient(override string) (*Client, error) {
	c, err := LoadClientUnvalidated(override)
	if err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// LoadServer loads and validates the pdsd configuration.
func LoadServer(override string) (*Server, error) {
	merged, err := loadMerged(RoleServer, override)
	if err != nil {
		return nil, err
	}
	var s Server
	if err := decode(merged, &s); err != nil {
		return nil, err
	}
	// Expand a leading ~ in bucket paths to the home of the user pdsd runs as.
	for name, b := range s.Buckets {
		p, err := expandUser(b.Path)
		if err != nil {
			return nil, fmt.Errorf("config: bucket %q path %q: %w", name, b.Path, err)
		}
		b.Path = p
		s.Buckets[name] = b
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate checks that the client config has everything required from somewhere.
func (c *Client) Validate() error {
	if len(c.Endpoints) == 0 {
		return fmt.Errorf("config: at least one endpoints entry is required")
	}
	seen := make(map[string]int, len(c.Endpoints))
	for i, endpoint := range c.Endpoints {
		if strings.TrimSpace(endpoint.Host) == "" {
			return fmt.Errorf("config: endpoints[%d] has no host", i)
		}
		if endpoint.SSHPort <= 0 || endpoint.SSHPort > 65535 {
			return fmt.Errorf("config: endpoints[%d] sshPort must be between 1 and 65535", i)
		}
		if endpoint.HTTPPort < 0 || endpoint.HTTPPort > 65535 {
			return fmt.Errorf("config: endpoints[%d] httpPort must be 0 or between 1 and 65535", i)
		}
		key := normalizedClientSSHEndpoint(endpoint)
		if previous, ok := seen[key]; ok {
			return fmt.Errorf("config: endpoints[%d] duplicates endpoints[%d] SSH endpoint %q", i, previous, key)
		}
		seen[key] = i
	}
	if c.DialTimeout != nil && *c.DialTimeout <= 0 {
		return fmt.Errorf("config: dialTimeout must be positive")
	}
	if len(c.TrustedKeys) == 0 {
		return fmt.Errorf("config: at least one trustedKeys entry is required")
	}
	return nil
}

// normalizedClientSSHEndpoint returns a comparison key for duplicate detection.
// DNS names are case-insensitive, bracketed and unbracketed IP literals are
// equivalent, and IP literals are reduced to their canonical spelling.
func normalizedClientSSHEndpoint(endpoint ClientEndpoint) string {
	host := strings.TrimSpace(endpoint.Host)
	if len(host) >= 2 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		host = addr.String()
	} else {
		host = strings.ToLower(host)
	}
	return net.JoinHostPort(host, fmt.Sprint(endpoint.SSHPort))
}

// Validate checks that the server config is internally consistent.
func (s *Server) Validate() error {
	if s.SSHListen == "" {
		return fmt.Errorf("config: sshListen is required")
	}
	if _, err := parseEndpoint(s.SSHListen); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if s.HTTPListen != "" {
		if !s.AllowAnonymous {
			return fmt.Errorf("config: httpListen requires allowAnonymous: true (HTTP is unauthenticated read-only access)")
		}
		if _, err := parseEndpoint(s.HTTPListen); err != nil {
			return fmt.Errorf("config: %w", err)
		}
	}
	if len(s.AuthorizedKeys) == 0 && !s.AllowAnonymous {
		return fmt.Errorf("config: at least one authorizedKeys entry is required (or set allowAnonymous: true)")
	}
	for i, ce := range s.AuthorizedKeys {
		if ce.Host == "" {
			return fmt.Errorf("config: authorizedKeys[%d] has no host", i)
		}
		if len(ce.Keys) == 0 {
			return fmt.Errorf("config: authorizedKeys host %q has no keys", ce.Host)
		}
	}
	for name, b := range s.Buckets {
		if strings.HasPrefix(name, ".") {
			return fmt.Errorf("config: bucket name %q may not begin with '.'", name)
		}
		if b.Path == "" {
			return fmt.Errorf("config: bucket %q has no path", name)
		}
		mode := strings.ToLower(b.Mode)
		if mode != "" && mode != "ro" && mode != "rw" {
			return fmt.Errorf("config: bucket %q mode %q must be ro or rw", name, b.Mode)
		}
		if b.Writable() {
			if b.Extension == "" {
				return fmt.Errorf("config: rw bucket %q requires extension", name)
			}
			if !validExtension(b.Extension) {
				return fmt.Errorf("config: rw bucket %q extension %q must be a safe filename suffix", name, b.Extension)
			}
			if b.Validator == "" || !validate.Known(b.Validator) {
				return fmt.Errorf("config: rw bucket %q validator %q must be one of %v",
					name, b.Validator, validate.Names())
			}
		}
	}
	if s.ExecBucket != "" {
		b, ok := s.Buckets[s.ExecBucket]
		if !ok {
			return fmt.Errorf("config: execBucket %q is not a defined bucket", s.ExecBucket)
		}
		if b.Writable() {
			return fmt.Errorf("config: execBucket %q must be mode ro (got rw)", s.ExecBucket)
		}
	}
	return nil
}

// extRe matches a safe filename suffix: alphanumeric ends, with dots/dashes/
// underscores allowed in between (e.g. "yaml", "tar.gz", "txt").
var extRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)

// validExtension reports whether ext is a single safe filename suffix with no path
// separators or ".." traversal semantics.
func validExtension(ext string) bool {
	return extRe.MatchString(ext) && !strings.Contains(ext, "..")
}

// expandUser expands a leading "~" or "~/" to the home directory of the user the
// process runs as. Other paths (including "~otheruser") are returned unchanged.
func expandUser(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[2:]), nil
}

// loadMerged walks the config tiers for role and returns the deep-merged map.
func loadMerged(role Role, override string) (map[string]any, error) {
	acc := map[string]any{}
	for _, root := range tierRoots(role) {
		for _, f := range layerFiles(root) {
			if err := mergeFile(acc, f, role); err != nil {
				return nil, err
			}
		}
	}
	if override != "" {
		if err := mergeFile(acc, override, role); err != nil {
			return nil, err
		}
	}
	return acc, nil
}

func tierRoots(role Role) []string {
	return []string{
		filepath.Join("/usr/lib/pds", string(role)),
		filepath.Join("/etc/pds", string(role)),
		filepath.Join(xdgConfigHome(), "pds", string(role)),
	}
}

func xdgConfigHome() string {
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		return v
	}
	return filepath.Join(os.Getenv("HOME"), ".config")
}

// layerFiles returns config.yaml (if present) then sorted config.d/*.yaml for a tier.
func layerFiles(root string) []string {
	var files []string
	base := filepath.Join(root, "config.yaml")
	if fileExists(base) {
		files = append(files, base)
	}
	entries, err := os.ReadDir(filepath.Join(root, "config.d"))
	if err == nil {
		var drops []string
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			n := e.Name()
			if strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml") {
				drops = append(drops, filepath.Join(root, "config.d", n))
			}
		}
		sort.Strings(drops)
		files = append(files, drops...)
	}
	return files
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

func mergeFile(acc map[string]any, path string, role Role) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: reading %s: %w", path, err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(data, &m); err != nil {
		return fmt.Errorf("config: parsing %s: %w", path, err)
	}
	mergeConfigMap(acc, m, role)
	return nil
}

// mergeConfigMap applies the generic merge rules, except that a client layer's
// top-level endpoints list replaces the preceding list. Endpoint order expresses
// failover priority, so unioning lists from separate layers would be surprising.
func mergeConfigMap(dst, src map[string]any, role Role) {
	endpoints, replaceEndpoints := src["endpoints"]
	mergeMap(dst, src)
	if role == RoleClient && replaceEndpoints {
		dst["endpoints"] = endpoints
	}
}

// mergeMap deep-merges src into dst: scalars override, maps recurse, lists are
// unioned (string duplicates removed; non-string elements concatenated).
func mergeMap(dst, src map[string]any) {
	for k, sv := range src {
		if dv, ok := dst[k]; ok {
			dm, dIsMap := dv.(map[string]any)
			sm, sIsMap := sv.(map[string]any)
			if dIsMap && sIsMap {
				mergeMap(dm, sm)
				continue
			}
			dl, dIsList := dv.([]any)
			sl, sIsList := sv.([]any)
			if dIsList && sIsList {
				dst[k] = mergeList(dl, sl)
				continue
			}
		}
		dst[k] = sv
	}
}

func mergeList(a, b []any) []any {
	out := append([]any{}, a...)
	seen := map[string]bool{}
	for _, v := range out {
		if s, ok := v.(string); ok {
			seen[s] = true
		}
	}
	for _, v := range b {
		if s, ok := v.(string); ok {
			if seen[s] {
				continue
			}
			seen[s] = true
		}
		out = append(out, v)
	}
	return out
}

// decode round-trips the merged map through YAML into a typed struct so yaml tags
// (camelCase) apply consistently.
func decode(m map[string]any, out any) error {
	data, err := yaml.Marshal(m)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		if err.Error() == "EOF" { // empty config
			return nil
		}
		return fmt.Errorf("config: %w", err)
	}
	return nil
}
