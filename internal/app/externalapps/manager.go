package externalapps

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	certificateapp "github.com/rebeccapanel/rebecca/internal/app/certificates"
)

const (
	defaultBaseDir              = "/var/lib/rebecca/external-apps"
	legacyBaseDir               = "/var/lib/rebecca/php-apps"
	externalAppFileAccessRoot   = "/var/lib/rebecca"
	mirzaBotRepositoryURL       = "https://github.com/mahdiMGF2/mirzabot"
	mirzaBotAPIBaseURL          = "https://api.github.com/repos/mahdiMGF2/mirzabot"
	mirzaBotArchiveBaseURL      = "https://codeload.github.com/mahdiMGF2/mirzabot"
	MaxRequestBodyBytes         = 34 << 20
	maxExternalAppArchiveBytes  = 32 << 20
	maxExternalAppExtractedSize = 256 << 20
	maxExternalAppFiles         = 5000
	defaultRequestBodyLimitMB   = 32
	defaultStaticCacheSeconds   = 3600
	maxStaticCacheSeconds       = 365 * 24 * 60 * 60
	externalAppsSQLiteDetail    = "External application hosting requires MySQL or MariaDB and is disabled when Rebecca uses SQLite."
)

type Config struct {
	BaseDir           string
	DatabaseURL       string
	DatabaseDialect   string
	MySQLRootPassword string
}

var (
	errExternalAppBusy        = errors.New("another external application operation is already running")
	errExternalAppExists      = errors.New("an application already uses this domain and path")
	errExternalAppNotFound    = errors.New("external application not found")
	errExternalAppUpToDate    = errors.New("MirzaBot is already up to date")
	errExternalAppUnsupported = errors.New("external application hosting is not supported by this installation")
	externalAppIDPattern      = regexp.MustCompile(`^[0-9a-f]{12}$`)
	externalAppPathPattern    = regexp.MustCompile(`^bot[0-9a-f]{12}$`)
	mirzaBotTokenPattern      = regexp.MustCompile(`^[0-9]{5,16}:[A-Za-z0-9_-]{20,100}$`)
	mirzaReleasePattern       = regexp.MustCompile(`^v?[0-9]+(?:\.[0-9]+){1,3}$`)
	mirzaCommitPattern        = regexp.MustCompile(`^[0-9a-f]{40}$`)
	telegramIDPattern         = regexp.MustCompile(`^-?[0-9]{5,20}$`)
	databaseNamePattern       = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
	databaseUserPattern       = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,31}$`)
	databasePasswordPattern   = regexp.MustCompile(`^[A-Za-z0-9!@#$%^&*_.+=:-]{12,128}$`)
)

type InstallRequest struct {
	Domain         string `json:"domain"`
	BotToken       string `json:"bot_token"`
	AdminID        string `json:"admin_id"`
	DatabaseBackup []byte `json:"-"`
}

type ArchiveInstallRequest struct {
	Domain           string
	Name             string
	Runtime          string
	Archive          []byte
	CreateDatabase   bool
	Database         string
	DatabaseUser     string
	DatabasePassword string
}

type Record struct {
	ID                 string `json:"id,omitempty"`
	Template           string `json:"template"`
	Name               string `json:"name"`
	Domain             string `json:"domain"`
	Path               string `json:"path,omitempty"`
	Enabled            bool   `json:"enabled"`
	Runtime            string `json:"runtime"`
	Version            string `json:"version,omitempty"`
	SourceSHA          string `json:"source_sha,omitempty"`
	InstalledAt        string `json:"installed_at"`
	PHPVersion         string `json:"php_version,omitempty"`
	BotUsername        string `json:"bot_username,omitempty"`
	IndexFile          string `json:"index_file,omitempty"`
	FallbackToIndex    bool   `json:"fallback_to_index,omitempty"`
	MaxRequestBodyMB   int    `json:"max_request_body_mb,omitempty"`
	StaticCacheSeconds *int   `json:"static_cache_seconds,omitempty"`
	NotFoundFile       string `json:"not_found_file,omitempty"`
	Root               string `json:"root"`
	Socket             string `json:"socket,omitempty"`
	PoolConfig         string `json:"pool_config,omitempty"`
	CronConfig         string `json:"cron_config,omitempty"`
	Service            string `json:"service,omitempty"`
	UnitConfig         string `json:"unit_config,omitempty"`
	Port               int    `json:"port,omitempty"`
	SystemUser         string `json:"system_user,omitempty"`
	Database           string `json:"database,omitempty"`
	DatabaseUser       string `json:"database_user,omitempty"`
	storageBase        string
}

type PublicRecord struct {
	ID                 string `json:"id"`
	Template           string `json:"template"`
	Name               string `json:"name"`
	Domain             string `json:"domain"`
	Path               string `json:"path,omitempty"`
	Enabled            bool   `json:"enabled"`
	Runtime            string `json:"runtime"`
	Version            string `json:"version,omitempty"`
	SourceSHA          string `json:"source_sha,omitempty"`
	InstalledAt        string `json:"installed_at"`
	PHPVersion         string `json:"php_version,omitempty"`
	BotUsername        string `json:"bot_username,omitempty"`
	IndexFile          string `json:"index_file"`
	FallbackToIndex    bool   `json:"fallback_to_index"`
	MaxRequestBodyMB   int    `json:"max_request_body_mb"`
	StaticCacheSeconds int    `json:"static_cache_seconds"`
	NotFoundFile       string `json:"not_found_file"`
	HasDatabase        bool   `json:"has_database"`
	PublicURL          string `json:"public_url"`
	UpdateAvailable    bool   `json:"update_available,omitempty"`
	LatestVersion      string `json:"latest_version,omitempty"`
}

type secrets struct {
	BotToken      string `json:"bot_token,omitempty"`
	WebhookSecret string `json:"webhook_secret,omitempty"`
	CronSecret    string `json:"cron_secret,omitempty"`
}

type Manager struct {
	baseDir      string
	legacyBase   string
	databaseURL  string
	dialect      string
	rootPassword string
	certificates *certificateapp.Manager
	httpClient   *http.Client
	mirzaAPIBase string
	mirzaArchive string
	fileAccess   string

	operationMu  sync.Mutex
	releaseMu    sync.Mutex
	release      mirzaBotRelease
	releaseUntil time.Time
	mu           sync.RWMutex
	apps         map[string]Record
}

func New(cfg Config, certificates *certificateapp.Manager) *Manager {
	dialect := strings.ToLower(strings.TrimSpace(cfg.DatabaseDialect))
	baseDir := strings.TrimSpace(cfg.BaseDir)
	legacyBase := ""
	if baseDir == "" {
		baseDir = defaultBaseDir
		if dialect != "sqlite" && dialect != "sqlite3" {
			legacyBase = legacyBaseDir
			_ = migrateLegacyBaseDir(baseDir, legacyBaseDir)
		}
	}
	manager := &Manager{
		baseDir:      filepath.Clean(baseDir),
		legacyBase:   legacyBase,
		databaseURL:  cfg.DatabaseURL,
		dialect:      dialect,
		rootPassword: cfg.MySQLRootPassword,
		certificates: certificates,
		mirzaAPIBase: mirzaBotAPIBaseURL,
		mirzaArchive: mirzaBotArchiveBaseURL,
		fileAccess:   externalAppFileAccessRoot,
		httpClient: &http.Client{
			Timeout: 2 * time.Minute,
			CheckRedirect: func(request *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return errors.New("too many redirects")
				}
				switch strings.ToLower(request.URL.Hostname()) {
				case "api.github.com", "codeload.github.com", "github.com", "objects.githubusercontent.com", "api.telegram.org":
					return nil
				default:
					return errors.New("unexpected redirect host")
				}
			},
		},
		apps: map[string]Record{},
	}
	if manager.sqliteDisabled() {
		return manager
	}
	manager.reload()
	return manager
}

func (m *Manager) sqliteDisabled() bool {
	return m != nil && (m.dialect == "sqlite" || m.dialect == "sqlite3")
}

func migrateLegacyBaseDir(baseDir, oldBaseDir string) error {
	if _, err := os.Lstat(oldBaseDir); err == nil || !os.IsNotExist(err) {
		return nil
	}
	if _, err := os.Stat(baseDir); err != nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(oldBaseDir), 0o700); err != nil {
		return err
	}
	return os.Symlink(baseDir, oldBaseDir)
}

func (m *Manager) reload() {
	loaded := map[string]Record{}
	mounts := map[string]bool{}
	bases := []string{m.baseDir}
	if m.legacyBase != "" {
		bases = append(bases, m.legacyBase)
	}
	seenBases := map[string]bool{}
	for _, base := range bases {
		resolved, err := filepath.EvalSymlinks(base)
		if err == nil && seenBases[resolved] {
			continue
		}
		if err == nil {
			seenBases[resolved] = true
		}
		entries, err := os.ReadDir(filepath.Join(base, ".metadata"))
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(base, ".metadata", entry.Name()))
			if err != nil {
				continue
			}
			var record Record
			if json.Unmarshal(data, &record) != nil || (record.Template != "archive" && record.Template != "mirzabot") {
				continue
			}
			id := strings.TrimSuffix(entry.Name(), ".json")
			if record.ID != "" {
				id = strings.ToLower(strings.TrimSpace(record.ID))
			}
			domain := CanonicalHost(record.Domain)
			mountPath := strings.Trim(strings.ToLower(strings.TrimSpace(record.Path)), "/")
			if !externalAppIDPattern.MatchString(id) || domain == "" || (mountPath != "" && !externalAppPathPattern.MatchString(mountPath)) || !pathWithinResolved(filepath.Join(base, "apps"), record.Root) {
				continue
			}
			if record.Runtime == "php" && (!pathWithin("/run/php", record.Socket) || !pathWithin("/etc/php", record.PoolConfig)) {
				continue
			}
			if record.Runtime == "node" && (record.Port < 20000 || record.Port > 39999 || !pathWithin("/etc/systemd/system", record.UnitConfig) || !strings.HasPrefix(record.Service, "rebecca-node-")) {
				continue
			}
			if record.CronConfig != "" && !pathWithin("/etc/cron.d", record.CronConfig) {
				continue
			}
			mountKey := domain + "\x00" + mountPath
			if mounts[mountKey] {
				continue
			}
			record.ID = id
			record.Domain = domain
			record.Path = mountPath
			record.storageBase = base
			if record.Template == "mirzabot" {
				_ = patchMirzaMiniApp(record.Root, mountPath)
			}
			loaded[id] = record
			mounts[mountKey] = true
		}
	}
	m.mu.Lock()
	m.apps = loaded
	m.mu.Unlock()
}

func (m *Manager) Lookup(identifier string) (Record, bool) {
	if m.sqliteDisabled() {
		return Record{}, false
	}
	identifier = strings.ToLower(strings.TrimSpace(identifier))
	m.mu.RLock()
	record, ok := m.apps[identifier]
	if !ok {
		host := CanonicalHost(identifier)
		for _, candidate := range m.apps {
			if candidate.Domain != host {
				continue
			}
			if ok {
				m.mu.RUnlock()
				return Record{}, false
			}
			record, ok = candidate, true
		}
	}
	m.mu.RUnlock()
	return record, ok
}

func (m *Manager) HasHost(host string) bool {
	if m.sqliteDisabled() {
		return false
	}
	host = CanonicalHost(host)
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, record := range m.apps {
		if record.Domain == host {
			return true
		}
	}
	return false
}

func (m *Manager) Match(host, requestPath string) (Record, string, bool) {
	if m.sqliteDisabled() {
		return Record{}, "", false
	}
	host = CanonicalHost(host)
	cleanPath := strings.TrimPrefix(path.Clean("/"+requestPath), "/")
	m.mu.RLock()
	defer m.mu.RUnlock()
	var matched Record
	matchedPath := ""
	best := -1
	for _, record := range m.apps {
		if record.Domain != host {
			continue
		}
		mount := strings.Trim(record.Path, "/")
		if mount == "" {
			if best < 0 {
				matched, matchedPath, best = record, cleanPath, 0
			}
			continue
		}
		if cleanPath != mount && !strings.HasPrefix(cleanPath, mount+"/") {
			continue
		}
		if len(mount) > best {
			matched = record
			matchedPath = strings.TrimPrefix(strings.TrimPrefix(cleanPath, mount), "/")
			best = len(mount)
		}
	}
	return matched, matchedPath, best >= 0
}

// MatchMirzaLegacyPath keeps older Mini App bundles working when they request
// /app or /api from the domain root instead of including the external-app mount.
// A domain with multiple MirzaBot apps is intentionally left ambiguous.
func (m *Manager) MatchMirzaLegacyPath(host, requestPath string) (Record, string, bool) {
	if m.sqliteDisabled() {
		return Record{}, "", false
	}
	cleanPath := strings.TrimPrefix(path.Clean("/"+requestPath), "/")
	if cleanPath != "app" && !strings.HasPrefix(cleanPath, "app/") && cleanPath != "api" && !strings.HasPrefix(cleanPath, "api/") {
		return Record{}, "", false
	}
	host = CanonicalHost(host)
	m.mu.RLock()
	defer m.mu.RUnlock()
	var matched Record
	for _, record := range m.apps {
		if record.Template != "mirzabot" || record.Domain != host || strings.TrimSpace(record.Path) == "" {
			continue
		}
		if matched.ID != "" {
			return Record{}, "", false
		}
		matched = record
	}
	if matched.ID == "" {
		return Record{}, "", false
	}
	return matched, cleanPath, true
}

func (m *Manager) mountExists(domain, mountPath string) bool {
	domain = CanonicalHost(domain)
	mountPath = strings.Trim(mountPath, "/")
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, record := range m.apps {
		if record.Domain == domain && record.Path == mountPath {
			return true
		}
	}
	return false
}

func (m *Manager) setRecord(record Record) {
	m.mu.Lock()
	m.apps[record.ID] = record
	m.mu.Unlock()
}

func (m *Manager) removeRecord(id string) {
	m.mu.Lock()
	delete(m.apps, id)
	m.mu.Unlock()
}

func (m *Manager) withEnabledRecord(record Record, activate func() error) (func(), error) {
	previous, existed := m.Lookup(record.ID)
	record.Enabled = true
	m.setRecord(record)
	rollback := func() {
		if existed {
			m.setRecord(previous)
		} else {
			m.removeRecord(record.ID)
		}
	}
	if err := activate(); err != nil {
		rollback()
		return nil, err
	}
	return rollback, nil
}

func (m *Manager) publicRecords() []PublicRecord {
	m.mu.RLock()
	records := make([]PublicRecord, 0, len(m.apps))
	for _, record := range m.apps {
		records = append(records, publicExternalAppRecord(record))
	}
	m.mu.RUnlock()
	sort.Slice(records, func(i, j int) bool {
		if records[i].Domain == records[j].Domain {
			return records[i].Path < records[j].Path
		}
		return records[i].Domain < records[j].Domain
	})
	return records
}

func publicExternalAppRecord(record Record) PublicRecord {
	return PublicRecord{
		ID:                 record.ID,
		Template:           record.Template,
		Name:               record.Name,
		Domain:             record.Domain,
		Path:               record.Path,
		Enabled:            record.Enabled,
		Runtime:            record.Runtime,
		Version:            record.Version,
		SourceSHA:          record.SourceSHA,
		InstalledAt:        record.InstalledAt,
		PHPVersion:         record.PHPVersion,
		BotUsername:        record.BotUsername,
		IndexFile:          externalAppIndexFile(record),
		FallbackToIndex:    record.FallbackToIndex,
		MaxRequestBodyMB:   externalAppMaxRequestBodyMB(record),
		StaticCacheSeconds: ExternalAppStaticCacheSeconds(record),
		NotFoundFile:       record.NotFoundFile,
		HasDatabase:        record.Database != "",
		PublicURL:          externalAppPublicURL(record) + "/",
	}
}

func externalAppDefaultIndex(root, runtime string) string {
	if runtime == "node" {
		return ""
	}
	if runtime == "php" {
		if info, err := os.Stat(filepath.Join(root, "index.php")); err == nil && !info.IsDir() {
			return "index.php"
		}
	}
	return "index.html"
}

func externalAppIndexFile(record Record) string {
	if index := strings.TrimSpace(record.IndexFile); index != "" {
		return filepath.ToSlash(index)
	}
	if record.Template == "mirzabot" {
		return "index.php"
	}
	return externalAppDefaultIndex(record.Root, record.Runtime)
}

func externalAppMaxRequestBodyMB(record Record) int {
	if record.MaxRequestBodyMB < 1 || record.MaxRequestBodyMB > defaultRequestBodyLimitMB {
		return defaultRequestBodyLimitMB
	}
	return record.MaxRequestBodyMB
}

func ExternalAppRequestBodyLimitBytes(record Record) int64 {
	return int64(externalAppMaxRequestBodyMB(record)) << 20
}

func ExternalAppStaticCacheSeconds(record Record) int {
	if record.StaticCacheSeconds == nil {
		return defaultStaticCacheSeconds
	}
	seconds := *record.StaticCacheSeconds
	if seconds < 0 || seconds > maxStaticCacheSeconds {
		return defaultStaticCacheSeconds
	}
	return seconds
}

func mirzaBotUpdateAvailable(record Record, release mirzaBotRelease) bool {
	if record.Template != "mirzabot" || release.SHA == "" {
		return false
	}
	if strings.EqualFold(record.SourceSHA, release.SHA) {
		return false
	}
	comparison, ok := compareMirzaBotVersions(record.Version, release.Version)
	return !ok || comparison < 0
}

func compareMirzaBotVersions(left, right string) (int, bool) {
	parse := func(value string) ([]int, bool) {
		value = strings.TrimPrefix(strings.TrimSpace(value), "v")
		if !mirzaReleasePattern.MatchString(value) {
			return nil, false
		}
		parts := strings.Split(value, ".")
		numbers := make([]int, len(parts))
		for index, part := range parts {
			number, err := strconv.Atoi(part)
			if err != nil {
				return nil, false
			}
			numbers[index] = number
		}
		return numbers, true
	}
	leftParts, leftOK := parse(left)
	rightParts, rightOK := parse(right)
	if !leftOK || !rightOK {
		return 0, false
	}
	for index := 0; index < max(len(leftParts), len(rightParts)); index++ {
		var leftPart, rightPart int
		if index < len(leftParts) {
			leftPart = leftParts[index]
		}
		if index < len(rightParts) {
			rightPart = rightParts[index]
		}
		if leftPart < rightPart {
			return -1, true
		}
		if leftPart > rightPart {
			return 1, true
		}
	}
	return 0, true
}

func externalAppPublicURL(record Record) string {
	value := "https://" + record.Domain
	if record.Path != "" {
		value += "/" + record.Path
	}
	return value
}

func (m *Manager) hostingSupported() (bool, string) {
	if m.sqliteDisabled() {
		return false, externalAppsSQLiteDetail
	}
	mode, err := os.ReadFile("/opt/rebecca/.install-mode")
	if err != nil || strings.TrimSpace(string(mode)) != "binary" {
		return false, "External application hosting is available only in binary installations."
	}
	return true, ""
}

func (m *Manager) mirzaSupported() (bool, string) {
	if ok, detail := m.hostingSupported(); !ok {
		return false, detail
	}
	credentials, err := parseDatabaseCredentials(m.databaseURL)
	if err != nil || !isLocalDatabaseHost(credentials.Host) || credentials.Port != "3306" {
		return false, "MirzaBot requires Rebecca to use the local MySQL or MariaDB service on port 3306."
	}
	return true, ""
}

func (m *Manager) certificateDomain(ctx context.Context, requested string) (string, error) {
	if m.certificates == nil {
		return "", errors.New("SSL manager is unavailable")
	}
	requested = CanonicalHost(requested)
	records, err := m.certificates.List(ctx)
	if err != nil {
		return "", fmt.Errorf("a managed SSL certificate is required for this domain: %w", err)
	}
	found := false
	for _, record := range records {
		if !externalAppCertificateContains(record, requested) {
			continue
		}
		found = true
		if (record.Status == "active" || record.Status == "expiring") && record.ServeTLS {
			return requested, nil
		}
	}
	if found {
		return "", errors.New("select an active managed certificate that is enabled for SNI serving")
	}
	return "", errors.New("a managed SSL certificate is required for this domain")
}

func externalAppCertificateContains(record certificateapp.Record, domain string) bool {
	if strings.EqualFold(record.Domain, domain) {
		return true
	}
	for _, name := range record.AltNames {
		if strings.EqualFold(name, domain) {
			return true
		}
	}
	return false
}

func (m *Manager) installArchive(ctx context.Context, request ArchiveInstallRequest) (PublicRecord, error) {
	if !m.operationMu.TryLock() {
		return PublicRecord{}, errExternalAppBusy
	}
	defer m.operationMu.Unlock()
	if ok, detail := m.hostingSupported(); !ok {
		return PublicRecord{}, fmt.Errorf("%w: %s", errExternalAppUnsupported, detail)
	}
	domain, err := m.certificateDomain(ctx, request.Domain)
	if err != nil {
		return PublicRecord{}, err
	}
	if m.mountExists(domain, "") {
		return PublicRecord{}, errExternalAppExists
	}
	if len(request.Archive) > maxExternalAppArchiveBytes {
		return PublicRecord{}, errors.New("ZIP archive exceeds 32 MiB")
	}
	if request.CreateDatabase {
		request.Database = strings.TrimSpace(request.Database)
		request.DatabaseUser = strings.TrimSpace(request.DatabaseUser)
		if !databaseNamePattern.MatchString(request.Database) {
			return PublicRecord{}, errors.New("database name must start with a letter and contain only letters, numbers, or underscores (maximum 64 characters)")
		}
		if !databaseUserPattern.MatchString(request.DatabaseUser) {
			return PublicRecord{}, errors.New("database username must start with a letter and contain only letters, numbers, or underscores (maximum 32 characters)")
		}
		if !databasePasswordPattern.MatchString(request.DatabasePassword) {
			return PublicRecord{}, errors.New("database password must be 12-128 characters and use letters, numbers, or !@#$%^&*_.+=:-")
		}
		credentials, err := parseDatabaseCredentials(m.databaseURL)
		if err != nil || !isLocalDatabaseHost(credentials.Host) || credentials.Port != "3306" {
			return PublicRecord{}, errors.New("managed application databases require Rebecca to use the local MySQL or MariaDB service on port 3306")
		}
		if err := m.ensureExternalAppDatabaseFree(ctx, request.Database, request.DatabaseUser); err != nil {
			return PublicRecord{}, err
		}
	}
	if err := m.prepareStorage(); err != nil {
		return PublicRecord{}, err
	}
	stage, err := os.MkdirTemp(m.baseDir, ".archive-install-")
	if err != nil {
		return PublicRecord{}, err
	}
	defer os.RemoveAll(stage)
	var root, runtime string
	if len(request.Archive) > 0 {
		root, err = extractExternalAppArchive(request.Archive, stage)
		if err != nil {
			return PublicRecord{}, err
		}
		runtime, err = detectExternalAppRuntime(root)
		if err != nil {
			return PublicRecord{}, err
		}
	} else {
		runtime = strings.ToLower(strings.TrimSpace(request.Runtime))
		if runtime == "" {
			runtime = "php"
		}
		if runtime != "php" && runtime != "static" && runtime != "node" {
			return PublicRecord{}, errors.New("runtime must be php, node, or static")
		}
		root = filepath.Join(stage, "app")
		if err := os.Mkdir(root, 0o700); err != nil {
			return PublicRecord{}, err
		}
		if runtime == "node" {
			if err := writeEmptyNodeApp(root); err != nil {
				return PublicRecord{}, err
			}
		}
	}

	suffix := domainHash(domain)
	appRoot := filepath.Join(m.appsDir(), suffix)
	if _, err := os.Stat(appRoot); err == nil {
		return PublicRecord{}, errExternalAppExists
	} else if !os.IsNotExist(err) {
		return PublicRecord{}, err
	}
	record := Record{
		ID:          suffix,
		Template:    "archive",
		Name:        normalizeExternalAppName(request.Name, domain),
		Domain:      domain,
		Enabled:     true,
		Runtime:     runtime,
		IndexFile:   "index.html",
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
		Root:        appRoot,
		storageBase: m.baseDir,
	}
	if runtime == "php" {
		record.IndexFile = "index.php"
	} else if runtime == "node" {
		record.IndexFile = ""
	}
	if len(request.Archive) > 0 {
		record.IndexFile = externalAppDefaultIndex(root, runtime)
		record.SourceSHA = sha256Hex(request.Archive)
	}
	if request.CreateDatabase {
		record.Database = request.Database
		record.DatabaseUser = request.DatabaseUser
	}

	var userCreated, appCreated, poolCreated, unitCreated, databaseCreated bool
	completed := false
	defer func() {
		if completed {
			return
		}
		_ = os.Remove(m.recordPathFor(record))
		if poolCreated {
			_ = os.Remove(record.PoolConfig)
			_, _ = runExternalAppCommand(context.Background(), time.Minute, "systemctl", "reload", record.Service)
		}
		if unitCreated {
			_, _ = runExternalAppCommand(context.Background(), time.Minute, "systemctl", "disable", "--now", record.Service)
			_ = os.Remove(record.UnitConfig)
			_, _ = runExternalAppCommand(context.Background(), time.Minute, "systemctl", "daemon-reload")
		}
		if databaseCreated {
			_ = m.dropExternalAppDatabase(context.Background(), record.Database, record.DatabaseUser)
		}
		if appCreated {
			_ = os.RemoveAll(appRoot)
		}
		if userCreated {
			_, _ = runExternalAppCommand(context.Background(), time.Minute, "userdel", record.SystemUser)
		}
	}()

	if runtime == "php" {
		if err := prepareExternalAppHost(ctx); err != nil {
			return PublicRecord{}, err
		}
		phpVersion, err := activePHPVersion(ctx, false)
		if err != nil {
			return PublicRecord{}, err
		}
		record.PHPVersion = phpVersion
		record.SystemUser = "rbphp_" + suffix
		record.Socket = filepath.Join("/run/php", "rebecca-"+suffix+".sock")
		record.PoolConfig = filepath.Join("/etc/php", phpVersion, "fpm", "pool.d", "rebecca-"+suffix+".conf")
		record.Service = "php" + phpVersion + "-fpm"
		if err := ensureExternalAppRuntimeFree(ctx, record); err != nil {
			return PublicRecord{}, err
		}
		if _, err := runExternalAppCommand(ctx, time.Minute, "useradd", "--system", "--user-group", "--home-dir", appRoot, "--shell", "/usr/sbin/nologin", "--no-create-home", record.SystemUser); err != nil {
			return PublicRecord{}, fmt.Errorf("create isolated PHP user: %w", err)
		}
		userCreated = true
	} else if runtime == "node" {
		if err := prepareExternalAppNodeHost(ctx); err != nil {
			return PublicRecord{}, err
		}
		record.SystemUser = "rbnode_" + suffix
		record.Port = externalAppNodePort(suffix)
		record.Service = "rebecca-node-" + suffix + ".service"
		record.UnitConfig = filepath.Join("/etc/systemd/system", record.Service)
		if err := ensureExternalAppRuntimeFree(ctx, record); err != nil {
			return PublicRecord{}, err
		}
		if _, err := runExternalAppCommand(ctx, time.Minute, "useradd", "--system", "--user-group", "--home-dir", appRoot, "--shell", "/usr/sbin/nologin", "--no-create-home", record.SystemUser); err != nil {
			return PublicRecord{}, fmt.Errorf("create isolated Node.js user: %w", err)
		}
		userCreated = true
	}
	if err := os.Rename(root, appRoot); err != nil {
		return PublicRecord{}, fmt.Errorf("install application files: %w", err)
	}
	appCreated = true
	if runtime == "php" || runtime == "node" {
		uid, gid, err := unixUserIDs(ctx, record.SystemUser)
		if err != nil {
			return PublicRecord{}, err
		}
		if err := prepareOwnedExternalAppTree(appRoot, uid, gid); err != nil {
			return PublicRecord{}, err
		}
		if runtime == "php" {
			if err := writeExternalAppPool(record, false); err != nil {
				return PublicRecord{}, err
			}
			poolCreated = true
			if err := reloadPHPFPM(ctx, record); err != nil {
				return PublicRecord{}, err
			}
		} else {
			if err := installExternalAppNode(ctx, record); err != nil {
				return PublicRecord{}, err
			}
			unitCreated = true
		}
	} else if err := makeStaticTreeReadOnly(appRoot); err != nil {
		return PublicRecord{}, err
	}
	if request.CreateDatabase {
		if err := m.createExternalAppDatabase(ctx, record.Database, record.DatabaseUser, request.DatabasePassword); err != nil {
			return PublicRecord{}, err
		}
		databaseCreated = true
	}
	if err := m.writeRecord(record); err != nil {
		return PublicRecord{}, err
	}
	m.setRecord(record)
	completed = true
	return publicExternalAppRecord(record), nil
}

func (m *Manager) installMirzaBot(ctx context.Context, request InstallRequest) (PublicRecord, error) {
	if !m.operationMu.TryLock() {
		return PublicRecord{}, errExternalAppBusy
	}
	defer m.operationMu.Unlock()
	request.Domain = strings.TrimSpace(request.Domain)
	request.BotToken = strings.TrimSpace(request.BotToken)
	request.AdminID = strings.TrimSpace(request.AdminID)
	if !mirzaBotTokenPattern.MatchString(request.BotToken) || !telegramIDPattern.MatchString(request.AdminID) {
		return PublicRecord{}, errors.New("a valid Telegram bot token and Telegram admin ID are required")
	}
	if ok, detail := m.mirzaSupported(); !ok {
		return PublicRecord{}, fmt.Errorf("%w: %s", errExternalAppUnsupported, detail)
	}
	domain, err := m.certificateDomain(ctx, request.Domain)
	if err != nil {
		return PublicRecord{}, err
	}
	if err := m.ensureBotTokenAvailable(request.BotToken); err != nil {
		return PublicRecord{}, err
	}
	if err := prepareExternalAppHost(ctx); err != nil {
		return PublicRecord{}, err
	}
	phpVersion, err := activePHPVersion(ctx, true)
	if err != nil {
		return PublicRecord{}, err
	}
	botUsername, err := m.telegramBotUsername(ctx, request.BotToken)
	if err != nil {
		return PublicRecord{}, err
	}
	source, err := m.downloadMirzaBot(ctx)
	if err != nil {
		return PublicRecord{}, err
	}
	if err := m.prepareStorage(); err != nil {
		return PublicRecord{}, err
	}
	stage, err := os.MkdirTemp(m.baseDir, ".mirzabot-install-")
	if err != nil {
		return PublicRecord{}, err
	}
	defer os.RemoveAll(stage)
	sourceRoot, err := extractMirzaBotArchive(source.Archive, stage)
	if err != nil {
		return PublicRecord{}, err
	}

	suffix, err := randomHex(6)
	if err != nil {
		return PublicRecord{}, err
	}
	mountPath := "bot" + suffix
	if m.mountExists(domain, mountPath) {
		return PublicRecord{}, errExternalAppExists
	}
	record := Record{
		ID:           suffix,
		Template:     "mirzabot",
		Name:         "MirzaBot @" + botUsername,
		Domain:       domain,
		Path:         mountPath,
		Enabled:      false,
		Runtime:      "php",
		Version:      source.Version,
		SourceSHA:    source.SHA,
		InstalledAt:  time.Now().UTC().Format(time.RFC3339),
		PHPVersion:   phpVersion,
		BotUsername:  botUsername,
		IndexFile:    "index.php",
		Root:         filepath.Join(m.appsDir(), suffix),
		Socket:       filepath.Join("/run/php", "rebecca-"+suffix+".sock"),
		PoolConfig:   filepath.Join("/etc/php", phpVersion, "fpm", "pool.d", "rebecca-"+suffix+".conf"),
		CronConfig:   filepath.Join("/etc/cron.d", "rebecca-php-"+suffix),
		Service:      "php" + phpVersion + "-fpm",
		SystemUser:   "rbphp_" + suffix,
		Database:     "rb_mirza_" + suffix,
		DatabaseUser: "rbm_" + suffix,
		storageBase:  m.baseDir,
	}
	if err := m.ensureMirzaInstallTargetsFree(ctx, record); err != nil {
		return PublicRecord{}, err
	}

	var userCreated, appCreated, databaseCreated, poolCreated, cronCreated bool
	var rollbackRecord func()
	completed := false
	defer func() {
		if completed {
			return
		}
		if rollbackRecord != nil {
			rollbackRecord()
		}
		_ = os.Remove(m.recordPathFor(record))
		_ = os.Remove(m.secretPathFor(record))
		if cronCreated {
			_ = os.Remove(record.CronConfig)
		}
		if poolCreated {
			_ = os.Remove(record.PoolConfig)
			_, _ = runExternalAppCommand(context.Background(), time.Minute, "systemctl", "reload", record.Service)
		}
		if databaseCreated {
			_ = m.dropExternalAppDatabase(context.Background(), record.Database, record.DatabaseUser)
		}
		if appCreated {
			_ = os.RemoveAll(record.Root)
		}
		if userCreated {
			_, _ = runExternalAppCommand(context.Background(), time.Minute, "userdel", record.SystemUser)
		}
	}()

	if _, err := runExternalAppCommand(ctx, time.Minute, "useradd", "--system", "--user-group", "--home-dir", record.Root, "--shell", "/usr/sbin/nologin", "--no-create-home", record.SystemUser); err != nil {
		return PublicRecord{}, fmt.Errorf("create isolated PHP user: %w", err)
	}
	userCreated = true
	if err := os.Rename(sourceRoot, record.Root); err != nil {
		return PublicRecord{}, fmt.Errorf("install MirzaBot source: %w", err)
	}
	appCreated = true
	if err := removeMirzaBotInstaller(record.Root); err != nil {
		return PublicRecord{}, err
	}
	if err := patchMirzaMiniApp(record.Root, record.Path); err != nil {
		return PublicRecord{}, err
	}
	uid, gid, err := unixUserIDs(ctx, record.SystemUser)
	if err != nil {
		return PublicRecord{}, err
	}
	if err := prepareOwnedExternalAppTree(record.Root, uid, gid); err != nil {
		return PublicRecord{}, err
	}
	if err := installMirzaBotDependencies(ctx, record.Root, record.SystemUser); err != nil {
		return PublicRecord{}, err
	}
	databasePassword, err := randomHex(24)
	if err != nil {
		return PublicRecord{}, err
	}
	if err := m.ensureExternalAppDatabaseFree(ctx, record.Database, record.DatabaseUser); err != nil {
		return PublicRecord{}, err
	}
	databaseCreated = true
	if err := m.createExternalAppDatabase(ctx, record.Database, record.DatabaseUser, databasePassword); err != nil {
		return PublicRecord{}, err
	}
	configPath := filepath.Join(record.Root, "config.php")
	config := mirzaBotConfig(record.Database, record.DatabaseUser, databasePassword, request.BotToken, request.AdminID, externalAppHostPath(record), botUsername)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		return PublicRecord{}, fmt.Errorf("write MirzaBot configuration: %w", err)
	}
	if err := os.Chown(configPath, uid, gid); err != nil {
		return PublicRecord{}, err
	}
	if len(request.DatabaseBackup) > 0 {
		if err := m.importExternalAppDatabase(ctx, record.Database, record.DatabaseUser, databasePassword, request.DatabaseBackup); err != nil {
			return PublicRecord{}, err
		}
	}
	if err := initializeMirzaBotDatabase(ctx, record.Root, record.SystemUser, uid, gid); err != nil {
		return PublicRecord{}, err
	}
	if err := m.verifyExternalAppDatabase(ctx, record.Database); err != nil {
		return PublicRecord{}, err
	}
	webhookSecret, err := randomHex(32)
	if err != nil {
		return PublicRecord{}, err
	}
	cronSecret, err := randomHex(24)
	if err != nil {
		return PublicRecord{}, err
	}
	if err := writeExternalAppSecretFile(record.Root, ".rebecca-cron-secret", cronSecret, uid, gid); err != nil {
		return PublicRecord{}, err
	}
	if err := writeExternalAppPool(record, true); err != nil {
		return PublicRecord{}, err
	}
	poolCreated = true
	if err := writeMirzaCron(record); err != nil {
		return PublicRecord{}, err
	}
	cronCreated = true
	if err := reloadPHPFPM(ctx, record); err != nil {
		return PublicRecord{}, err
	}
	secrets := secrets{BotToken: request.BotToken, WebhookSecret: webhookSecret, CronSecret: cronSecret}
	if err := m.writeSecrets(record, secrets); err != nil {
		return PublicRecord{}, err
	}
	if err := m.writeRecord(record); err != nil {
		return PublicRecord{}, err
	}
	rollbackRecord, err = m.withEnabledRecord(record, func() error {
		return m.setTelegramWebhook(ctx, request.BotToken, record, webhookSecret)
	})
	if err != nil {
		return PublicRecord{}, err
	}
	record.Enabled = true
	if err := m.writeRecord(record); err != nil {
		_ = m.deleteTelegramWebhook(context.Background(), request.BotToken)
		return PublicRecord{}, err
	}
	m.setRecord(record)
	completed = true
	return publicExternalAppRecord(record), nil
}

func (m *Manager) ensureBotTokenAvailable(token string) error {
	m.mu.RLock()
	records := make([]Record, 0, len(m.apps))
	for _, record := range m.apps {
		if record.Template == "mirzabot" {
			records = append(records, record)
		}
	}
	m.mu.RUnlock()
	for _, record := range records {
		secrets, err := m.readSecrets(record)
		if err != nil {
			return err
		}
		if subtleConstantStringEqual(secrets.BotToken, token) {
			return errors.New("this Telegram bot is already hosted")
		}
	}
	return nil
}

func subtleConstantStringEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func (m *Manager) AuthorizeMirzaRequest(r *http.Request, record Record, rel string) error {
	rel = strings.ToLower(filepath.ToSlash(rel))
	indexFile := strings.ToLower(externalAppIndexFile(record))
	if rel != indexFile && !strings.HasPrefix(rel, "cronbot/") {
		return nil
	}
	secrets, err := m.readSecrets(record)
	if err != nil {
		return err
	}
	var actual, expected string
	if rel == indexFile && r.Method == http.MethodPost {
		actual = strings.TrimSpace(r.Header.Get("X-Telegram-Bot-Api-Secret-Token"))
		expected = secrets.WebhookSecret
	} else if strings.HasPrefix(rel, "cronbot/") {
		actual = strings.TrimSpace(r.Header.Get("X-Rebecca-Cron-Secret"))
		expected = secrets.CronSecret
	} else {
		return nil
	}
	if expected == "" || !subtleConstantStringEqual(actual, expected) {
		return errors.New("invalid application secret")
	}
	return nil
}

func validateExternalAppIndexFile(record Record, rootPath, raw string) (string, error) {
	name, err := normalizeExternalAppPath(strings.TrimSpace(raw), false)
	if err != nil {
		return "", errors.New("default document must be a safe relative path")
	}
	switch strings.ToLower(path.Base(name)) {
	case "config.php", "table.php", "composer.json", "composer.lock", "install.sh":
		return "", errors.New("this file cannot be used as the default document")
	}
	extension := strings.ToLower(path.Ext(name))
	if extension != ".php" && extension != ".html" && extension != ".htm" {
		return "", errors.New("default document must be a PHP or HTML file")
	}
	if record.Runtime == "static" && extension == ".php" {
		return "", errors.New("static applications cannot use a PHP default document")
	}
	if record.Template == "mirzabot" && extension != ".php" {
		return "", errors.New("MirzaBot requires a PHP default document")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return "", err
	}
	defer root.Close()
	info, err := root.Lstat(filepath.FromSlash(name))
	if err != nil || !info.Mode().IsRegular() || FileHasMultipleLinks(info) {
		return "", errors.New("default document does not exist or is not a regular file")
	}
	return filepath.ToSlash(name), nil
}

func validateExternalAppNotFoundFile(rootPath, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	name, err := normalizeExternalAppPath(raw, false)
	if err != nil {
		return "", errors.New("404 document must be a safe relative path")
	}
	switch strings.ToLower(path.Base(name)) {
	case "config.php", "table.php", "composer.json", "composer.lock", "install.sh":
		return "", errors.New("this file cannot be used as the 404 document")
	}
	extension := strings.ToLower(path.Ext(name))
	if extension != ".html" && extension != ".htm" {
		return "", errors.New("404 document must be an HTML file")
	}
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return "", err
	}
	defer root.Close()
	info, err := root.Lstat(filepath.FromSlash(name))
	if err != nil || !info.Mode().IsRegular() || FileHasMultipleLinks(info) {
		return "", errors.New("404 document does not exist or is not a regular file")
	}
	return filepath.ToSlash(name), nil
}

func (m *Manager) updateSettings(identifier, indexFile string, fallbackToIndex bool, maxRequestBodyMB, staticCacheSeconds int, notFoundFile string) (PublicRecord, error) {
	if !m.operationMu.TryLock() {
		return PublicRecord{}, errExternalAppBusy
	}
	defer m.operationMu.Unlock()
	record, ok := m.Lookup(identifier)
	if !ok {
		return PublicRecord{}, errExternalAppNotFound
	}
	indexFile, err := validateExternalAppIndexFile(record, record.Root, indexFile)
	if err != nil {
		return PublicRecord{}, err
	}
	if maxRequestBodyMB < 1 || maxRequestBodyMB > defaultRequestBodyLimitMB {
		return PublicRecord{}, errors.New("request body limit must be between 1 and 32 MiB")
	}
	if staticCacheSeconds < 0 || staticCacheSeconds > maxStaticCacheSeconds {
		return PublicRecord{}, errors.New("static cache lifetime must be between 0 and 31536000 seconds")
	}
	notFoundFile, err = validateExternalAppNotFoundFile(record.Root, notFoundFile)
	if err != nil {
		return PublicRecord{}, err
	}
	record.IndexFile = indexFile
	record.FallbackToIndex = fallbackToIndex
	record.MaxRequestBodyMB = maxRequestBodyMB
	record.StaticCacheSeconds = &staticCacheSeconds
	record.NotFoundFile = notFoundFile
	if err := m.writeRecord(record); err != nil {
		return PublicRecord{}, err
	}
	m.setRecord(record)
	return publicExternalAppRecord(record), nil
}

func patchMirzaMiniApp(root, mountPath string) error {
	if !externalAppPathPattern.MatchString(mountPath) {
		return fmt.Errorf("invalid MirzaBot mount path %q", mountPath)
	}
	appRoot := filepath.Join(root, "app")
	if _, err := os.Stat(appRoot); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("prepare MirzaBot Mini App: %w", err)
	}
	indexPath := filepath.Join(appRoot, "index.php")
	index, err := os.ReadFile(indexPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("prepare MirzaBot Mini App: %w", err)
	}
	apiOrigin := "/" + mountPath
	appPath := apiOrigin + "/app/"
	bootstrap := []byte(`<script>window.__MIRZA_API_ORIGIN=window.location.origin+"` + apiOrigin + `";window.__MIRZA_APP_PATH="` + appPath + `";</script>`)
	if !bytes.Contains(index, []byte("__MIRZA_API_ORIGIN")) {
		marker := []byte("</head>")
		at := bytes.Index(index, marker)
		if at < 0 {
			return errors.New("prepare MirzaBot Mini App: app/index.php has no head element")
		}
		updated := make([]byte, 0, len(index)+len(bootstrap))
		updated = append(updated, index[:at]...)
		updated = append(updated, bootstrap...)
		updated = append(updated, index[at:]...)
		if err := os.WriteFile(indexPath, updated, 0o644); err != nil {
			return err
		}
	}

	assetsRoot := filepath.Join(appRoot, "assets")
	if _, err := os.Stat(assetsRoot); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("prepare MirzaBot Mini App: %w", err)
	}
	return filepath.WalkDir(assetsRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 || !strings.EqualFold(filepath.Ext(entry.Name()), ".js") {
			return nil
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		const patchMarker = "/* rebecca-mirza-mounted */"
		if strings.Contains(string(content), patchMarker) {
			return nil
		}
		updated := []byte(strings.NewReplacer(
			`window.location.origin+"/api/`, `window.__MIRZA_API_ORIGIN+"/`,
			`window.location.origin+"/api"`, `window.__MIRZA_API_ORIGIN||window.location.origin+"/api"`,
			`window.location.pathname!=="/app/"`, `window.location.pathname!==window.__MIRZA_APP_PATH`,
			`window.location.href="/app/"`, `window.location.href=window.__MIRZA_APP_PATH`,
		).Replace(string(content)))
		if bytes.Equal(content, updated) {
			return nil
		}
		updated = append([]byte(patchMarker+"\n"), updated...)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		return os.WriteFile(path, updated, info.Mode().Perm())
	})
}

func (m *Manager) updateMirzaBot(ctx context.Context, identifier string) (PublicRecord, error) {
	if !m.operationMu.TryLock() {
		return PublicRecord{}, errExternalAppBusy
	}
	defer m.operationMu.Unlock()
	record, ok := m.Lookup(identifier)
	if !ok {
		return PublicRecord{}, errExternalAppNotFound
	}
	if record.Template != "mirzabot" {
		return PublicRecord{}, errors.New("only MirzaBot applications support automatic updates")
	}
	source, err := m.downloadMirzaBot(ctx)
	if err != nil {
		return PublicRecord{}, err
	}
	m.releaseMu.Lock()
	m.release = mirzaBotRelease{Version: source.Version, SHA: source.SHA}
	m.releaseUntil = time.Now().Add(10 * time.Minute)
	m.releaseMu.Unlock()
	if !mirzaBotUpdateAvailable(record, mirzaBotRelease{Version: source.Version, SHA: source.SHA}) {
		return PublicRecord{}, errExternalAppUpToDate
	}
	config, err := os.ReadFile(filepath.Join(record.Root, "config.php"))
	if err != nil {
		return PublicRecord{}, fmt.Errorf("preserve MirzaBot configuration: %w", err)
	}
	storedSecrets, err := m.readSecrets(record)
	if err != nil {
		return PublicRecord{}, err
	}
	uid, gid, err := unixUserIDs(ctx, record.SystemUser)
	if err != nil {
		return PublicRecord{}, err
	}
	stage, err := os.MkdirTemp(m.baseDir, ".mirzabot-update-")
	if err != nil {
		return PublicRecord{}, err
	}
	defer os.RemoveAll(stage)
	if err := os.Chmod(stage, 0o711); err != nil {
		return PublicRecord{}, err
	}
	nextRoot, err := extractMirzaBotArchive(source.Archive, stage)
	if err != nil {
		return PublicRecord{}, err
	}
	if err := removeMirzaBotInstaller(nextRoot); err != nil {
		return PublicRecord{}, err
	}
	if err := patchMirzaMiniApp(nextRoot, record.Path); err != nil {
		return PublicRecord{}, err
	}
	if err := prepareOwnedExternalAppTree(nextRoot, uid, gid); err != nil {
		return PublicRecord{}, err
	}
	configPath := filepath.Join(nextRoot, "config.php")
	if err := os.Remove(configPath); err != nil {
		return PublicRecord{}, err
	}
	if err := os.WriteFile(configPath, config, 0o600); err != nil {
		return PublicRecord{}, fmt.Errorf("restore MirzaBot configuration: %w", err)
	}
	if err := os.Chown(configPath, uid, gid); err != nil {
		return PublicRecord{}, err
	}
	if err := writeExternalAppSecretFile(nextRoot, ".rebecca-cron-secret", storedSecrets.CronSecret, uid, gid); err != nil {
		return PublicRecord{}, err
	}
	if err := installMirzaBotDependencies(ctx, nextRoot, record.SystemUser); err != nil {
		return PublicRecord{}, err
	}
	if _, err := validateExternalAppIndexFile(record, nextRoot, externalAppIndexFile(record)); err != nil {
		return PublicRecord{}, fmt.Errorf("preserve application settings: %w", err)
	}
	if err := initializeMirzaBotDatabase(ctx, nextRoot, record.SystemUser, uid, gid); err != nil {
		return PublicRecord{}, err
	}
	if err := m.verifyExternalAppDatabase(ctx, record.Database); err != nil {
		return PublicRecord{}, err
	}

	previousRoot := filepath.Join(stage, ".previous")
	if err := os.Rename(record.Root, previousRoot); err != nil {
		return PublicRecord{}, fmt.Errorf("stage current MirzaBot files: %w", err)
	}
	if err := os.Rename(nextRoot, record.Root); err != nil {
		_ = os.Rename(previousRoot, record.Root)
		return PublicRecord{}, fmt.Errorf("activate MirzaBot update: %w", err)
	}
	rollback := func() error {
		failedRoot := filepath.Join(stage, ".failed")
		if err := os.Rename(record.Root, failedRoot); err != nil {
			return err
		}
		if err := os.Rename(previousRoot, record.Root); err != nil {
			_ = os.Rename(failedRoot, record.Root)
			return err
		}
		return nil
	}
	if err := reloadPHPFPM(ctx, record); err != nil {
		if rollbackErr := rollback(); rollbackErr != nil {
			return PublicRecord{}, fmt.Errorf("reload PHP-FPM after update: %v; rollback failed: %w", err, rollbackErr)
		}
		_ = reloadPHPFPM(context.Background(), record)
		return PublicRecord{}, err
	}
	updated := record
	updated.Version = source.Version
	updated.SourceSHA = source.SHA
	if updated.Enabled {
		if err := m.setTelegramWebhook(ctx, storedSecrets.BotToken, updated, storedSecrets.WebhookSecret); err != nil {
			if rollbackErr := rollback(); rollbackErr != nil {
				return PublicRecord{}, fmt.Errorf("update Telegram webhook: %v; rollback failed: %w", err, rollbackErr)
			}
			_ = reloadPHPFPM(context.Background(), record)
			return PublicRecord{}, fmt.Errorf("update Telegram webhook: %w", err)
		}
	}
	if err := m.writeRecord(updated); err != nil {
		if rollbackErr := rollback(); rollbackErr != nil {
			return PublicRecord{}, fmt.Errorf("save MirzaBot version: %v; rollback failed: %w", err, rollbackErr)
		}
		_ = reloadPHPFPM(context.Background(), record)
		return PublicRecord{}, err
	}
	m.setRecord(updated)
	return publicExternalAppRecord(updated), nil
}

func (m *Manager) setEnabled(ctx context.Context, identifier string, enabled bool) (PublicRecord, error) {
	if !m.operationMu.TryLock() {
		return PublicRecord{}, errExternalAppBusy
	}
	defer m.operationMu.Unlock()
	record, ok := m.Lookup(identifier)
	if !ok {
		return PublicRecord{}, errExternalAppNotFound
	}
	var rollbackRecord func()
	if enabled {
		if _, err := m.certificateDomain(ctx, record.Domain); err != nil {
			return PublicRecord{}, err
		}
		if record.Template == "mirzabot" {
			secrets, err := m.readSecrets(record)
			if err != nil {
				return PublicRecord{}, err
			}
			rollbackRecord, err = m.withEnabledRecord(record, func() error {
				if err := m.setTelegramWebhook(ctx, secrets.BotToken, record, secrets.WebhookSecret); err != nil {
					return err
				}
				if err := writeMirzaCron(record); err != nil {
					_ = m.deleteTelegramWebhook(context.Background(), secrets.BotToken)
					return err
				}
				return nil
			})
			if err != nil {
				return PublicRecord{}, err
			}
		}
		if record.Runtime == "node" {
			if err := startExternalAppNode(ctx, record); err != nil {
				return PublicRecord{}, err
			}
		}
		record.Enabled = true
	} else {
		if record.Runtime == "node" {
			if err := stopExternalAppNode(ctx, record); err != nil {
				return PublicRecord{}, err
			}
		}
		record.Enabled = false
	}
	if err := m.writeRecord(record); err != nil {
		if rollbackRecord != nil {
			rollbackRecord()
		}
		if record.Runtime == "node" {
			if enabled {
				_ = stopExternalAppNode(context.Background(), record)
			} else {
				_ = startExternalAppNode(context.Background(), record)
			}
		}
		if enabled && record.Template == "mirzabot" {
			_ = os.Remove(record.CronConfig)
			if secrets, secretErr := m.readSecrets(record); secretErr == nil {
				_ = m.deleteTelegramWebhook(context.Background(), secrets.BotToken)
			}
		}
		return PublicRecord{}, err
	}
	m.setRecord(record)
	if !enabled && record.Template == "mirzabot" {
		if err := os.Remove(record.CronConfig); err != nil && !os.IsNotExist(err) {
			return publicExternalAppRecord(record), err
		}
		secrets, err := m.readSecrets(record)
		if err != nil {
			return publicExternalAppRecord(record), err
		}
		if err := m.deleteTelegramWebhook(ctx, secrets.BotToken); err != nil {
			return publicExternalAppRecord(record), err
		}
	}
	return publicExternalAppRecord(record), nil
}

func (m *Manager) delete(ctx context.Context, identifier string, keepDatabase bool) error {
	if !m.operationMu.TryLock() {
		return errExternalAppBusy
	}
	defer m.operationMu.Unlock()
	record, ok := m.Lookup(identifier)
	if !ok {
		return errExternalAppNotFound
	}
	record.Enabled = false
	if err := m.writeRecord(record); err != nil {
		return err
	}
	m.setRecord(record)
	if record.Template == "mirzabot" {
		if secrets, err := m.readSecrets(record); err == nil {
			_ = m.deleteTelegramWebhook(ctx, secrets.BotToken)
		}
	}
	if record.CronConfig != "" {
		if err := os.Remove(record.CronConfig); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if record.PoolConfig != "" {
		if err := os.Remove(record.PoolConfig); err != nil && !os.IsNotExist(err) {
			return err
		}
		if _, err := runExternalAppCommand(ctx, time.Minute, "systemctl", "reload", record.Service); err != nil {
			return fmt.Errorf("reload PHP-FPM: %w", err)
		}
	}
	if record.UnitConfig != "" {
		if err := stopExternalAppNode(ctx, record); err != nil {
			return err
		}
		if err := os.Remove(record.UnitConfig); err != nil && !os.IsNotExist(err) {
			return err
		}
		if _, err := runExternalAppCommand(ctx, time.Minute, "systemctl", "daemon-reload"); err != nil {
			return fmt.Errorf("reload systemd: %w", err)
		}
	}
	if record.Database != "" && !keepDatabase {
		if err := m.dropExternalAppDatabase(ctx, record.Database, record.DatabaseUser); err != nil {
			return err
		}
	}
	if err := os.RemoveAll(record.Root); err != nil {
		return err
	}
	if record.SystemUser != "" {
		if _, err := runExternalAppCommand(ctx, time.Minute, "userdel", record.SystemUser); err != nil && externalAppSystemUserExists(ctx, record.SystemUser) {
			return fmt.Errorf("remove isolated application user: %w", err)
		}
	}
	if err := os.Remove(m.recordPathFor(record)); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(m.secretPathFor(record)); err != nil && !os.IsNotExist(err) {
		return err
	}
	m.removeRecord(record.ID)
	return nil
}

func (m *Manager) prepareStorage() error {
	for _, dir := range []string{m.baseDir, m.appsDir(), m.metadataDir(), m.secretsDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("prepare external application storage: %w", err)
		}
	}
	if err := os.Chmod(m.baseDir, 0o711); err != nil {
		return err
	}
	return os.Chmod(m.appsDir(), 0o711)
}

func (m *Manager) writeRecord(record Record) error {
	return writePrivateJSON(m.recordPathFor(record), record)
}

func (m *Manager) writeSecrets(record Record, secrets secrets) error {
	return writePrivateJSON(m.secretPathFor(record), secrets)
}

func (m *Manager) readSecrets(record Record) (secrets, error) {
	data, err := os.ReadFile(m.secretPathFor(record))
	if err != nil {
		return secrets{}, fmt.Errorf("read external application secrets: %w", err)
	}
	var stored secrets
	if err := json.Unmarshal(data, &stored); err != nil {
		return secrets{}, errors.New("external application secrets are invalid")
	}
	return stored, nil
}

func (m *Manager) appsDir() string     { return filepath.Join(m.baseDir, "apps") }
func (m *Manager) metadataDir() string { return filepath.Join(m.baseDir, ".metadata") }
func (m *Manager) secretsDir() string  { return filepath.Join(m.baseDir, ".secrets") }
func (m *Manager) recordPath(suffix string) string {
	return filepath.Join(m.metadataDir(), suffix+".json")
}
func (m *Manager) secretPath(suffix string) string {
	return filepath.Join(m.secretsDir(), suffix+".json")
}

func (m *Manager) recordPathFor(record Record) string {
	base := record.storageBase
	if base == "" {
		base = m.baseDir
	}
	return filepath.Join(base, ".metadata", record.ID+".json")
}

func (m *Manager) secretPathFor(record Record) string {
	base := record.storageBase
	if base == "" {
		base = m.baseDir
	}
	return filepath.Join(base, ".secrets", record.ID+".json")
}

func writePrivateJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".record-*.tmp")
	if err != nil {
		return err
	}
	name := temp.Name()
	defer os.Remove(name)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (m *Manager) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if m == nil {
		writeError(w, http.StatusServiceUnavailable, "external application manager is unavailable")
		return
	}
	requestPath := externalAppAPIPath(r.URL.Path)
	if m.sqliteDisabled() {
		if requestPath == "" && r.Method == http.MethodGet {
			writeJSON(w, http.StatusOK, map[string]any{
				"supported": false,
				"detail":    externalAppsSQLiteDetail,
				"templates": []map[string]any{
					{"id": "archive", "name": "PHP / HTML ZIP", "supported": false, "detail": externalAppsSQLiteDetail},
					{"id": "mirzabot", "name": "MirzaBot", "supported": false, "detail": externalAppsSQLiteDetail},
				},
				"apps": []PublicRecord{},
			})
			return
		}
		writeError(w, http.StatusConflict, externalAppsSQLiteDetail)
		return
	}
	if requestPath == "" {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		supported, detail := m.hostingSupported()
		mirzaSupported, mirzaDetail := m.mirzaSupported()
		releaseCtx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		release, _ := m.cachedMirzaBotRelease(releaseCtx)
		cancel()
		apps := m.publicRecords()
		for index := range apps {
			record := Record{Template: apps[index].Template, Version: apps[index].Version, SourceSHA: apps[index].SourceSHA}
			if mirzaBotUpdateAvailable(record, release) {
				apps[index].UpdateAvailable = true
				apps[index].LatestVersion = release.Version
			}
		}
		mirzaVersion := "latest"
		mirzaSourceURL := mirzaBotRepositoryURL + "/tags"
		if release.Version != "" {
			mirzaVersion = release.Version
			mirzaSourceURL = mirzaBotRepositoryURL + "/releases/tag/" + url.PathEscape(release.Version)
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"supported": supported,
			"detail":    detail,
			"templates": []map[string]any{
				{"id": "archive", "name": "PHP / HTML ZIP", "supported": supported},
				{"id": "mirzabot", "name": "MirzaBot", "version": mirzaVersion, "source_sha": release.SHA, "source_url": mirzaSourceURL, "supported": mirzaSupported, "detail": mirzaDetail},
			},
			"apps": apps,
		})
		return
	}
	switch requestPath {
	case "archive":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		m.handleExternalAppArchiveInstall(w, r)
		return
	case "mirzabot":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		payload, err := decodeMirzaInstallRequest(r)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if externalAppUsesCurrentPanelHost(r, payload.Domain) {
			writeError(w, http.StatusBadRequest, "the current panel hostname cannot be replaced by an application")
			return
		}
		record, err := m.installMirzaBot(r.Context(), payload)
		if err != nil {
			writeExternalAppError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, record)
		return
	}
	parts := strings.Split(requestPath, "/")
	identifier, err := url.PathUnescape(parts[0])
	if err != nil || identifier == "" {
		writeError(w, http.StatusBadRequest, "invalid application ID")
		return
	}
	if len(parts) >= 2 && parts[1] == "files" {
		m.handleExternalAppFiles(w, r, identifier, parts[2:])
		return
	}
	if len(parts) == 2 && parts[1] == "database-backup" {
		m.handleExternalAppDatabaseBackup(w, r, identifier)
		return
	}
	if len(parts) == 2 && parts[1] == "php-config" {
		m.handleExternalAppConfig(w, r, identifier)
		return
	}
	if len(parts) == 2 && parts[1] == "settings" {
		if r.Method != http.MethodPut {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var payload struct {
			IndexFile          string  `json:"index_file"`
			FallbackToIndex    bool    `json:"fallback_to_index"`
			MaxRequestBodyMB   *int    `json:"max_request_body_mb"`
			StaticCacheSeconds *int    `json:"static_cache_seconds"`
			NotFoundFile       *string `json:"not_found_file"`
		}
		if err := decodeOptionalJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		current, ok := m.Lookup(identifier)
		if !ok {
			writeExternalAppError(w, errExternalAppNotFound)
			return
		}
		maxRequestBodyMB := externalAppMaxRequestBodyMB(current)
		if payload.MaxRequestBodyMB != nil {
			maxRequestBodyMB = *payload.MaxRequestBodyMB
		}
		staticCacheSeconds := ExternalAppStaticCacheSeconds(current)
		if payload.StaticCacheSeconds != nil {
			staticCacheSeconds = *payload.StaticCacheSeconds
		}
		notFoundFile := current.NotFoundFile
		if payload.NotFoundFile != nil {
			notFoundFile = *payload.NotFoundFile
		}
		record, err := m.updateSettings(identifier, payload.IndexFile, payload.FallbackToIndex, maxRequestBodyMB, staticCacheSeconds, notFoundFile)
		if err != nil {
			writeExternalAppError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, record)
		return
	}
	if len(parts) == 2 && parts[1] == "update" {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		record, err := m.updateMirzaBot(r.Context(), identifier)
		if err != nil {
			writeExternalAppError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, record)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodDelete {
		var payload struct {
			KeepDatabase bool `json:"keep_database"`
		}
		if err := decodeOptionalJSON(r, &payload); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := m.delete(r.Context(), identifier, payload.KeepDatabase); err != nil {
			writeExternalAppError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if len(parts) != 2 || r.Method != http.MethodPost || (parts[1] != "enable" && parts[1] != "disable") {
		writeError(w, http.StatusNotFound, "not found")
		return
	}
	record, err := m.setEnabled(r.Context(), identifier, parts[1] == "enable")
	if err != nil {
		writeExternalAppError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, record)
}

func (m *Manager) handleExternalAppDatabaseBackup(w http.ResponseWriter, r *http.Request, identifier string) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !m.operationMu.TryLock() {
		writeExternalAppError(w, errExternalAppBusy)
		return
	}
	record, ok := m.Lookup(identifier)
	if !ok {
		m.operationMu.Unlock()
		writeExternalAppError(w, errExternalAppNotFound)
		return
	}
	if record.Template != "mirzabot" || record.Database == "" {
		m.operationMu.Unlock()
		writeError(w, http.StatusBadRequest, "database backup is available only for MirzaBot applications")
		return
	}
	dump, err := m.dumpExternalAppDatabase(r.Context(), record.Database)
	m.operationMu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	name := dump.Name()
	defer func() {
		_ = dump.Close()
		_ = os.Remove(name)
	}()
	info, err := dump.Stat()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read database backup")
		return
	}
	filename := fmt.Sprintf("mirzabot-%s-%s.sql", record.ID, time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	w.Header().Set("Content-Type", "application/sql")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, filename, info.ModTime(), dump)
}

func decodeMirzaInstallRequest(r *http.Request) (InstallRequest, error) {
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "multipart/form-data") {
		var payload InstallRequest
		if err := decodeOptionalJSON(r, &payload); err != nil {
			return InstallRequest{}, err
		}
		return payload, nil
	}
	if err := r.ParseMultipartForm(MaxRequestBodyBytes); err != nil {
		return InstallRequest{}, errors.New("invalid multipart upload")
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	payload := InstallRequest{
		Domain:   r.FormValue("domain"),
		BotToken: r.FormValue("bot_token"),
		AdminID:  r.FormValue("admin_id"),
	}
	file, _, err := r.FormFile("database_backup")
	if errors.Is(err, http.ErrMissingFile) {
		return payload, nil
	}
	if err != nil {
		return InstallRequest{}, errors.New("invalid SQL backup upload")
	}
	defer file.Close()
	payload.DatabaseBackup, err = io.ReadAll(io.LimitReader(file, maxExternalAppArchiveBytes+1))
	if err != nil {
		return InstallRequest{}, errors.New("read SQL backup")
	}
	if len(payload.DatabaseBackup) == 0 || len(payload.DatabaseBackup) > maxExternalAppArchiveBytes {
		return InstallRequest{}, errors.New("SQL backup is empty or exceeds 32 MiB")
	}
	return payload, nil
}

func externalAppAPIPath(requestPath string) string {
	return strings.Trim(strings.TrimPrefix(requestPath, "/api/settings/external-apps"), "/")
}

func decodeArchiveInstallRequest(r *http.Request) (ArchiveInstallRequest, error) {
	if err := r.ParseMultipartForm(MaxRequestBodyBytes); err != nil {
		return ArchiveInstallRequest{}, errors.New("invalid multipart upload")
	}
	if r.MultipartForm != nil {
		defer r.MultipartForm.RemoveAll()
	}
	request := ArchiveInstallRequest{
		Domain:           r.FormValue("domain"),
		Name:             r.FormValue("name"),
		Runtime:          r.FormValue("runtime"),
		Database:         r.FormValue("database"),
		DatabaseUser:     r.FormValue("database_user"),
		DatabasePassword: r.FormValue("database_password"),
	}
	if value := strings.TrimSpace(r.FormValue("create_database")); value != "" {
		createDatabase, err := strconv.ParseBool(value)
		if err != nil {
			return ArchiveInstallRequest{}, errors.New("invalid database option")
		}
		request.CreateDatabase = createDatabase
	}
	file, _, err := r.FormFile("archive")
	if errors.Is(err, http.ErrMissingFile) {
		return request, nil
	}
	if err != nil {
		return ArchiveInstallRequest{}, errors.New("invalid ZIP archive upload")
	}
	defer file.Close()
	request.Archive, err = io.ReadAll(io.LimitReader(file, maxExternalAppArchiveBytes+1))
	if err != nil {
		return ArchiveInstallRequest{}, errors.New("read ZIP archive")
	}
	if len(request.Archive) == 0 {
		return ArchiveInstallRequest{}, errors.New("ZIP archive is empty")
	}
	if len(request.Archive) > maxExternalAppArchiveBytes {
		return ArchiveInstallRequest{}, errors.New("ZIP archive exceeds 32 MiB")
	}
	return request, nil
}

func (m *Manager) handleExternalAppArchiveInstall(w http.ResponseWriter, r *http.Request) {
	request, err := decodeArchiveInstallRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if externalAppUsesCurrentPanelHost(r, request.Domain) {
		writeError(w, http.StatusBadRequest, "the current panel hostname cannot be replaced by an application")
		return
	}
	record, err := m.installArchive(r.Context(), request)
	if err != nil {
		writeExternalAppError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, record)
}

func externalAppUsesCurrentPanelHost(r *http.Request, domain string) bool {
	domain = CanonicalHost(domain)
	return domain != "" && domain == CanonicalHost(r.Host)
}

func writeExternalAppError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errExternalAppNotFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, errExternalAppBusy), errors.Is(err, errExternalAppExists), errors.Is(err, errExternalAppUpToDate):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, errExternalAppUnsupported):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	default:
		writeError(w, http.StatusBadRequest, err.Error())
	}
}

func decodeOptionalJSON(r *http.Request, target any) error {
	if r.Body == nil {
		return nil
	}
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(target); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, detail string) {
	writeJSON(w, status, map[string]any{"detail": detail})
}

func normalizeExternalAppName(value, domain string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return domain
	}
	runes := []rune(value)
	if len(runes) > 80 {
		runes = runes[:80]
	}
	return string(runes)
}

func sha256Hex(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func randomHex(bytesCount int) (string, error) {
	data := make([]byte, bytesCount)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func domainHash(domain string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(domain)))
	return hex.EncodeToString(digest[:6])
}

func extractMirzaBotArchive(data []byte, destination string) (string, error) {
	root, err := extractZIPArchive(data, destination, true)
	if err != nil {
		return "", err
	}
	for _, required := range []string{"composer.json", "composer.lock", "table.php", "config.php", "index.php"} {
		if info, err := os.Stat(filepath.Join(root, required)); err != nil || info.IsDir() {
			return "", fmt.Errorf("MirzaBot archive is missing %s", required)
		}
	}
	return root, nil
}

func extractExternalAppArchive(data []byte, destination string) (string, error) {
	return extractZIPArchive(data, destination, false)
}

func extractZIPArchive(data []byte, destination string, requireSingleRoot bool) (string, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return "", errors.New("upload is not a valid ZIP archive")
	}
	if len(reader.File) == 0 || len(reader.File) > maxExternalAppFiles {
		return "", errors.New("ZIP archive has an invalid file count")
	}
	rootName := ""
	singleRoot := true
	var total uint64
	for _, entry := range reader.File {
		name := strings.ReplaceAll(entry.Name, "\\", "/")
		clean := filepath.ToSlash(filepath.Clean(name))
		if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") || strings.HasPrefix(clean, "/") {
			return "", errors.New("ZIP archive contains an unsafe path")
		}
		parts := strings.Split(clean, "/")
		if rootName == "" {
			rootName = parts[0]
		} else if parts[0] != rootName {
			singleRoot = false
		}
		if len(parts) == 1 && !entry.FileInfo().IsDir() {
			singleRoot = false
		}
		mode := entry.Mode()
		if mode&os.ModeSymlink != 0 || mode&(os.ModeDevice|os.ModeNamedPipe|os.ModeSocket) != 0 {
			return "", errors.New("ZIP archive contains an unsupported file type")
		}
		total += entry.UncompressedSize64
		if total > maxExternalAppExtractedSize {
			return "", errors.New("ZIP archive exceeds the 256 MiB extracted size limit")
		}
		target := filepath.Join(destination, filepath.FromSlash(clean))
		if !pathWithin(destination, target) {
			return "", errors.New("ZIP archive escaped the staging directory")
		}
		if entry.FileInfo().IsDir() {
			if err := os.MkdirAll(target, 0o755); err != nil {
				return "", err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return "", err
		}
		source, err := entry.Open()
		if err != nil {
			return "", err
		}
		file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			source.Close()
			return "", err
		}
		written, copyErr := io.Copy(file, io.LimitReader(source, int64(entry.UncompressedSize64)+1))
		closeErr := file.Close()
		source.Close()
		if copyErr != nil || closeErr != nil || written != int64(entry.UncompressedSize64) {
			return "", errors.New("extract ZIP archive")
		}
	}
	if requireSingleRoot && !singleRoot {
		return "", errors.New("template archive has multiple roots")
	}
	if singleRoot {
		root := filepath.Join(destination, rootName)
		if info, err := os.Stat(root); err == nil && info.IsDir() {
			return root, nil
		}
	}
	return destination, nil
}

func detectExternalAppRuntime(root string) (string, error) {
	if data, err := os.ReadFile(filepath.Join(root, "package.json")); err == nil {
		var manifest struct {
			Scripts map[string]string `json:"scripts"`
		}
		if json.Unmarshal(data, &manifest) != nil || strings.TrimSpace(manifest.Scripts["start"]) == "" {
			return "", errors.New("Node.js archive package.json must define a start script")
		}
		return "node", nil
	}
	runtime := "static"
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.EqualFold(filepath.Ext(path), ".php") {
			runtime = "php"
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	index := "index.html"
	if runtime == "php" {
		index = "index.php"
		if _, err := os.Stat(filepath.Join(root, index)); err != nil {
			if _, htmlErr := os.Stat(filepath.Join(root, "index.html")); htmlErr != nil {
				return "", errors.New("PHP archive must contain index.php or index.html at its root")
			}
		}
	} else if _, err := os.Stat(filepath.Join(root, index)); err != nil {
		return "", errors.New("HTML archive must contain index.html at its root")
	}
	return runtime, nil
}

func CanonicalHost(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if parsed, err := url.Parse("//" + host); err == nil && parsed.Hostname() != "" {
		host = parsed.Hostname()
	}
	return strings.TrimSuffix(host, ".")
}

func pathWithin(root, candidate string) bool {
	root, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return false
	}
	candidate, err = filepath.Abs(filepath.Clean(candidate))
	if err != nil {
		return false
	}
	return candidate == root || strings.HasPrefix(candidate, root+string(os.PathSeparator))
}

func pathWithinResolved(root, candidate string) bool {
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return false
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	return err == nil && pathWithin(resolvedRoot, resolvedCandidate)
}

func isLocalDatabaseHost(host string) bool {
	switch strings.ToLower(strings.TrimSpace(host)) {
	case "127.0.0.1", "localhost", "::1":
		return true
	default:
		return false
	}
}
