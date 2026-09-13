package externalapps

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	certificateapp "github.com/rebeccapanel/rebecca/internal/app/certificates"
)

func TestExtractExternalAppArchiveAndDetectRuntime(t *testing.T) {
	archive := externalAppTestZIP(t, map[string]string{
		"site/index.php":        "<?php echo 'ok';",
		"site/assets/style.css": "body{}",
	})
	root, err := extractExternalAppArchive(archive, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(root) != "site" {
		t.Fatalf("root=%q", root)
	}
	runtime, err := detectExternalAppRuntime(root)
	if err != nil || runtime != "php" {
		t.Fatalf("runtime=%q err=%v", runtime, err)
	}
}

func TestDetectNodeRuntimeAndLoopbackUnit(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"scripts":{"start":"next start"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime, err := detectExternalAppRuntime(root)
	if err != nil || runtime != "node" {
		t.Fatalf("runtime=%q err=%v", runtime, err)
	}
	record := Record{ID: "0123456789ab", Domain: "app.example.com", Root: root, SystemUser: "rbnode_0123456789ab", Port: externalAppNodePort("0123456789ab")}
	unit := externalAppNodeUnit(record)
	if !strings.Contains(unit, "EnvironmentFile=-"+root+"/.env") || !strings.Contains(unit, "Environment=HOST=127.0.0.1") || !strings.Contains(unit, "Environment=PORT="+strconv.Itoa(record.Port)) {
		t.Fatalf("Node.js service is not bound to its assigned loopback address:\n%s", unit)
	}
}

func TestExtractExternalAppArchiveRejectsUnsafeContent(t *testing.T) {
	t.Run("traversal", func(t *testing.T) {
		archive := externalAppTestZIP(t, map[string]string{"../escape.php": "bad"})
		if _, err := extractExternalAppArchive(archive, t.TempDir()); err == nil {
			t.Fatal("traversal archive was accepted")
		}
	})
	t.Run("missing index", func(t *testing.T) {
		archive := externalAppTestZIP(t, map[string]string{"site/readme.txt": "no index"})
		root, err := extractExternalAppArchive(archive, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := detectExternalAppRuntime(root); err == nil {
			t.Fatal("archive without an index was accepted")
		}
	})
}

func TestExternalAppDefaultDocumentSettings(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "apps", "0123456789ab")
	if err := os.MkdirAll(filepath.Join(root, "public"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "public", "home.php"), []byte("<?php"), 0o600); err != nil {
		t.Fatal(err)
	}
	record := Record{
		ID: "0123456789ab", Template: "archive", Domain: "app.example.com", Runtime: "php", Root: root, storageBase: base,
	}
	manager := &Manager{baseDir: base, apps: map[string]Record{record.ID: record}}
	if err := os.WriteFile(filepath.Join(root, "404.html"), []byte("missing"), 0o600); err != nil {
		t.Fatal(err)
	}
	updated, err := manager.updateSettings(record.ID, "public/home.php", true, 8, 0, "404.html")
	if err != nil {
		t.Fatal(err)
	}
	if updated.IndexFile != "public/home.php" || !updated.FallbackToIndex || updated.MaxRequestBodyMB != 8 || updated.StaticCacheSeconds != 0 || updated.NotFoundFile != "404.html" {
		t.Fatalf("settings=%+v", updated)
	}
	for _, invalid := range []string{"../home.php", "config.php", "missing.php", "public/home.txt"} {
		if _, err := manager.updateSettings(record.ID, invalid, false, 8, 0, ""); err == nil {
			t.Fatalf("invalid default document %q was accepted", invalid)
		}
	}
	if _, err := manager.updateSettings(record.ID, "public/home.php", false, 0, 0, ""); err == nil {
		t.Fatal("zero request body limit was accepted")
	}
	if _, err := manager.updateSettings(record.ID, "public/home.php", false, 8, -1, ""); err == nil {
		t.Fatal("negative cache lifetime was accepted")
	}
	if _, err := manager.updateSettings(record.ID, "public/home.php", false, 8, 0, "public/home.php"); err == nil {
		t.Fatal("PHP 404 document was accepted")
	}
	request := httptest.NewRequest(
		http.MethodPut,
		"/api/settings/external-apps/"+record.ID+"/settings",
		strings.NewReader(`{"index_file":"public/home.php","fallback_to_index":false}`),
	)
	response := httptest.NewRecorder()
	manager.ServeHTTP(response, request)
	var compatible PublicRecord
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &compatible) != nil {
		t.Fatalf("legacy settings response=%d %q", response.Code, response.Body.String())
	}
	if compatible.MaxRequestBodyMB != 8 || compatible.StaticCacheSeconds != 0 || compatible.NotFoundFile != "404.html" {
		t.Fatalf("legacy settings lost new values: %+v", compatible)
	}
}

func TestMirzaBotUpdateAvailabilityUsesPinnedCommit(t *testing.T) {
	release := mirzaBotRelease{Version: "0.3.2", SHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
	current := Record{Template: "mirzabot", Version: "0.3.1", SourceSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	if !mirzaBotUpdateAvailable(current, release) {
		t.Fatal("new release commit was not detected")
	}
	current.Version, current.SourceSHA = release.Version, release.SHA
	if mirzaBotUpdateAvailable(current, release) {
		t.Fatal("current release was marked as outdated")
	}
	current.Version, current.SourceSHA = "0.3.2", "cccccccccccccccccccccccccccccccccccccccc"
	if mirzaBotUpdateAvailable(current, release) {
		t.Fatal("newer installation was offered a downgrade")
	}
	current.Version, current.SourceSHA = "0.3.2", "dddddddddddddddddddddddddddddddddddddddd"
	release.Version, release.SHA = "0.3.2", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	if mirzaBotUpdateAvailable(current, release) {
		t.Fatal("same version with a different commit was offered automatically")
	}
}

func TestExternalAppsResponseMarksMirzaBotUpdate(t *testing.T) {
	record := Record{
		ID: "0123456789ab", Template: "mirzabot", Domain: "bot.example.com", Runtime: "php",
		Version: "0.3.1", SourceSHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	manager := &Manager{
		baseDir: t.TempDir(), apps: map[string]Record{record.ID: record},
		release:      mirzaBotRelease{Version: "0.3.2", SHA: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
		releaseUntil: time.Now().Add(time.Minute),
	}
	request := httptest.NewRequest(http.MethodGet, "/api/settings/external-apps", nil)
	response := httptest.NewRecorder()
	manager.ServeHTTP(response, request)
	var payload struct {
		Apps []PublicRecord `json:"apps"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &payload) != nil {
		t.Fatalf("response=%d %q", response.Code, response.Body.String())
	}
	if len(payload.Apps) != 1 || !payload.Apps[0].UpdateAvailable || payload.Apps[0].LatestVersion != "0.3.2" {
		t.Fatalf("apps=%+v", payload.Apps)
	}
}

func TestExternalAppsAreDisabledForSQLite(t *testing.T) {
	manager := New(Config{BaseDir: t.TempDir(), DatabaseDialect: "sqlite"}, nil)
	manager.apps["0123456789ab"] = Record{
		ID: "0123456789ab", Domain: "app.example.com", Path: "", Enabled: true,
	}
	if manager.HasHost("app.example.com") {
		t.Fatal("SQLite installation exposed an external application host")
	}
	if _, _, ok := manager.Match("app.example.com", "/"); ok {
		t.Fatal("SQLite installation routed an external application request")
	}

	response := httptest.NewRecorder()
	manager.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/settings/external-apps", nil))
	var status struct {
		Supported bool           `json:"supported"`
		Apps      []PublicRecord `json:"apps"`
	}
	if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &status) != nil {
		t.Fatalf("status response=%d %q", response.Code, response.Body.String())
	}
	if status.Supported || len(status.Apps) != 0 {
		t.Fatalf("SQLite status=%+v", status)
	}

	response = httptest.NewRecorder()
	manager.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/settings/external-apps/archive", nil))
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "SQLite") {
		t.Fatalf("mutation response=%d %q", response.Code, response.Body.String())
	}
}

func TestMirzaBotUpdatePreservesConfigurationAndRunsMigration(t *testing.T) {
	const oldSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const newSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	archive := externalAppTestZIP(t, map[string]string{
		"mirzabot/composer.json": "{}", "mirzabot/composer.lock": "{}",
		"mirzabot/config.php": "upstream config", "mirzabot/index.php": "<?php echo 'new';",
		"mirzabot/new.php": "<?php", "mirzabot/install.sh": "#!/bin/bash",
		"mirzabot/install/index.php": "<?php echo 'installer';",
		"mirzabot/table.php":         "<?php\ntelegram('setwebhook', [\n    'url' => \"https://$domainhosts/index.php\"\n]);\n",
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tags":
			_, _ = w.Write([]byte(`[{"name":"0.3.2","commit":{"sha":"` + newSHA + `"}}]`))
		case "/zip/" + newSHA:
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	bin := t.TempDir()
	writeCommand := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\n"+body+"\n"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	writeCommand("id", "if [ \"$1\" = -u ]; then echo "+strconv.Itoa(os.Getuid())+"; else echo "+strconv.Itoa(os.Getgid())+"; fi")
	writeCommand("runuser", `
echo "$*" >> "$REBECCA_FAKE_RUNUSER_LOG"
for arg in "$@"; do
  case "$arg" in --working-dir=*) root="${arg#--working-dir=}";; esac
done
if [ -n "$root" ]; then mkdir -p "$root/vendor"; : > "$root/vendor/autoload.php"; fi
exit 0`)
	writeCommand("mysql", "echo 12")
	writeCommand("php-fpm8.4", "exit 0")
	writeCommand("systemctl", "exit 0")
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	runuserLog := filepath.Join(t.TempDir(), "runuser.log")
	t.Setenv("REBECCA_FAKE_RUNUSER_LOG", runuserLog)

	base := t.TempDir()
	root := filepath.Join(base, "apps", "0123456789ab")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	const config = "<?php // keep this exact configuration\n"
	if err := os.WriteFile(filepath.Join(root, "config.php"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php echo 'old';"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "old.php"), []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(t.TempDir(), "app.sock")
	if err := os.WriteFile(socket, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	record := Record{
		ID: "0123456789ab", Template: "mirzabot", Domain: "bot.example.com", Path: "bot0123456789ab",
		Runtime: "php", Version: "0.3.1", SourceSHA: oldSHA, IndexFile: "index.php", Root: root,
		Socket: socket, Service: "php8.4-fpm", PHPVersion: "8.4", SystemUser: "rbphp_0123456789ab",
		Database: "rb_mirza_0123456789ab", storageBase: base,
	}
	manager := &Manager{
		baseDir: base, apps: map[string]Record{record.ID: record}, httpClient: server.Client(),
		mirzaAPIBase: server.URL, mirzaArchive: server.URL,
	}
	if err := manager.writeRecord(record); err != nil {
		t.Fatal(err)
	}
	if err := manager.writeSecrets(record, secrets{CronSecret: "preserved-cron-secret"}); err != nil {
		t.Fatal(err)
	}
	updated, err := manager.updateMirzaBot(context.Background(), record.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Version != "0.3.2" || updated.SourceSHA != newSHA {
		t.Fatalf("updated=%+v", updated)
	}
	gotConfig, err := os.ReadFile(filepath.Join(root, "config.php"))
	if err != nil || string(gotConfig) != config {
		t.Fatalf("config=%q err=%v", gotConfig, err)
	}
	cronSecret, err := os.ReadFile(filepath.Join(root, ".rebecca-cron-secret"))
	if err != nil || strings.TrimSpace(string(cronSecret)) != "preserved-cron-secret" {
		t.Fatalf("cron secret=%q err=%v", cronSecret, err)
	}
	if _, err := os.Stat(filepath.Join(root, "new.php")); err != nil {
		t.Fatal("new release files were not activated")
	}
	if _, err := os.Stat(filepath.Join(root, "old.php")); !os.IsNotExist(err) {
		t.Fatal("old release files were retained")
	}
	if _, err := os.Stat(filepath.Join(root, "install.sh")); !os.IsNotExist(err) {
		t.Fatal("upstream installer was retained")
	}
	if _, err := os.Stat(filepath.Join(root, "install")); !os.IsNotExist(err) {
		t.Fatal("upstream web installer was retained")
	}
	commands, err := os.ReadFile(runuserLog)
	if err != nil || !strings.Contains(string(commands), "php .rebecca-init.php") {
		t.Fatalf("table initializer was not run: %q err=%v", commands, err)
	}
}

func TestMirzaRequestSecretsAreIndependent(t *testing.T) {
	base := t.TempDir()
	manager := &Manager{baseDir: base, apps: map[string]Record{}}
	domain := "bot.example.com"
	record := Record{ID: domainHash(domain), Domain: domain, Template: "mirzabot", storageBase: base}
	if err := manager.writeSecrets(record, secrets{
		WebhookSecret: "webhook-secret",
		CronSecret:    "cron-secret",
	}); err != nil {
		t.Fatal(err)
	}
	webhook := httptest.NewRequest(http.MethodPost, "https://bot.example.com/index.php", nil)
	if err := manager.AuthorizeMirzaRequest(webhook, record, "index.php"); err == nil {
		t.Fatal("webhook without secret was accepted")
	}
	webhook.Header.Set("X-Telegram-Bot-Api-Secret-Token", "webhook-secret")
	if err := manager.AuthorizeMirzaRequest(webhook, record, "index.php"); err != nil {
		t.Fatal(err)
	}

	cron := httptest.NewRequest(http.MethodGet, "https://bot.example.com/cronbot/statusday.php", nil)
	cron.Header.Set("X-Rebecca-Cron-Secret", "webhook-secret")
	if err := manager.AuthorizeMirzaRequest(cron, record, "cronbot/statusday.php"); err == nil {
		t.Fatal("webhook secret was accepted as cron secret")
	}
	cron.Header.Set("X-Rebecca-Cron-Secret", "cron-secret")
	if err := manager.AuthorizeMirzaRequest(cron, record, "cronbot/statusday.php"); err != nil {
		t.Fatal(err)
	}
}

func TestMirzaBotTokenCannotBeReused(t *testing.T) {
	base := t.TempDir()
	record := Record{ID: "0123456789ab", Domain: "one.example.com", Template: "mirzabot", storageBase: base}
	manager := &Manager{baseDir: base, apps: map[string]Record{
		record.ID: record,
	}}
	if err := manager.writeSecrets(record, secrets{BotToken: "existing-token"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.ensureBotTokenAvailable("existing-token"); err == nil {
		t.Fatal("duplicate Telegram bot token was accepted")
	}
	if err := manager.ensureBotTokenAvailable("different-token"); err != nil {
		t.Fatal(err)
	}
}

func TestWriteMirzaCronUsesPerAppIdentityWithoutEmbeddingSecret(t *testing.T) {
	root := t.TempDir()
	record := Record{
		Domain:     "bot.example.com",
		Path:       "bot0123456789ab",
		Root:       root,
		SystemUser: "rbphp_abcdef",
		CronConfig: filepath.Join(t.TempDir(), "rebecca-php-abcdef"),
	}
	if err := writeMirzaCron(record); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(record.CronConfig)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	if strings.Count(text, "https://bot.example.com/bot0123456789ab/cronbot/") != len(mirzaCronTasks) {
		t.Fatalf("cron task count mismatch:\n%s", text)
	}
	if !strings.Contains(text, "rbphp_abcdef") || !strings.Contains(text, ".rebecca-cron-secret") {
		t.Fatalf("cron identity/secret file missing:\n%s", text)
	}
	if strings.Contains(text, "super-secret-value") {
		t.Fatal("cron secret was embedded in the world-readable cron definition")
	}
}

func TestMirzaWebhookUsesDedicatedPath(t *testing.T) {
	record := Record{Domain: "bot.example.com", Path: "bot0123456789ab"}
	if got := externalAppWebhookURL(record); got != "https://bot.example.com/bot0123456789ab/index.php" {
		t.Fatalf("webhook URL=%q", got)
	}
	if got := externalAppWebhookURL(Record{Domain: "legacy.example.com"}); got != "https://legacy.example.com/index.php" {
		t.Fatalf("legacy webhook URL=%q", got)
	}
}

func TestMirzaRecordIsEnabledWhileWebhookActivates(t *testing.T) {
	record := Record{ID: "0123456789ab", Template: "mirzabot", Domain: "bot.example.com", Path: "bot0123456789ab"}
	manager := &Manager{apps: map[string]Record{record.ID: record}}

	wantErr := errors.New("webhook failed")
	if _, err := manager.withEnabledRecord(record, func() error {
		matched, _, ok := manager.Match(record.Domain, "/"+record.Path)
		if !ok || !matched.Enabled {
			t.Fatal("MirzaBot route was not enabled before webhook activation")
		}
		return wantErr
	}); !errors.Is(err, wantErr) {
		t.Fatalf("activation error = %v", err)
	}
	if restored, ok := manager.Lookup(record.ID); !ok || restored.Enabled {
		t.Fatal("failed webhook activation did not restore the disabled record")
	}
}

func TestWriteExternalAppPoolBoundsResources(t *testing.T) {
	record := Record{
		Root:       t.TempDir(),
		SystemUser: "rbphp_abcdef",
		Socket:     "/run/php/rebecca-abcdef.sock",
		PoolConfig: filepath.Join(t.TempDir(), "rebecca-abcdef.conf"),
	}
	if err := writeExternalAppPool(record, false); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(record.PoolConfig)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "pm.max_children = 2") ||
		!strings.Contains(string(content), "memory_limit] = 256M") ||
		!strings.Contains(string(content), "env[PATH] = /usr/local/sbin") {
		t.Fatalf("PHP-FPM resource limits are missing:\n%s", content)
	}
}

func TestMirzaBotConfigEscapesPHPStrings(t *testing.T) {
	config := mirzaBotConfig("db", "user", "pa'ss", "12345:abcdefghijklmnopqrstuvwxyz", "12345", "bot.example.com", "bot")
	if !strings.Contains(config, "$passworddb = 'pa\\'ss';") {
		t.Fatalf("password was not escaped: %s", config)
	}
	if strings.Contains(config, "PDOException $e) { error_log('Database connection failed: ") {
		t.Fatal("generated config exposes database errors")
	}
}

func TestMySQLOptionFileValueEscapesCredentials(t *testing.T) {
	input := "pa#ss;word\\\"\nnext"
	if value := mysqlOptionFileValue(input); value != strconv.Quote(input) {
		t.Fatalf("escaped option value = %q", value)
	}
}

func externalAppTestZIP(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for name, content := range files {
		file, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := file.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func TestExternalAppManagerReloadRejectsEscapedRoots(t *testing.T) {
	manager := &Manager{baseDir: t.TempDir(), apps: map[string]Record{}}
	if err := manager.prepareStorage(); err != nil {
		t.Fatal(err)
	}
	record := Record{Template: "archive", Domain: "bad.example.com", Runtime: "static", Root: "/etc"}
	if err := writePrivateJSON(manager.recordPath(domainHash(record.Domain)), record); err != nil {
		t.Fatal(err)
	}
	manager.reload()
	if _, ok := manager.Lookup(record.Domain); ok {
		t.Fatal("escaped application root was loaded")
	}
}

func TestMigrateLegacyBaseDirPreservesAndRecoversLegacyStorage(t *testing.T) {
	t.Run("existing legacy tree stays in place", func(t *testing.T) {
		parent := t.TempDir()
		oldBase := filepath.Join(parent, "php-apps")
		base := filepath.Join(parent, "external-apps")
		if err := os.MkdirAll(oldBase, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := migrateLegacyBaseDir(base, oldBase); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(oldBase); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("already renamed tree gets legacy alias", func(t *testing.T) {
		parent := t.TempDir()
		oldBase := filepath.Join(parent, "php-apps")
		base := filepath.Join(parent, "external-apps")
		if err := os.MkdirAll(base, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(base, "marker"), []byte("ok"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := migrateLegacyBaseDir(base, oldBase); err != nil {
			t.Fatal(err)
		}
		if data, err := os.ReadFile(filepath.Join(oldBase, "marker")); err != nil || string(data) != "ok" {
			t.Fatalf("legacy alias marker = %q, err = %v", data, err)
		}
	})
}

func TestExternalAppManagerLoadsLegacyAndMatchesMultipleBotsPerDomain(t *testing.T) {
	parent := t.TempDir()
	base := filepath.Join(parent, "external-apps")
	legacy := filepath.Join(parent, "php-apps")
	for _, record := range []Record{
		{ID: "0123456789ab", Template: "mirzabot", Domain: "bot.example.com", Runtime: "static", Path: "", Root: filepath.Join(legacy, "apps", "0123456789ab")},
		{ID: "abcdef012345", Template: "mirzabot", Domain: "bot.example.com", Runtime: "static", Path: "botabcdef012345", Root: filepath.Join(base, "apps", "abcdef012345")},
	} {
		storage := base
		if record.Path == "" {
			storage = legacy
		}
		if err := os.MkdirAll(record.Root, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := writePrivateJSON(filepath.Join(storage, ".metadata", record.ID+".json"), record); err != nil {
			t.Fatal(err)
		}
	}
	manager := &Manager{baseDir: base, legacyBase: legacy, apps: map[string]Record{}}
	manager.reload()
	if len(manager.publicRecords()) != 2 {
		t.Fatalf("loaded apps=%+v", manager.publicRecords())
	}
	matched, rel, ok := manager.Match("bot.example.com", "/botabcdef012345/cronbot/statusday.php")
	if !ok || matched.ID != "abcdef012345" || rel != "cronbot/statusday.php" {
		t.Fatalf("matched=%+v rel=%q ok=%v", matched, rel, ok)
	}
	matched, rel, ok = manager.Match("bot.example.com", "/index.php")
	if !ok || matched.ID != "0123456789ab" || rel != "index.php" {
		t.Fatalf("legacy match=%+v rel=%q ok=%v", matched, rel, ok)
	}
}

func TestExternalAppManagerRecoversPreviouslyRenamedLegacyRecord(t *testing.T) {
	parent := t.TempDir()
	base := filepath.Join(parent, "external-apps")
	legacy := filepath.Join(parent, "php-apps")
	id := "0123456789ab"
	if err := os.MkdirAll(filepath.Join(base, "apps", id), 0o700); err != nil {
		t.Fatal(err)
	}
	record := Record{Template: "mirzabot", Domain: "bot.example.com", Runtime: "static", Root: filepath.Join(legacy, "apps", id)}
	if err := writePrivateJSON(filepath.Join(base, ".metadata", id+".json"), record); err != nil {
		t.Fatal(err)
	}
	if err := migrateLegacyBaseDir(base, legacy); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{baseDir: base, legacyBase: legacy, apps: map[string]Record{}}
	manager.reload()
	loaded, ok := manager.Lookup(id)
	if !ok || loaded.Root != record.Root {
		t.Fatalf("recovered=%+v ok=%v", loaded, ok)
	}
}

func TestDecodeMirzaInstallRequestAcceptsOptionalSQLBackup(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for key, value := range map[string]string{"domain": "bot.example.com", "bot_token": "12345:abcdefghijklmnopqrstuvwxyz", "admin_id": "12345"} {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	file, err := writer.CreateFormFile("database_backup", "backup.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("CREATE TABLE test (id INT);")); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/settings/external-apps/mirzabot", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	payload, err := decodeMirzaInstallRequest(request)
	if err != nil || string(payload.DatabaseBackup) != "CREATE TABLE test (id INT);" {
		t.Fatalf("payload=%+v err=%v", payload, err)
	}
}

func TestDecodeArchiveInstallRequestAcceptsEmptyProjectAndDatabase(t *testing.T) {
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	fields := map[string]string{
		"domain":            "app.example.com",
		"name":              "My app",
		"runtime":           "php",
		"create_database":   "true",
		"database":          "my_app",
		"database_user":     "my_app_user",
		"database_password": "SafePassword_1234",
	}
	for key, value := range fields {
		if err := writer.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/settings/external-apps/archive", &body)
	request.Header.Set("Content-Type", writer.FormDataContentType())
	payload, err := decodeArchiveInstallRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Domain != fields["domain"] || payload.Name != fields["name"] || payload.Runtime != "php" || len(payload.Archive) != 0 || !payload.CreateDatabase || payload.Database != fields["database"] || payload.DatabaseUser != fields["database_user"] || payload.DatabasePassword != fields["database_password"] {
		t.Fatalf("payload=%+v", payload)
	}
	if !databaseNamePattern.MatchString(payload.Database) || !databaseUserPattern.MatchString(payload.DatabaseUser) || !databasePasswordPattern.MatchString(payload.DatabasePassword) {
		t.Fatal("valid database credentials were rejected")
	}
	for _, invalid := range []string{"bad-name", "1database", "name with spaces"} {
		if databaseNamePattern.MatchString(invalid) {
			t.Fatalf("invalid database name %q was accepted", invalid)
		}
	}
	for _, invalid := range []string{"bad-user", "1user", "user with spaces"} {
		if databaseUserPattern.MatchString(invalid) {
			t.Fatalf("invalid database username %q was accepted", invalid)
		}
	}
	for _, invalid := range []string{"short", "password with spaces", "password'quote"} {
		if databasePasswordPattern.MatchString(invalid) {
			t.Fatalf("invalid database password %q was accepted", invalid)
		}
	}
}

func TestCreateExternalAppDatabaseGrantsRebeccaAccess(t *testing.T) {
	bin := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "mysql.log")
	script := `#!/bin/sh
query=$(cat)
printf '%s\n' "$query" >> "$REBECCA_MYSQL_TEST_LOG"
case "$query" in
  *"SELECT EXISTS"*) printf '0\t0\n' ;;
  *"SELECT Host"*) printf '127.0.0.1\nlocalhost\n' ;;
esac
`
	if err := os.WriteFile(filepath.Join(bin, "mysql"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("REBECCA_MYSQL_TEST_LOG", logPath)
	manager := &Manager{databaseURL: "mysql://rebecca:secret@127.0.0.1:3306/rebecca"}
	if err := manager.ensureExternalAppDatabaseFree(context.Background(), "project_db", "project_user"); err != nil {
		t.Fatal(err)
	}
	if err := manager.createExternalAppDatabase(context.Background(), "project_db", "project_user", "SafePassword_1234"); err != nil {
		t.Fatal(err)
	}
	queries, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	text := string(queries)
	for _, expected := range []string{
		"CREATE DATABASE `project_db`",
		"GRANT ALL PRIVILEGES ON `project_db`.* TO 'project_user'@'localhost'",
		"GRANT ALL PRIVILEGES ON `project_db`.* TO 'rebecca'@'127.0.0.1'",
		"GRANT ALL PRIVILEGES ON `project_db`.* TO 'rebecca'@'localhost'",
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("missing %q in queries:\n%s", expected, text)
		}
	}
}

func TestMirzaBotDatabaseBackupDownload(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "mariadb-dump"), []byte("#!/bin/sh\nprintf '%s\\n' '-- MirzaBot backup' 'CREATE TABLE test (id INT);'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	record := Record{ID: "0123456789ab", Template: "mirzabot", Database: "rb_mirza_0123456789ab"}
	manager := &Manager{apps: map[string]Record{record.ID: record}}
	request := httptest.NewRequest(http.MethodGet, "/api/settings/external-apps/"+record.ID+"/database-backup", nil)
	response := httptest.NewRecorder()
	manager.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "CREATE TABLE test") {
		t.Fatalf("response=%d %q", response.Code, response.Body.String())
	}
	if disposition := response.Header().Get("Content-Disposition"); !strings.Contains(disposition, "mirzabot-"+record.ID) || !strings.HasSuffix(disposition, `.sql"`) {
		t.Fatalf("content-disposition=%q", disposition)
	}
	if response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control=%q", response.Header().Get("Cache-Control"))
	}
}

func TestExternalAppCertificateContainsPrimaryAndSAN(t *testing.T) {
	record := certificateapp.Record{Domain: "one.example.com", AltNames: []string{"two.example.com"}}
	if !externalAppCertificateContains(record, "one.example.com") || !externalAppCertificateContains(record, "two.example.com") {
		t.Fatal("managed certificate names were not available to external applications")
	}
	if externalAppCertificateContains(record, "other.example.com") {
		t.Fatal("unmanaged certificate name was accepted")
	}
}

func TestExternalAppCannotReplaceCurrentPanelHost(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "https://panel.example.com/api/settings/external-apps/mirzabot", nil)
	if !externalAppUsesCurrentPanelHost(request, "panel.example.com") {
		t.Fatal("current panel hostname was accepted for an application")
	}
	if externalAppUsesCurrentPanelHost(request, "bot.example.com") {
		t.Fatal("independent application hostname was rejected")
	}
}

func TestDownloadMirzaBotUsesLatestTaggedCommit(t *testing.T) {
	const commit = "0123456789abcdef0123456789abcdef01234567"
	archive := externalAppTestZIP(t, map[string]string{
		"mirzabot/composer.json": "{}", "mirzabot/composer.lock": "{}",
		"mirzabot/table.php": "<?php", "mirzabot/config.php": "<?php", "mirzabot/index.php": "<?php",
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != "Rebecca" {
			t.Errorf("user-agent=%q", r.Header.Get("User-Agent"))
		}
		switch r.URL.Path {
		case "/tags":
			_, _ = w.Write([]byte(`[{"name":"0.3.0","commit":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},{"name":"0.3.1","commit":{"sha":"` + commit + `"}}]`))
		case "/zip/" + commit:
			_, _ = w.Write(archive)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	manager := &Manager{httpClient: server.Client(), mirzaAPIBase: server.URL, mirzaArchive: server.URL}
	source, err := manager.downloadMirzaBot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if source.Version != "0.3.1" || source.SHA != commit || !bytes.Equal(source.Archive, archive) {
		t.Fatalf("source=%+v", source)
	}
	if _, err := extractMirzaBotArchive(source.Archive, t.TempDir()); err != nil {
		t.Fatal(err)
	}
}

func TestDownloadMirzaBotRejectsInvalidTags(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`[{"name":"main","commit":{"sha":"not-a-commit"}}]`))
	}))
	defer server.Close()
	manager := &Manager{httpClient: server.Client(), mirzaAPIBase: server.URL, mirzaArchive: server.URL}
	if _, err := manager.downloadMirzaBot(context.Background()); err == nil {
		t.Fatal("invalid tag was accepted")
	}
}

func TestLatestMirzaBotReleaseArchive(t *testing.T) {
	if os.Getenv("REBECCA_TEST_LATEST_MIRZABOT") != "1" {
		t.Skip("set REBECCA_TEST_LATEST_MIRZABOT=1 to verify the current tagged GitHub release")
	}
	manager := New(Config{BaseDir: t.TempDir()}, nil)
	source, err := manager.downloadMirzaBot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !mirzaReleasePattern.MatchString(source.Version) || !mirzaCommitPattern.MatchString(source.SHA) {
		t.Fatalf("invalid release metadata: version=%q sha=%q", source.Version, source.SHA)
	}
	root, err := extractMirzaBotArchive(source.Archive, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	table, err := os.ReadFile(filepath.Join(root, "table.php"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := mirzaBotTableInitializer(table); err != nil {
		t.Fatal(err)
	}
	t.Logf("validated MirzaBot %s at %s", source.Version, source.SHA)
}

func TestPatchMirzaMiniAppUsesMountedPaths(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "app", "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(root, "app", "index.php")
	if err := os.WriteFile(indexPath, []byte("<head></head>"), 0o644); err != nil {
		t.Fatal(err)
	}
	assetPath := filepath.Join(root, "app", "assets", "index.js")
	asset := `const api=window.location.origin+"/api";if(window.location.pathname!=="/app/")window.location.href="/app/";`
	if err := os.WriteFile(assetPath, []byte(asset), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := patchMirzaMiniApp(root, "bot0123456789ab"); err != nil {
		t.Fatal(err)
	}
	index, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(index), `__MIRZA_API_ORIGIN=window.location.origin+"/bot0123456789ab"`) || !strings.Contains(string(index), `__MIRZA_APP_PATH="/bot0123456789ab/app/"`) {
		t.Fatalf("mounted bootstrap missing: %s", index)
	}
	updated, err := os.ReadFile(assetPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		`window.__MIRZA_API_ORIGIN||window.location.origin+"/api"`,
		`window.location.pathname!==window.__MIRZA_APP_PATH`,
		`window.location.href=window.__MIRZA_APP_PATH`,
	} {
		if !strings.Contains(string(updated), expected) {
			t.Fatalf("asset missing %q: %s", expected, updated)
		}
	}
}

func TestMatchMirzaLegacyPathRequiresSingleMountedApp(t *testing.T) {
	manager := &Manager{apps: map[string]Record{
		"one": {ID: "one", Template: "mirzabot", Domain: "bot.example.com", Path: "bot0123456789ab"},
	}}
	if record, relative, ok := manager.MatchMirzaLegacyPath("bot.example.com", "/api/keyboard.php"); !ok || record.ID != "one" || relative != "api/keyboard.php" {
		t.Fatalf("legacy match=%+v %q %v", record, relative, ok)
	}
	manager.apps["two"] = Record{ID: "two", Template: "mirzabot", Domain: "bot.example.com", Path: "botabcdef012345"}
	if _, _, ok := manager.MatchMirzaLegacyPath("bot.example.com", "/api/keyboard.php"); ok {
		t.Fatal("ambiguous legacy match was accepted")
	}
}
