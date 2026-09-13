package backup

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportRejectsUnsafeArchivePath(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "unsafe.rbbackup")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "../evil", Mode: 0o600, Size: int64(len("bad"))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write([]byte("bad")); err != nil {
		t.Fatal(err)
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	service := NewService(nil, "sqlite", "sqlite:///tmp/rebecca.sqlite3")
	_, err = service.Import(context.Background(), archivePath)
	if err == nil || !strings.Contains(err.Error(), "unsafe paths") {
		t.Fatalf("expected unsafe path error, got %v", err)
	}
}

func TestSafeExtractRejectsOversizedEntry(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "oversized.rbbackup")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	if err := tarWriter.WriteHeader(&tar.Header{Name: "large", Mode: 0o600, Size: maxBackupExtractBytes + 1}); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	err = safeExtract(archivePath, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected extraction size limit error, got %v", err)
	}
}

func TestSafeExtractSupportsZipBackups(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "backup.zip")
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for name, content := range map[string]string{ManifestName: `{"format":"rebecca"}`, "files/rebecca_env": "PANEL_DOMAIN=example.com\n"} {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	destination := t.TempDir()
	if err := safeExtract(archivePath, destination); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{ManifestName, "files/rebecca_env"} {
		if _, err := os.Stat(filepath.Join(destination, filepath.FromSlash(name))); err != nil {
			t.Fatalf("extracted %s: %v", name, err)
		}
	}
}

func TestImportRejectsInvalidManifest(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "invalid.rbbackup")
	writeBackupArchiveForTest(t, archivePath, map[string][]byte{
		ManifestName: []byte(`{"format":"wrong","version":1}`),
	})
	service := NewService(nil, "sqlite", "sqlite:///tmp/rebecca.sqlite3")
	_, err := service.Import(context.Background(), archivePath)
	if err == nil || !strings.Contains(err.Error(), "Invalid backup manifest format") {
		t.Fatalf("expected invalid manifest error, got %v", err)
	}
}

func TestMySQLMissingDumpTool(t *testing.T) {
	t.Setenv("PATH", filepath.Join(t.TempDir(), "empty-bin"))
	service := NewService(nil, "mysql", "mysql://user:pass@127.0.0.1:3306/rebecca")
	_, err := service.Export(context.Background(), ScopeDatabase)
	if err == nil || !strings.Contains(err.Error(), "Required database tool is not installed") {
		t.Fatalf("expected missing tool error, got %v", err)
	}
}

func TestFullRestoreKeepsDestinationMySQLCredentials(t *testing.T) {
	targetEnv := filepath.Join(t.TempDir(), "rebecca_env")
	if err := os.WriteFile(targetEnv, []byte(strings.Join([]string{
		`REBECCA_DATABASE_FLAVOR="mysql"`,
		`MYSQL_DATABASE="rebecca"`,
		`MYSQL_USER="rebecca"`,
		`MYSQL_PASSWORD="destination-password"`,
		`MYSQL_ROOT_PASSWORD="destination-root-password"`,
		`SQLALCHEMY_DATABASE_URL="mysql+pymysql://rebecca:destination-password@127.0.0.1:3306/rebecca"`,
	}, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	filesDir := t.TempDir()
	sourceEnv := filepath.Join(filesDir, "rebecca_env")
	if err := os.WriteFile(sourceEnv, []byte(strings.Join([]string{
		`PANEL_DOMAIN="source.example.com"`,
		`MYSQL_PASSWORD="source-password"`,
		`MYSQL_ROOT_PASSWORD="source-root-password"`,
		`SQLALCHEMY_DATABASE_URL="mysql+pymysql://rebecca:source-password@127.0.0.1:3306/rebecca"`,
	}, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	service := NewService(nil, "mysql", "mysql+pymysql://rebecca:destination-password@127.0.0.1:3306/rebecca", WithFileRoots([]FileRoot{
		{ArchiveName: "rebecca_env", Path: targetEnv},
	}))
	if err := service.preserveLocalDatabaseEnv(filesDir); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(sourceEnv)
	if err != nil {
		t.Fatal(err)
	}
	text := string(content)
	for _, expected := range []string{
		`PANEL_DOMAIN="source.example.com"`,
		`MYSQL_PASSWORD="destination-password"`,
		`MYSQL_ROOT_PASSWORD="destination-root-password"`,
		`SQLALCHEMY_DATABASE_URL="mysql+pymysql://rebecca:destination-password@127.0.0.1:3306/rebecca"`,
	} {
		if !strings.Contains(text, expected) {
			t.Fatalf("restored env missing %q in %q", expected, text)
		}
	}
	if strings.Contains(text, "source-password") {
		t.Fatalf("restored env retained source database credentials: %q", text)
	}
}

func TestMySQLAccessDeniedBackupError(t *testing.T) {
	err := mysqlBackupCommandError("restore", "ERROR 1045 (28000): Access denied for user 'rebecca'@'localhost'")
	if !strings.Contains(err.Error(), "configured database credentials") || !strings.Contains(err.Error(), "MYSQL_PASSWORD") {
		t.Fatalf("expected actionable credential error, got %v", err)
	}
}

func writeBackupArchiveForTest(t *testing.T, archivePath string, files map[string][]byte) {
	t.Helper()
	file, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	for name, content := range files {
		if err := tarWriter.WriteHeader(&tar.Header{Name: name, Mode: 0o600, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tarWriter.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := tarWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
