package backup

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Service struct {
	db          *sql.DB
	dialect     string
	databaseURL string
	fileRoots   []FileRoot
}

const (
	maxBackupExtractBytes   int64 = 1 << 30
	maxBackupArchiveEntries       = 10_000
)

type Option func(*Service)

func WithFileRoots(roots []FileRoot) Option {
	return func(s *Service) {
		s.fileRoots = roots
	}
}

func NewService(db *sql.DB, dialect string, databaseURL string, opts ...Option) *Service {
	service := &Service{
		db:          db,
		dialect:     normalizeDialect(dialect),
		databaseURL: strings.TrimSpace(databaseURL),
		fileRoots:   defaultFileRoots(),
	}
	for _, opt := range opts {
		opt(service)
	}
	return service
}

func (s *Service) Export(ctx context.Context, scope string) (ExportResult, error) {
	scope, err := validateScope(scope)
	if err != nil {
		return ExportResult{}, err
	}

	output, err := os.CreateTemp("", "rebecca-backup-*"+Extension)
	if err != nil {
		return ExportResult{}, err
	}
	outputPath := output.Name()
	_ = output.Close()

	buildDir, err := os.MkdirTemp("", "rebecca-backup-build-*")
	if err != nil {
		_ = os.Remove(outputPath)
		return ExportResult{}, err
	}
	defer os.RemoveAll(buildDir)

	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(outputPath)
		}
	}()

	payload, err := s.exportDatabasePayload(ctx, buildDir)
	if err != nil {
		return ExportResult{}, err
	}
	tableCount, rowCount, err := s.databaseCounts(ctx)
	if err != nil {
		return ExportResult{}, err
	}

	paths := []manifestPath{}
	if scope == ScopeFull {
		for _, root := range s.fileRoots {
			if root.ArchiveName == "" || root.Path == "" {
				continue
			}
			if _, statErr := os.Stat(root.Path); statErr == nil {
				paths = append(paths, manifestPath{ArchiveName: root.ArchiveName, Path: root.Path})
			}
		}
	}

	m := manifest{
		Format:    Format,
		Version:   Version,
		Scope:     scope,
		CreatedAt: utcNowString(),
		Database: manifestDB{
			URLDialect:       s.dialect,
			SourceURLDialect: sourceURLDialect(s.databaseURL),
			Payload:          payload.ArchiveName,
			PayloadType:      payload.PayloadType,
			Tables:           tableCount,
			Rows:             rowCount,
		},
		Paths: paths,
	}
	manifestContent, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return ExportResult{}, err
	}
	if err := os.WriteFile(filepath.Join(buildDir, ManifestName), manifestContent, 0o600); err != nil {
		return ExportResult{}, err
	}

	if err := s.writeArchive(outputPath, buildDir, payload.ArchiveName, scope); err != nil {
		return ExportResult{}, err
	}

	timestamp := time.Now().UTC().Format("20060102-150405")
	cleanup = false
	return ExportResult{
		Path:     outputPath,
		Filename: fmt.Sprintf("rebecca-%s-%s%s", scope, timestamp, Extension),
		Scope:    scope,
	}, nil
}

func (s *Service) Import(ctx context.Context, archivePath string) (ImportResult, error) {
	if stat, err := os.Stat(archivePath); err != nil || stat.IsDir() {
		return ImportResult{}, Error{Message: "Backup file not found"}
	}

	extractDir, err := os.MkdirTemp("", "rebecca-backup-import-*")
	if err != nil {
		return ImportResult{}, err
	}
	defer os.RemoveAll(extractDir)

	if err := safeExtract(archivePath, extractDir); err != nil {
		return ImportResult{}, err
	}
	m, err := loadManifest(filepath.Join(extractDir, ManifestName))
	if err != nil {
		return ImportResult{}, err
	}
	scope, err := validateScope(m.Scope)
	if err != nil {
		return ImportResult{}, err
	}
	if scope == ScopeFull && (s.dialect == "mysql" || s.dialect == "mariadb") {
		if err := s.preserveLocalDatabaseEnv(filepath.Join(extractDir, FilesPrefix)); err != nil {
			return ImportResult{}, err
		}
	}

	tables, rows, warnings, err := s.restoreDatabasePayload(ctx, extractDir, m)
	if err != nil {
		return ImportResult{}, err
	}

	filesRestored := []string{}
	if scope == ScopeFull {
		restored, fileWarnings, restoreErr := s.restoreFileRoots(filepath.Join(extractDir, FilesPrefix))
		if restoreErr != nil {
			return ImportResult{}, restoreErr
		}
		filesRestored = restored
		warnings = append(warnings, fileWarnings...)
	}

	return ImportResult{
		Scope:          scope,
		TablesRestored: tables,
		RowsRestored:   rows,
		FilesRestored:  filesRestored,
		Warnings:       warnings,
	}, nil
}

func (s *Service) exportDatabasePayload(ctx context.Context, buildDir string) (databasePayload, error) {
	switch s.dialect {
	case "sqlite":
		output := filepath.Join(buildDir, DatabaseSQLiteName)
		if err := s.exportSQLite(ctx, output); err != nil {
			return databasePayload{}, err
		}
		return databasePayload{ArchiveName: DatabaseSQLiteName, PayloadType: "sqlite-file"}, nil
	case "mysql", "mariadb":
		output := filepath.Join(buildDir, DatabaseSQLName)
		if err := s.exportMySQL(ctx, output); err != nil {
			return databasePayload{}, err
		}
		return databasePayload{ArchiveName: DatabaseSQLName, PayloadType: "mysql-dump"}, nil
	default:
		return databasePayload{}, Error{Message: "Unsupported database backend for Rebecca backup: " + s.dialect}
	}
}

func (s *Service) restoreDatabasePayload(ctx context.Context, extractDir string, m manifest) (int, int, []string, error) {
	if m.Database.Payload != "" {
		payloadPath := filepath.Join(extractDir, filepath.FromSlash(m.Database.Payload))
		if !isRegularFile(payloadPath) {
			return 0, 0, nil, Error{Message: "Backup database payload is missing"}
		}
		switch m.Database.PayloadType {
		case "sqlite-file":
			if err := s.restoreSQLite(ctx, payloadPath); err != nil {
				return 0, 0, nil, err
			}
		case "mysql-dump":
			if err := s.restoreMySQL(ctx, payloadPath); err != nil {
				return 0, 0, nil, err
			}
		default:
			return 0, 0, nil, Error{Message: "Backup database payload type is not supported"}
		}
		tables, rows, err := s.databaseCounts(ctx)
		return tables, rows, nil, err
	}

	legacyPath := filepath.Join(extractDir, DatabaseDumpName)
	if !isRegularFile(legacyPath) {
		return 0, 0, nil, Error{Message: "Backup database payload is missing"}
	}
	tables, rows, warnings, err := s.restoreLegacyJSON(ctx, legacyPath)
	if err != nil {
		return 0, 0, nil, err
	}
	warnings = append(warnings, "Restored a legacy JSON database payload; create a fresh backup to use hard database replacement.")
	return tables, rows, warnings, nil
}

func (s *Service) exportSQLite(ctx context.Context, outputPath string) error {
	if s.db == nil {
		return Error{Message: "SQLite database connection is not available"}
	}
	target := sqliteQuoteString(outputPath)
	if _, err := s.db.ExecContext(ctx, "VACUUM INTO "+target); err != nil {
		sourcePath, pathErr := s.sqliteDatabasePath()
		if pathErr != nil {
			return pathErr
		}
		return copyFile(sourcePath, outputPath, 0o600)
	}
	return nil
}

func (s *Service) restoreSQLite(ctx context.Context, payloadPath string) error {
	targetPath, err := s.sqliteDatabasePath()
	if err != nil {
		return Error{Message: "This backup contains a SQLite database, but the current installation is not using SQLite"}
	}
	if err := validateSQLiteFile(payloadPath); err != nil {
		return err
	}
	if s.db != nil {
		if err := restoreSQLiteLogically(ctx, s.db, payloadPath); err != nil {
			return err
		}
		_ = os.Remove(targetPath + "-wal")
		_ = os.Remove(targetPath + "-shm")
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return err
	}
	tempTarget := filepath.Join(filepath.Dir(targetPath), fmt.Sprintf(".%s.restore-%d.tmp", filepath.Base(targetPath), os.Getpid()))
	if err := copyFile(payloadPath, tempTarget, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tempTarget, targetPath); err == nil {
		_ = os.Remove(targetPath + "-wal")
		_ = os.Remove(targetPath + "-shm")
		return nil
	}
	_ = os.Remove(tempTarget)
	return Error{Message: "Failed to replace SQLite database file"}
}

func (s *Service) exportMySQL(ctx context.Context, outputPath string) error {
	command, err := findExecutable([]string{"mariadb-dump", "mysqldump"})
	if err != nil {
		return err
	}
	databaseName, err := s.mysqlDatabaseName()
	if err != nil {
		return err
	}
	tempDir, err := os.MkdirTemp("", "rebecca-mysql-dump-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	defaultsFile, err := s.writeMySQLDefaultsFile(tempDir)
	if err != nil {
		return err
	}
	args := []string{
		"--defaults-extra-file=" + defaultsFile,
		"--single-transaction",
		"--quick",
		"--routines",
		"--triggers",
		"--events",
		"--hex-blob",
		"--add-drop-database",
		"--default-character-set=utf8mb4",
		"--databases",
		databaseName,
	}
	out, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer out.Close()
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdout = out
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return mysqlBackupCommandError("dump", stderr.String())
	}
	return nil
}

func (s *Service) restoreMySQL(ctx context.Context, payloadPath string) error {
	command, err := findExecutable([]string{"mariadb", "mysql"})
	if err != nil {
		return err
	}
	databaseName, err := s.mysqlDatabaseName()
	if err != nil {
		return err
	}
	tempDir, err := os.MkdirTemp("", "rebecca-mysql-restore-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	defaultsFile, err := s.writeMySQLDefaultsFile(tempDir)
	if err != nil {
		return err
	}
	filteredPath := filepath.Join(tempDir, "database.sql")
	if err := filterMySQLDumpForDatabase(payloadPath, filteredPath); err != nil {
		return err
	}
	rollbackRawPath := filepath.Join(tempDir, "rollback.sql")
	if err := s.exportMySQL(ctx, rollbackRawPath); err != nil {
		return Error{Message: "Failed to create a rollback backup before restoring MySQL/MariaDB: " + err.Error()}
	}
	rollbackPath := filepath.Join(tempDir, "rollback-filtered.sql")
	if err := filterMySQLDumpForDatabase(rollbackRawPath, rollbackPath); err != nil {
		return err
	}
	if err := s.dropMySQLTables(ctx); err != nil {
		return s.restoreMySQLRollback(command, defaultsFile, databaseName, rollbackPath, err)
	}
	if err := restoreMySQLDump(ctx, command, defaultsFile, databaseName, filteredPath); err != nil {
		return s.restoreMySQLRollback(command, defaultsFile, databaseName, rollbackPath, err)
	}
	return nil
}

func (s *Service) restoreMySQLRollback(command string, defaultsFile string, databaseName string, rollbackPath string, restoreErr error) error {
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := s.dropMySQLTables(rollbackCtx); err != nil {
		return Error{Message: restoreErr.Error() + "; automatic rollback failed: " + err.Error()}
	}
	if err := restoreMySQLDump(rollbackCtx, command, defaultsFile, databaseName, rollbackPath); err != nil {
		return Error{Message: restoreErr.Error() + "; automatic rollback failed: " + err.Error()}
	}
	return restoreErr
}

func restoreMySQLDump(ctx context.Context, command string, defaultsFile string, databaseName string, inputPath string) error {
	input, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer input.Close()
	restoreCmd := exec.CommandContext(ctx, command, "--defaults-extra-file="+defaultsFile, "--database="+databaseName)
	restoreCmd.Stdin = input
	if stderr, err := restoreCmd.CombinedOutput(); err != nil {
		return mysqlBackupCommandError("restore", string(stderr))
	}
	return nil
}

func mysqlBackupCommandError(action string, stderr string) error {
	detail := strings.TrimSpace(stderr)
	lower := strings.ToLower(detail)
	if strings.Contains(lower, "error 1045") || strings.Contains(lower, "access denied for user") {
		return Error{Message: "MySQL/MariaDB rejected Rebecca's configured database credentials (error 1045). Check MYSQL_PASSWORD and SQLALCHEMY_DATABASE_URL."}
	}
	if detail == "" {
		detail = "database command failed"
	}
	return Error{Message: "Failed to " + action + " MySQL/MariaDB database: " + detail}
}

func (s *Service) dropMySQLTables(ctx context.Context) error {
	if s.db == nil {
		return Error{Message: "MySQL/MariaDB database connection is not available"}
	}
	tables, err := s.tableNames(ctx)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if _, err := tx.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0"); err != nil {
		return err
	}
	for _, table := range tables {
		if _, err := tx.ExecContext(ctx, "DROP TABLE IF EXISTS "+quoteMySQLIdentifier(table)); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true
	return nil
}

func (s *Service) databaseCounts(ctx context.Context) (int, int, error) {
	if s.db == nil {
		return 0, 0, nil
	}
	tables, err := s.tableNames(ctx)
	if err != nil {
		return 0, 0, err
	}
	rows := 0
	for _, table := range tables {
		query := "SELECT COUNT(*) FROM " + s.quoteIdentifier(table)
		var count int
		if err := s.db.QueryRowContext(ctx, query).Scan(&count); err != nil {
			return 0, 0, err
		}
		rows += count
	}
	return len(tables), rows, nil
}

func (s *Service) tableNames(ctx context.Context) ([]string, error) {
	if s.db == nil {
		return nil, nil
	}
	var rows *sql.Rows
	var err error
	switch s.dialect {
	case "sqlite":
		rows, err = s.db.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	case "mysql", "mariadb":
		rows, err = s.db.QueryContext(ctx, `SELECT table_name FROM information_schema.tables WHERE table_schema = DATABASE() AND table_type = 'BASE TABLE' ORDER BY table_name`)
	default:
		return nil, Error{Message: "Unsupported database backend for Rebecca backup: " + s.dialect}
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tables := []string{}
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			return nil, err
		}
		tables = append(tables, table)
	}
	return tables, rows.Err()
}

func (s *Service) writeArchive(outputPath string, buildDir string, databaseArchiveName string, scope string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer file.Close()
	gzipWriter := gzip.NewWriter(file)
	defer gzipWriter.Close()
	tarWriter := tar.NewWriter(gzipWriter)
	defer tarWriter.Close()

	if err := addFileToTar(tarWriter, filepath.Join(buildDir, ManifestName), ManifestName); err != nil {
		return err
	}
	if err := addFileToTar(tarWriter, filepath.Join(buildDir, databaseArchiveName), databaseArchiveName); err != nil {
		return err
	}
	if scope != ScopeFull {
		return nil
	}
	skips := s.activeSQLitePaths()
	for _, root := range s.fileRoots {
		if root.ArchiveName == "" || root.Path == "" {
			continue
		}
		if _, err := os.Stat(root.Path); err != nil {
			continue
		}
		archiveRoot := filepath.ToSlash(filepath.Join(FilesPrefix, root.ArchiveName))
		if err := addTreeToTar(tarWriter, root.Path, archiveRoot, skips); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) restoreFileRoots(filesDir string) ([]string, []string, error) {
	restored := []string{}
	warnings := []string{}
	if _, err := os.Stat(filesDir); err != nil {
		return restored, []string{"Backup does not contain file payloads"}, nil
	}
	allowed := map[string]string{}
	for _, root := range s.fileRoots {
		if root.Path == "" || root.ArchiveName == "" {
			continue
		}
		resolved, err := filepath.Abs(root.Path)
		if err != nil {
			return nil, nil, err
		}
		allowed[resolved] = root.ArchiveName
	}
	skips := s.activeSQLitePaths()
	for _, root := range s.fileRoots {
		source := filepath.Join(filesDir, root.ArchiveName)
		if _, err := os.Stat(source); err != nil {
			warnings = append(warnings, "Backup does not contain "+root.ArchiveName)
			continue
		}
		target, err := filepath.Abs(root.Path)
		if err != nil {
			return nil, nil, err
		}
		if allowed[target] != root.ArchiveName {
			return nil, nil, Error{Message: "Refusing to restore outside Rebecca paths: " + root.Path}
		}
		sourceInfo, err := os.Stat(source)
		if err != nil {
			return nil, nil, err
		}
		if sourceInfo.IsDir() {
			err = replaceDirectoryContents(source, target, skips)
		} else {
			err = copyFile(source, target, sourceInfo.Mode().Perm())
		}
		if err != nil {
			return nil, nil, err
		}
		restored = append(restored, root.Path)
	}
	return restored, warnings, nil
}

func (s *Service) preserveLocalDatabaseEnv(filesDir string) error {
	var targetPath, archiveName string
	for _, root := range s.fileRoots {
		if root.ArchiveName == "rebecca_env" {
			targetPath, archiveName = root.Path, root.ArchiveName
			break
		}
	}
	if targetPath == "" {
		return nil
	}
	sourcePath := filepath.Join(filesDir, archiveName)
	if !isRegularFile(sourcePath) {
		return nil
	}

	assignments := []string{}
	if content, err := os.ReadFile(targetPath); err == nil {
		for _, line := range strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n") {
			if isDatabaseEnvKey(envAssignmentKey(line)) {
				assignments = upsertEnvAssignment(assignments, line)
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}

	parsed, err := url.Parse(s.databaseURL)
	if err != nil {
		return err
	}
	assignments = upsertEnvAssignment(assignments, dotenvAssignment("REBECCA_DATABASE_FLAVOR", s.dialect))
	assignments = upsertEnvAssignment(assignments, dotenvAssignment("SQLALCHEMY_DATABASE_URL", s.databaseURL))
	if parsed.User != nil {
		if username := parsed.User.Username(); username != "" {
			assignments = upsertEnvAssignment(assignments, dotenvAssignment("MYSQL_USER", username))
		}
		if password, ok := parsed.User.Password(); ok {
			assignments = upsertEnvAssignment(assignments, dotenvAssignment("MYSQL_PASSWORD", password))
		}
	}
	if databaseName := strings.TrimPrefix(parsed.Path, "/"); databaseName != "" {
		assignments = upsertEnvAssignment(assignments, dotenvAssignment("MYSQL_DATABASE", databaseName))
	}

	content, err := os.ReadFile(sourcePath)
	if err != nil {
		return err
	}
	lines := strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n")
	filtered := lines[:0]
	for _, line := range lines {
		if !isDatabaseEnvKey(envAssignmentKey(line)) {
			filtered = append(filtered, line)
		}
	}
	for len(filtered) > 0 && filtered[len(filtered)-1] == "" {
		filtered = filtered[:len(filtered)-1]
	}
	filtered = append(filtered, assignments...)
	return os.WriteFile(sourcePath, []byte(strings.Join(filtered, "\n")+"\n"), 0o600)
}

func envAssignmentKey(line string) string {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return ""
	}
	line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
	key, _, ok := strings.Cut(line, "=")
	if !ok {
		return ""
	}
	return strings.TrimSpace(key)
}

func isDatabaseEnvKey(key string) bool {
	return key == "REBECCA_DATABASE_FLAVOR" || key == "SQLALCHEMY_DATABASE_URL" || key == "DATABASE_URL" ||
		strings.HasPrefix(key, "MYSQL_") || strings.HasPrefix(key, "MARIADB_")
}

func upsertEnvAssignment(assignments []string, assignment string) []string {
	key := envAssignmentKey(assignment)
	for index, existing := range assignments {
		if envAssignmentKey(existing) == key {
			assignments[index] = assignment
			return assignments
		}
	}
	return append(assignments, assignment)
}

func dotenvAssignment(key string, value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "\n", `\n`, "\r", `\r`)
	return key + `="` + replacer.Replace(value) + `"`
}

func (s *Service) restoreLegacyJSON(ctx context.Context, dumpPath string) (int, int, []string, error) {
	content, err := os.ReadFile(dumpPath)
	if err != nil {
		return 0, 0, nil, err
	}
	var payload struct {
		Format  string `json:"format"`
		Version int    `json:"version"`
		Tables  []struct {
			Name    string           `json:"name"`
			Columns []string         `json:"columns"`
			Rows    []map[string]any `json:"rows"`
		} `json:"tables"`
	}
	if err := json.Unmarshal(content, &payload); err != nil {
		return 0, 0, nil, err
	}
	if payload.Format != Format {
		return 0, 0, nil, Error{Message: "Invalid database payload format"}
	}
	if payload.Version != Version {
		return 0, 0, nil, Error{Message: "Unsupported database payload version"}
	}
	if s.db == nil {
		return 0, 0, nil, Error{Message: "Database connection is not available"}
	}
	existing, err := s.tableNames(ctx)
	if err != nil {
		return 0, 0, nil, err
	}
	existingSet := map[string]bool{}
	for _, table := range existing {
		existingSet[table] = true
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, nil, err
	}
	defer tx.Rollback()
	if err := s.disableForeignKeys(ctx, tx); err != nil {
		return 0, 0, nil, err
	}
	for _, table := range existing {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+s.quoteIdentifier(table)); err != nil {
			return 0, 0, nil, err
		}
	}
	warnings := []string{}
	tablesRestored := 0
	rowsRestored := 0
	for _, tablePayload := range payload.Tables {
		if !existingSet[tablePayload.Name] {
			warnings = append(warnings, "Skipped unknown table: "+tablePayload.Name)
			continue
		}
		tablesRestored++
		if len(tablePayload.Rows) == 0 || len(tablePayload.Columns) == 0 {
			continue
		}
		columns := []string{}
		for _, col := range tablePayload.Columns {
			if strings.TrimSpace(col) != "" {
				columns = append(columns, col)
			}
		}
		if len(columns) == 0 {
			continue
		}
		query := "INSERT INTO " + s.quoteIdentifier(tablePayload.Name) + " (" + quoteIdentifierList(columns, s.dialect) + ") VALUES (" + placeholders(len(columns)) + ")"
		for _, row := range tablePayload.Rows {
			args := make([]any, len(columns))
			for i, col := range columns {
				args[i] = decodeLegacyValue(row[col])
			}
			if _, err := tx.ExecContext(ctx, query, args...); err != nil {
				return 0, 0, nil, err
			}
			rowsRestored++
		}
	}
	if err := s.enableForeignKeys(ctx, tx); err != nil {
		return 0, 0, nil, err
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, nil, err
	}
	return tablesRestored, rowsRestored, warnings, nil
}

func (s *Service) disableForeignKeys(ctx context.Context, tx *sql.Tx) error {
	switch s.dialect {
	case "sqlite":
		_, err := tx.ExecContext(ctx, "PRAGMA foreign_keys=OFF")
		return err
	case "mysql", "mariadb":
		_, err := tx.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=0")
		return err
	default:
		return nil
	}
}

func (s *Service) enableForeignKeys(ctx context.Context, tx *sql.Tx) error {
	switch s.dialect {
	case "sqlite":
		_, err := tx.ExecContext(ctx, "PRAGMA foreign_keys=ON")
		return err
	case "mysql", "mariadb":
		_, err := tx.ExecContext(ctx, "SET FOREIGN_KEY_CHECKS=1")
		return err
	default:
		return nil
	}
}

func (s *Service) sqliteDatabasePath() (string, error) {
	if s.dialect != "sqlite" {
		return "", Error{Message: "SQLite database file path is not available"}
	}
	path, err := sqlitePathFromURL(s.databaseURL)
	if err != nil {
		return "", err
	}
	if path == ":memory:" || path == "" {
		return "", Error{Message: "SQLite database file path is not available"}
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return abs, nil
}

func (s *Service) activeSQLitePaths() map[string]bool {
	result := map[string]bool{}
	path, err := s.sqliteDatabasePath()
	if err != nil {
		return result
	}
	add := func(value string) {
		if abs, err := filepath.Abs(value); err == nil {
			result[abs] = true
		}
	}
	add(path)
	add(path + "-wal")
	add(path + "-shm")
	return result
}

func (s *Service) mysqlDatabaseName() (string, error) {
	parsed, err := url.Parse(s.databaseURL)
	if err != nil {
		return "", err
	}
	name := strings.TrimPrefix(parsed.Path, "/")
	if name == "" {
		return "", Error{Message: "MySQL/MariaDB database name is not available"}
	}
	return name, nil
}

func (s *Service) writeMySQLDefaultsFile(dir string) (string, error) {
	parsed, err := url.Parse(s.databaseURL)
	if err != nil {
		return "", err
	}
	lines := []string{"[client]"}
	if parsed.User != nil {
		if user := parsed.User.Username(); user != "" {
			lines = append(lines, "user="+mysqlOptionValue(user))
		}
		if password, ok := parsed.User.Password(); ok {
			lines = append(lines, "password="+mysqlOptionValue(password))
		}
	}
	host := parsed.Host
	if host != "" {
		if h, p, err := net.SplitHostPort(host); err == nil {
			lines = append(lines, "host="+mysqlOptionValue(h), "protocol=tcp", "port="+mysqlOptionValue(p))
		} else {
			lines = append(lines, "host="+mysqlOptionValue(host), "protocol=tcp")
		}
	}
	query := parsed.Query()
	socketPath := firstNonEmpty(query.Get("unix_socket"), query.Get("socket"))
	if socketPath != "" {
		lines = append(lines, "socket="+mysqlOptionValue(socketPath))
	}
	path := filepath.Join(dir, "mysql-client.cnf")
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func mysqlOptionValue(value string) string {
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`, "\r", `\r`)
	return `"` + replacer.Replace(value) + `"`
}

func filterMySQLDumpForDatabase(inputPath string, outputPath string) error {
	input, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer output.Close()
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 0, 1024*1024), 64*1024*1024)
	writer := bufio.NewWriter(output)
	defer writer.Flush()
	for scanner.Scan() {
		line := scanner.Text()
		normalized := strings.TrimSpace(line)
		upper := strings.ToUpper(normalized)
		if strings.HasPrefix(upper, "USE ") ||
			strings.Contains(upper, "DROP DATABASE") ||
			strings.Contains(upper, "CREATE DATABASE") ||
			strings.HasPrefix(upper, "-- CURRENT DATABASE:") {
			continue
		}
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return nil
}

func (s *Service) quoteIdentifier(name string) string {
	if s.dialect == "mysql" || s.dialect == "mariadb" {
		return quoteMySQLIdentifier(name)
	}
	return quoteSQLiteIdentifier(name)
}

func validateScope(scope string) (string, error) {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		scope = ScopeDatabase
	}
	if scope != ScopeDatabase && scope != ScopeFull {
		return "", Error{Message: "Backup scope must be database or full"}
	}
	return scope, nil
}

func validateSQLiteFile(path string) error {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Ping()
}

func restoreSQLiteLogically(ctx context.Context, target *sql.DB, sourcePath string) error {
	source, err := sql.Open("sqlite", "file:"+sourcePath+"?mode=ro")
	if err != nil {
		return err
	}
	defer source.Close()
	rows, err := source.QueryContext(ctx, `SELECT name, sql FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		return err
	}
	type tableDDL struct {
		Name string
		SQL  string
	}
	tables := []tableDDL{}
	for rows.Next() {
		var table tableDDL
		if err := rows.Scan(&table.Name, &table.SQL); err != nil {
			rows.Close()
			return err
		}
		tables = append(tables, table)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	tx, err := target.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "PRAGMA foreign_keys=OFF"); err != nil {
		return err
	}
	targetRows, err := tx.QueryContext(ctx, `SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return err
	}
	targetTables := []string{}
	for targetRows.Next() {
		var name string
		if err := targetRows.Scan(&name); err != nil {
			targetRows.Close()
			return err
		}
		targetTables = append(targetTables, name)
	}
	if err := targetRows.Close(); err != nil {
		return err
	}
	for _, table := range targetTables {
		if _, err := tx.ExecContext(ctx, "DROP TABLE IF EXISTS "+quoteSQLiteIdentifier(table)); err != nil {
			return err
		}
	}
	for _, table := range tables {
		if _, err := tx.ExecContext(ctx, table.SQL); err != nil {
			return err
		}
		cols, err := sqliteColumns(ctx, source, table.Name)
		if err != nil {
			return err
		}
		if len(cols) == 0 {
			continue
		}
		query := "SELECT " + quoteIdentifierList(cols, "sqlite") + " FROM " + quoteSQLiteIdentifier(table.Name)
		sourceRows, err := source.QueryContext(ctx, query)
		if err != nil {
			return err
		}
		insertQuery := "INSERT INTO " + quoteSQLiteIdentifier(table.Name) + " (" + quoteIdentifierList(cols, "sqlite") + ") VALUES (" + placeholders(len(cols)) + ")"
		for sourceRows.Next() {
			values := make([]any, len(cols))
			scanArgs := make([]any, len(cols))
			for i := range values {
				scanArgs[i] = &values[i]
			}
			if err := sourceRows.Scan(scanArgs...); err != nil {
				sourceRows.Close()
				return err
			}
			if _, err := tx.ExecContext(ctx, insertQuery, values...); err != nil {
				sourceRows.Close()
				return err
			}
		}
		if err := sourceRows.Close(); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, "PRAGMA foreign_keys=ON"); err != nil {
		return err
	}
	return tx.Commit()
}

func sqliteColumns(ctx context.Context, db *sql.DB, table string) ([]string, error) {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+quoteSQLiteIdentifier(table)+")")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	columns := []string{}
	for rows.Next() {
		var cid int
		var name string
		var typ string
		var notNull int
		var defaultValue any
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notNull, &defaultValue, &pk); err != nil {
			return nil, err
		}
		columns = append(columns, name)
	}
	return columns, rows.Err()
}

func safeExtract(archivePath string, destination string) error {
	file, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer file.Close()
	base, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	var signature [4]byte
	if _, err := io.ReadFull(file, signature[:]); err != nil {
		return Error{Message: "Backup archive is invalid or empty"}
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if signature[0] == 0x1f && signature[1] == 0x8b {
		gzipReader, err := gzip.NewReader(file)
		if err != nil {
			return Error{Message: "Backup archive is not a valid gzip file"}
		}
		defer gzipReader.Close()
		return safeExtractTar(tar.NewReader(gzipReader), base)
	}
	if signature[0] == 'P' && signature[1] == 'K' && (signature[2] == 0x03 || signature[2] == 0x05 || signature[2] == 0x07) {
		return safeExtractZip(archivePath, base)
	}
	return Error{Message: "Backup archive must be a tar.gz or ZIP file"}
}

func safeExtractTar(tarReader *tar.Reader, base string) error {
	entries := 0
	var extracted int64
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		entries++
		if entries > maxBackupArchiveEntries {
			return Error{Message: "Backup archive contains too many entries"}
		}
		entryName, err := safeArchiveName(header.Name)
		if err != nil {
			return err
		}
		target, err := safeArchiveTarget(base, entryName)
		if err != nil {
			return err
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, fs.FileMode(header.Mode)&0o777); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if header.Size < 0 || header.Size > maxBackupExtractBytes-extracted {
				return Error{Message: "Backup archive is too large to extract"}
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fs.FileMode(header.Mode)&0o666)
			if err != nil {
				return err
			}
			written, copyErr := io.Copy(out, tarReader)
			if copyErr != nil {
				_ = out.Close()
				return copyErr
			}
			if err := out.Close(); err != nil {
				return err
			}
			extracted += written
		default:
			return Error{Message: "Backup archive contains unsupported linked or device entries"}
		}
	}
}

func safeExtractZip(archivePath string, base string) error {
	reader, err := zip.OpenReader(archivePath)
	if err != nil {
		return Error{Message: "Backup archive is not a valid ZIP file"}
	}
	defer reader.Close()
	if len(reader.File) > maxBackupArchiveEntries {
		return Error{Message: "Backup archive contains too many entries"}
	}
	var extracted int64
	for _, entry := range reader.File {
		entryName, err := safeArchiveName(entry.Name)
		if err != nil {
			return err
		}
		target, err := safeArchiveTarget(base, entryName)
		if err != nil {
			return err
		}
		mode := entry.FileInfo().Mode()
		if mode&os.ModeSymlink != 0 || mode&os.ModeNamedPipe != 0 || mode&os.ModeDevice != 0 || mode&os.ModeSocket != 0 {
			return Error{Message: "Backup archive contains unsupported linked or device entries"}
		}
		if entry.FileInfo().IsDir() || strings.HasSuffix(entry.Name, "/") {
			if err := os.MkdirAll(target, mode.Perm()&0o777); err != nil {
				return err
			}
			continue
		}
		if entry.UncompressedSize64 > uint64(maxBackupExtractBytes-extracted) {
			return Error{Message: "Backup archive is too large to extract"}
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		input, err := entry.Open()
		if err != nil {
			return err
		}
		fileMode := mode.Perm() & 0o666
		if fileMode == 0 {
			fileMode = 0o600
		}
		output, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fileMode)
		if err != nil {
			_ = input.Close()
			return err
		}
		written, copyErr := io.Copy(output, io.LimitReader(input, maxBackupExtractBytes-extracted+1))
		closeInputErr := input.Close()
		closeOutputErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if closeInputErr != nil {
			return closeInputErr
		}
		if closeOutputErr != nil {
			return closeOutputErr
		}
		if written > maxBackupExtractBytes-extracted || uint64(written) != entry.UncompressedSize64 {
			return Error{Message: "Backup archive is too large to extract"}
		}
		extracted += written
	}
	return nil
}

func safeArchiveName(name string) (string, error) {
	if strings.TrimSpace(name) == "" {
		return "", Error{Message: "Backup archive contains unsafe paths"}
	}
	cleaned := filepath.Clean(filepath.FromSlash(name))
	if filepath.IsAbs(cleaned) || cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(filepath.Separator)) || !filepath.IsLocal(cleaned) {
		return "", Error{Message: "Backup archive contains unsafe paths"}
	}
	return cleaned, nil
}

func safeArchiveTarget(base string, name string) (string, error) {
	cleaned, err := safeArchiveName(name)
	if err != nil {
		return "", err
	}
	target := filepath.Join(base, cleaned)
	resolved, err := filepath.Abs(target)
	if err != nil {
		return "", err
	}
	if resolved != base && !strings.HasPrefix(resolved, base+string(filepath.Separator)) {
		return "", Error{Message: "Backup archive contains unsafe paths"}
	}
	return resolved, nil
}

func loadManifest(path string) (manifest, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return manifest{}, Error{Message: "Backup manifest is missing"}
	}
	var m manifest
	if err := json.Unmarshal(content, &m); err != nil {
		return manifest{}, err
	}
	if m.Format != Format {
		return manifest{}, Error{Message: "Invalid backup manifest format"}
	}
	if m.Version != Version {
		return manifest{}, Error{Message: "Unsupported backup manifest version"}
	}
	return m, nil
}

func addFileToTar(writer *tar.Writer, source string, archiveName string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return err
	}
	header.Name = filepath.ToSlash(archiveName)
	header.Uid = 0
	header.Gid = 0
	header.Uname = ""
	header.Gname = ""
	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	file, err := os.Open(source)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = io.Copy(writer, file)
	return err
}

func addTreeToTar(writer *tar.Writer, root string, archiveRoot string, skip map[string]bool) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	return filepath.WalkDir(rootAbs, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeDevice != 0 || info.Mode()&os.ModeNamedPipe != 0 || info.Mode()&os.ModeSocket != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		pathAbs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if skip[pathAbs] {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(rootAbs, pathAbs)
		if err != nil {
			return err
		}
		name := archiveRoot
		if rel != "." {
			name = filepath.ToSlash(filepath.Join(archiveRoot, rel))
		}
		if entry.IsDir() {
			header := &tar.Header{Name: name, Mode: int64(info.Mode().Perm()), Typeflag: tar.TypeDir, ModTime: info.ModTime()}
			return writer.WriteHeader(header)
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		return addFileToTar(writer, pathAbs, name)
	})
}

func replaceDirectoryContents(source string, target string, skip map[string]bool) error {
	if err := os.MkdirAll(target, 0o755); err != nil {
		return err
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		path := filepath.Join(target, entry.Name())
		abs, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if skip[abs] {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	}
	return copyTree(source, target, skip)
}

func copyTree(source string, target string, skip map[string]bool) error {
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		destination := filepath.Join(target, rel)
		destinationAbs, err := filepath.Abs(destination)
		if err != nil {
			return err
		}
		if skip[destinationAbs] {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return os.MkdirAll(destination, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		return copyFile(path, destination, info.Mode().Perm())
	})
}

func copyFile(source string, destination string, mode fs.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer output.Close()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	return output.Close()
}

func defaultFileRoots() []FileRoot {
	configDir := strings.TrimSpace(os.Getenv("REBECCA_CONFIG_DIR"))
	if configDir == "" {
		configDir = "/etc/rebecca"
	}
	dataDir := strings.TrimSpace(os.Getenv("REBECCA_DATA_DIR"))
	if dataDir == "" {
		dataDir = "/var/lib/rebecca"
	}
	roots := []FileRoot{
		{ArchiveName: "etc_rebecca", Path: configDir},
		{ArchiveName: "var_lib_rebecca", Path: dataDir},
	}
	if envFile := defaultEnvFileRoot(); envFile != "" {
		roots = append(roots, FileRoot{ArchiveName: "rebecca_env", Path: envFile})
	}
	return roots
}

func defaultEnvFileRoot() string {
	for _, candidate := range []string{
		strings.TrimSpace(os.Getenv("REBECCA_ENV_FILE")),
		"/opt/rebecca/.env",
	} {
		if candidate == "" {
			continue
		}
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	return ""
}

func normalizeDialect(dialect string) string {
	dialect = strings.ToLower(strings.TrimSpace(dialect))
	if strings.HasPrefix(dialect, "sqlite") {
		return "sqlite"
	}
	if strings.HasPrefix(dialect, "mysql") {
		return "mysql"
	}
	if strings.HasPrefix(dialect, "mariadb") {
		return "mariadb"
	}
	return dialect
}

func sourceURLDialect(databaseURL string) string {
	if idx := strings.Index(databaseURL, ":"); idx > 0 {
		return databaseURL[:idx]
	}
	return "unknown"
}

func sqlitePathFromURL(databaseURL string) (string, error) {
	databaseURL = strings.TrimSpace(databaseURL)
	if strings.HasPrefix(databaseURL, "sqlite:///") {
		path := strings.TrimPrefix(databaseURL, "sqlite:///")
		if path == "" {
			return "", Error{Message: "SQLite database file path is not available"}
		}
		return filepath.FromSlash(path), nil
	}
	if strings.HasPrefix(databaseURL, "sqlite://") {
		parsed, err := url.Parse(databaseURL)
		if err != nil {
			return "", err
		}
		if parsed.Path == "" {
			return "", Error{Message: "SQLite database file path is not available"}
		}
		return filepath.FromSlash(parsed.Path), nil
	}
	return "", Error{Message: "SQLite database file path is not available"}
}

func findExecutable(candidates []string) (string, error) {
	for _, candidate := range candidates {
		if path, err := exec.LookPath(candidate); err == nil && path != "" {
			return path, nil
		}
	}
	return "", Error{Message: "Required database tool is not installed: " + strings.Join(candidates, " or ")}
}

func isRegularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func sqliteQuoteString(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func quoteSQLiteIdentifier(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `""`) + `"`
}

func quoteMySQLIdentifier(value string) string {
	return "`" + strings.ReplaceAll(value, "`", "``") + "`"
}

func quoteIdentifierList(columns []string, dialect string) string {
	quoted := make([]string, 0, len(columns))
	for _, column := range columns {
		if normalizeDialect(dialect) == "mysql" || normalizeDialect(dialect) == "mariadb" {
			quoted = append(quoted, quoteMySQLIdentifier(column))
		} else {
			quoted = append(quoted, quoteSQLiteIdentifier(column))
		}
	}
	return strings.Join(quoted, ",")
}

func placeholders(count int) string {
	parts := make([]string, count)
	for i := range parts {
		parts[i] = "?"
	}
	return strings.Join(parts, ",")
}

func decodeLegacyValue(value any) any {
	object, ok := value.(map[string]any)
	if !ok || len(object) != 2 {
		return value
	}
	marker, _ := object["__rebecca_type__"].(string)
	raw := object["value"]
	switch marker {
	case "bytes":
		if encoded, ok := raw.(string); ok {
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err == nil {
				return decoded
			}
		}
	case "datetime", "date", "time", "decimal":
		return raw
	}
	return value
}
