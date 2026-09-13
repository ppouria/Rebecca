package api

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	externalapps "github.com/rebeccapanel/rebecca/internal/app/externalapps"
)

const maxExternalAppResponseBytes = 64 << 20

type externalAppAwareHandler struct {
	apps *externalapps.Manager
	next http.Handler
}

func (h *externalAppAwareHandler) HandlesHost(host string) bool {
	if h == nil || h.apps == nil {
		return false
	}
	return h.apps.HasHost(host)
}

func (h *externalAppAwareHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.apps == nil {
		h.next.ServeHTTP(w, r)
		return
	}
	record, relativePath, ok := h.apps.Match(r.Host, r.URL.Path)
	if !ok {
		record, relativePath, ok = h.apps.MatchMirzaLegacyPath(r.Host, r.URL.Path)
	}
	if !ok {
		if !h.apps.HasHost(r.Host) {
			h.next.ServeHTTP(w, r)
			return
		}
		http.NotFound(w, r)
		return
	}
	setExternalAppSecurityHeaders(w.Header())
	if !record.Enabled {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "Application is disabled", http.StatusServiceUnavailable)
		return
	}
	requestBodyLimit := externalapps.ExternalAppRequestBodyLimitBytes(record)
	if r.ContentLength > requestBodyLimit {
		http.Error(w, "Request body is too large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, requestBodyLimit)
	if err := serveExternalApp(h.apps, w, r, record, relativePath); err != nil {
		http.Error(w, "Application is unavailable", http.StatusBadGateway)
	}
}

func serveExternalApp(manager *externalapps.Manager, w http.ResponseWriter, r *http.Request, record externalapps.Record, requestPath string) error {
	if record.Runtime == "node" {
		target := &url.URL{Scheme: "http", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(record.Port))}
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(w, "Application is unavailable", http.StatusBadGateway)
		}
		proxy.ServeHTTP(w, r)
		return nil
	}
	directoryIndex := strings.HasSuffix(r.URL.Path, "/") || (requestPath == "" && r.Method == http.MethodPost)
	rel, fullPath, info, err := resolveExternalAppPath(record, requestPath, directoryIndex)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if !serveExternalAppNotFound(w, r, record) {
				http.NotFound(w, r)
			}
			return nil
		}
		return err
	}
	if info.IsDir() && !strings.HasSuffix(r.URL.Path, "/") {
		target := r.URL.Path + "/"
		if r.URL.RawQuery != "" {
			target += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
		return nil
	}
	if info.IsDir() {
		if !serveExternalAppNotFound(w, r, record) {
			http.NotFound(w, r)
		}
		return nil
	}
	if strings.EqualFold(filepath.Ext(rel), ".php") {
		if record.Runtime != "php" || !phpScriptAllowed(record, rel) {
			http.NotFound(w, r)
			return nil
		}
		if record.Template == "mirzabot" {
			if err := manager.AuthorizeMirzaRequest(r, record, rel); err != nil {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return nil
			}
		}
		return serveExternalAppFastCGI(w, r, record, rel, fullPath)
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return nil
	}
	serveExternalAppStatic(w, r, record, rel)
	return nil
}

func resolveExternalAppPath(record externalapps.Record, requestPath string, directoryIndex bool) (string, string, os.FileInfo, error) {
	if strings.ContainsRune(requestPath, '\x00') || strings.Contains(requestPath, "\\") {
		return "", "", nil, os.ErrNotExist
	}
	cleanPath := path.Clean("/" + requestPath)
	rel := strings.TrimPrefix(cleanPath, "/")
	if rel == "." {
		rel = ""
	}
	if externalAppPathDenied(rel) {
		return "", "", nil, os.ErrNotExist
	}
	root, err := os.OpenRoot(record.Root)
	if err != nil {
		return "", "", nil, err
	}
	defer root.Close()
	rootPath := filepath.FromSlash(rel)
	if rootPath == "" {
		rootPath = "."
	}
	info, err := root.Stat(rootPath)
	if err != nil && record.FallbackToIndex && record.IndexFile != "" {
		candidate := filepath.FromSlash(record.IndexFile)
		if candidateInfo, candidateErr := root.Stat(candidate); candidateErr == nil && !candidateInfo.IsDir() {
			rel = filepath.ToSlash(record.IndexFile)
			info = candidateInfo
			err = nil
		}
	}
	if err == nil && info.IsDir() && directoryIndex {
		indexes := []string{"index.php", "index.html"}
		if rootPath == "." && record.IndexFile != "" {
			indexes = []string{record.IndexFile}
		}
		for _, index := range indexes {
			candidate := filepath.Join(rootPath, index)
			candidateInfo, candidateErr := root.Stat(candidate)
			if candidateErr == nil && !candidateInfo.IsDir() {
				rel = path.Join(rel, index)
				info = candidateInfo
				break
			}
		}
	}
	if err != nil {
		return "", "", nil, os.ErrNotExist
	}
	if externalAppPathDenied(rel) {
		return "", "", nil, os.ErrNotExist
	}
	return filepath.ToSlash(rel), filepath.Join(record.Root, filepath.FromSlash(rel)), info, nil
}

func externalAppPathDenied(rel string) bool {
	if rel == "" {
		return false
	}
	parts := strings.Split(strings.ToLower(filepath.ToSlash(rel)), "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.HasPrefix(part, ".") {
			return true
		}
	}
	switch parts[0] {
	case "vendor":
		return true
	}
	switch strings.ToLower(path.Base(rel)) {
	case "config.php", "table.php", "composer.json", "composer.lock", "install.sh":
		return true
	default:
		return false
	}
}

func phpScriptAllowed(record externalapps.Record, rel string) bool {
	if record.Template != "mirzabot" {
		return true
	}
	rel = strings.ToLower(filepath.ToSlash(rel))
	if rel == strings.ToLower(filepath.ToSlash(record.IndexFile)) || (record.IndexFile == "" && rel == "index.php") {
		return true
	}
	for _, prefix := range []string{"api/", "app/", "cronbot/", "panel/", "payment/", "sub/", "vpnbot/"} {
		if strings.HasPrefix(rel, prefix) {
			return true
		}
	}
	return false
}

func serveExternalAppStatic(w http.ResponseWriter, r *http.Request, record externalapps.Record, rel string) {
	if contentType := mime.TypeByExtension(strings.ToLower(filepath.Ext(rel))); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	if strings.EqualFold(filepath.Ext(rel), ".html") {
		w.Header().Set("Cache-Control", "no-cache")
	} else {
		seconds := externalapps.ExternalAppStaticCacheSeconds(record)
		if seconds == 0 {
			w.Header().Set("Cache-Control", "no-cache")
		} else {
			w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d", seconds))
		}
	}
	file, err := os.OpenInRoot(record.Root, filepath.FromSlash(rel))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	http.ServeContent(w, r, info.Name(), info.ModTime(), file)
}

func serveExternalAppNotFound(w http.ResponseWriter, r *http.Request, record externalapps.Record) bool {
	rel := strings.TrimSpace(record.NotFoundFile)
	if rel == "" {
		return false
	}
	file, err := os.OpenInRoot(record.Root, filepath.FromSlash(rel))
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	if contentType := mime.TypeByExtension(strings.ToLower(filepath.Ext(rel))); contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	w.WriteHeader(http.StatusNotFound)
	if r.Method != http.MethodHead {
		_, _ = io.Copy(w, file)
	}
	return true
}

func serveExternalAppFastCGI(w http.ResponseWriter, r *http.Request, record externalapps.Record, scriptRel, scriptPath string) error {
	params := externalAppFastCGIParams(r, record, scriptRel, scriptPath)
	stdout, stderr, err := fastCGIRequestLimited("unix", record.Socket, params, r.Body, maxExternalAppResponseBytes)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			http.Error(w, "Request body is too large", http.StatusRequestEntityTooLarge)
			return nil
		}
		return err
	}
	if len(stderr) > 0 && len(stdout) == 0 {
		return errors.New("PHP-FPM returned an error")
	}
	return writeExternalAppFastCGIResponse(w, stdout)
}

func externalAppFastCGIParams(r *http.Request, record externalapps.Record, scriptRel, scriptPath string) map[string]string {
	serverName := externalapps.CanonicalHost(r.Host)
	serverPort := "80"
	if _, port, err := net.SplitHostPort(r.Host); err == nil {
		serverPort = port
	} else if requestScheme(r) == "https" {
		serverPort = "443"
	}
	scriptName := "/" + path.Join(record.Path, strings.TrimLeft(filepath.ToSlash(scriptRel), "/"))
	remoteAddr := remoteHost(r.RemoteAddr)
	if record.Template == "mirzabot" {
		remoteAddr = requestRemote(r)
	}
	params := map[string]string{
		"GATEWAY_INTERFACE": "CGI/1.1",
		"SERVER_SOFTWARE":   "Rebecca",
		"REQUEST_METHOD":    r.Method,
		"QUERY_STRING":      r.URL.RawQuery,
		"REQUEST_URI":       r.URL.RequestURI(),
		"SCRIPT_FILENAME":   scriptPath,
		"SCRIPT_NAME":       scriptName,
		"PHP_SELF":          scriptName,
		"DOCUMENT_ROOT":     record.Root,
		"REDIRECT_STATUS":   "200",
		"SERVER_NAME":       serverName,
		"SERVER_PORT":       serverPort,
		"SERVER_PROTOCOL":   r.Proto,
		"REMOTE_ADDR":       remoteAddr,
		"HTTPS":             "off",
	}
	if requestScheme(r) == "https" {
		params["HTTPS"] = "on"
	}
	if r.ContentLength > 0 {
		params["CONTENT_LENGTH"] = strconv.FormatInt(r.ContentLength, 10)
	}
	if contentType := r.Header.Get("Content-Type"); contentType != "" {
		params["CONTENT_TYPE"] = contentType
	}
	for key, values := range r.Header {
		if len(values) == 0 {
			continue
		}
		cgiName := "HTTP_" + strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
		switch cgiName {
		case "HTTP_CONTENT_TYPE", "HTTP_CONTENT_LENGTH", "HTTP_CONNECTION", "HTTP_PROXY":
			continue
		}
		params[cgiName] = strings.Join(values, ", ")
	}
	return params
}

func writeExternalAppFastCGIResponse(w http.ResponseWriter, stdout []byte) error {
	headers, body, err := splitFastCGIHeaders(stdout)
	if err != nil {
		return err
	}
	statusCode := http.StatusOK
	statusSet := false
	hasLocation := false
	for key, values := range headers {
		if strings.EqualFold(key, "Status") && len(values) > 0 {
			if fields := strings.Fields(values[0]); len(fields) > 0 {
				if code, err := strconv.Atoi(fields[0]); err == nil && code >= 100 && code <= 999 {
					statusCode = code
					statusSet = true
				}
			}
			continue
		}
		if externalAppHopByHopHeader(key) || strings.EqualFold(key, "X-Powered-By") || strings.EqualFold(key, "Content-Length") {
			continue
		}
		if strings.EqualFold(key, "Location") {
			hasLocation = true
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	if hasLocation && !statusSet {
		statusCode = http.StatusFound
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(statusCode)
	_, err = w.Write(body)
	return err
}

func externalAppHopByHopHeader(key string) bool {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func setExternalAppSecurityHeaders(header http.Header) {
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "same-origin")
	header.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	header.Set("X-Frame-Options", "SAMEORIGIN")
}
