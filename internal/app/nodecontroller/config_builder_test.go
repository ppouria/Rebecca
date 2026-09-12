package nodecontroller

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestRuntimeConfigPreparationHonorsOccupiedSlot(t *testing.T) {
	controller := Controller{runtimeConfigPrep: make(chan struct{}, 1)}
	release, err := controller.lockRuntimeConfigPreparation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := controller.lockRuntimeConfigPreparation(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("occupied slot error = %v, want context canceled", err)
	}
	release()
	release, err = controller.lockRuntimeConfigPreparation(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	release()
}

func TestRuntimeConfigRequestUsesProvidedInbounds(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	controller := NewController(NewRepository(db, "sqlite"))
	req, err := controller.runtimeConfigRequestFromInbounds(context.Background(), NodeRow{}, "test", `{}`, []map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	var runtime map[string]any
	if err := json.Unmarshal([]byte(req.GetOvRuntimeJson()), &runtime); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"inbounds", "l2tp_inbounds", "pptp_inbounds", "wg_inbounds", "ikev2_inbounds", "anyconnect_inbounds"} {
		if got := interfaceSlice(runtime[key]); len(got) != 0 {
			t.Fatalf("%s = %#v, want empty", key, got)
		}
	}
}

func TestIncludeDBUsersPreservesReverseClient(t *testing.T) {
	raw := map[string]any{
		"inbounds": []any{map[string]any{
			"tag":      "vless-in",
			"protocol": "vless",
			"settings": map[string]any{"clients": []any{
				map[string]any{"id": "regular"},
				map[string]any{"id": "reverse", "reverse": map[string]any{"tag": "reverse-out"}},
			}},
		}},
	}

	if err := (Controller{}).includeDBUsers(context.Background(), raw, &runtimeConfigData{}); err != nil {
		t.Fatal(err)
	}
	clients := interfaceSlice(mapValue(listOfMaps(raw["inbounds"])[0]["settings"])["clients"])
	if len(clients) != 1 || stringValue(mapValue(clients[0])["id"]) != "reverse" {
		t.Fatalf("unexpected runtime clients: %#v", clients)
	}
}

func TestIncludeDBUsersKeepsPerInboundEmailsIndependent(t *testing.T) {
	raw := map[string]any{"inbounds": []any{
		map[string]any{"tag": "vless-a", "protocol": "vless", "settings": map[string]any{"clients": []any{}}, "streamSettings": map[string]any{"network": "tcp", "security": "tls"}},
		map[string]any{"tag": "vless-b", "protocol": "vless", "settings": map[string]any{"clients": []any{}}, "streamSettings": map[string]any{"network": "tcp", "security": "tls"}},
	}}
	data := &runtimeConfigData{
		users: []runtimeUserRow{{
			ID: 1, Username: "alice", CredentialKey: "05bfddf81eb418fa1edbce7cd286eee1", Flow: "legacy-flow", Protocol: "vless",
			ServiceID: sql.NullInt64{Int64: 7, Valid: true}, Settings: map[string]any{},
		}},
		serviceTags:  map[int64]map[string]bool{7: {"vless-a": true, "vless-b": true}},
		serviceFlows: map[int64]string{7: "xtls-rprx-vision"},
		masks:        map[string][]byte{},
	}
	if err := (Controller{}).includeDBUsers(context.Background(), raw, data); err != nil {
		t.Fatal(err)
	}
	for i, tag := range []string{"vless-a", "vless-b"} {
		clients := interfaceSlice(mapValue(listOfMaps(raw["inbounds"])[i]["settings"])["clients"])
		if len(clients) != 1 || stringValue(mapValue(clients[0])["email"]) != inboundRuntimeUserEmail(1, "alice", tag) {
			t.Fatalf("%s clients = %#v", tag, clients)
		}
		if stringValue(mapValue(clients[0])["flow"]) != "xtls-rprx-vision" {
			t.Fatalf("%s flow = %#v, want service flow", tag, clients[0])
		}
	}
}

func TestIncludeDBUsersBuildsShadowsocks2022Client(t *testing.T) {
	raw := map[string]any{
		"inbounds": []any{map[string]any{
			"tag":      "ss-2022",
			"protocol": "shadowsocks",
			"settings": map[string]any{
				"method":   "2022-blake3-aes-256-gcm",
				"password": "c2VydmVyLXBhc3N3ZC1tdXN0LWJlLTMya2V5cw==",
				"clients":  []any{},
			},
		}},
	}
	data := &runtimeConfigData{
		users: []runtimeUserRow{{
			ID: 1, Username: "alice", CredentialKey: "05bfddf81eb418fa1edbce7cd286eee1", Protocol: "shadowsocks",
			ServiceID: sql.NullInt64{Int64: 7, Valid: true}, Settings: map[string]any{},
		}},
		serviceTags: map[int64]map[string]bool{7: {"ss-2022": true}},
		masks:       map[string][]byte{},
	}
	if err := (Controller{}).includeDBUsers(context.Background(), raw, data); err != nil {
		t.Fatal(err)
	}
	clients := interfaceSlice(ensureMap(listOfMaps(raw["inbounds"])[0], "settings")["clients"])
	if len(clients) != 1 {
		t.Fatalf("expected one shadowsocks client, got %#v", clients)
	}
	client := mapValue(clients[0])
	if _, exists := client["method"]; exists {
		t.Fatalf("shadowsocks 2022 clients must not contain method: %#v", client)
	}
	key, err := base64.StdEncoding.DecodeString(stringValue(client["password"]))
	if err != nil || len(key) != 32 {
		t.Fatalf("shadowsocks 2022 client key must be 32 bytes: %#v err=%v", client, err)
	}
}

func TestApplyRuntimeAPIEnablesOnlineUserStats(t *testing.T) {
	raw := map[string]any{
		"inbounds":  []any{},
		"outbounds": []any{},
	}

	applyRuntimeAPI(raw, 10085)

	policy := mapValue(raw["policy"])
	levels := mapValue(policy["levels"])
	level0 := mapValue(levels["0"])
	if level0["statsUserUplink"] != true || level0["statsUserDownlink"] != true || level0["statsUserOnline"] != true {
		encoded, _ := json.Marshal(level0)
		t.Fatalf("runtime user stats policy is incomplete: %s", encoded)
	}
	system := mapValue(policy["system"])
	if system["statsInboundUplink"] != true || system["statsInboundDownlink"] != true {
		t.Fatalf("runtime inbound stats policy is incomplete: %#v", system)
	}
}

func TestRemoteAccessProtocolsRequireFullUserSync(t *testing.T) {
	for _, protocol := range []string{"openvpn", "l2tp", "pptp", "wireguard", "ikev2", "anyconnect"} {
		if !protocolRequiresFullUserSync(protocol) {
			t.Fatalf("%s user changes must trigger a full runtime sync", protocol)
		}
	}
	if protocolRequiresFullUserSync("vless") {
		t.Fatal("Xray-native users should keep using hot user updates")
	}
}

func TestInlineTLSCertificateFilesReadsMasterPaths(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "fullchain.pem")
	keyPath := filepath.Join(dir, "key.pem")
	certContent := "-----BEGIN CERTIFICATE-----\ncert-line\n-----END CERTIFICATE-----\n"
	keyContent := "-----BEGIN PRIVATE KEY-----\nkey-line\n-----END PRIVATE KEY-----\n"
	if err := os.WriteFile(certPath, []byte(certContent), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(keyContent), 0o600); err != nil {
		t.Fatal(err)
	}

	raw := map[string]any{
		"inbounds": []any{
			map[string]any{
				"tag":      "tls-in",
				"protocol": "vless",
				"streamSettings": map[string]any{
					"security": "tls",
					"tlsSettings": map[string]any{
						"certificates": []any{
							map[string]any{
								"certificateFile": certPath,
								"keyFile":         keyPath,
								"usage":           "encipherment",
							},
						},
					},
				},
			},
		},
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}},
	}

	if err := inlineTLSCertificateFiles(raw); err != nil {
		t.Fatal(err)
	}
	certificate := firstRuntimeCertificate(t, raw)
	if _, ok := certificate["certificateFile"]; ok {
		t.Fatalf("certificateFile should not be sent to node: %#v", certificate)
	}
	if _, ok := certificate["keyFile"]; ok {
		t.Fatalf("keyFile should not be sent to node: %#v", certificate)
	}
	expectedCert := []string{"-----BEGIN CERTIFICATE-----", "cert-line", "-----END CERTIFICATE-----"}
	expectedKey := []string{"-----BEGIN PRIVATE KEY-----", "key-line", "-----END PRIVATE KEY-----"}
	if !reflect.DeepEqual(certificate["certificate"], expectedCert) {
		t.Fatalf("unexpected inline certificate: %#v", certificate["certificate"])
	}
	if !reflect.DeepEqual(certificate["key"], expectedKey) {
		t.Fatalf("unexpected inline key: %#v", certificate["key"])
	}
	if certificate["usage"] != "encipherment" {
		t.Fatalf("certificate metadata was lost: %#v", certificate)
	}
}

func TestInlineTLSCertificateFilesSupportsLegacyCertFileAlias(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, []byte("cert\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := map[string]any{
		"inbounds": []any{
			map[string]any{
				"tag": "legacy-cert-alias",
				"streamSettings": map[string]any{
					"tlsSettings": map[string]any{
						"certificates": []map[string]any{
							{"certFile": certPath, "keyfile": keyPath},
						},
					},
				},
			},
		},
	}

	if err := inlineTLSCertificateFiles(raw); err != nil {
		t.Fatal(err)
	}
	certificate := firstRuntimeCertificate(t, raw)
	for _, key := range []string{"certFile", "certfile", "keyFile", "keyfile"} {
		if _, ok := certificate[key]; ok {
			t.Fatalf("%s should not be sent to node: %#v", key, certificate)
		}
	}
	if !reflect.DeepEqual(certificate["certificate"], []string{"cert"}) {
		t.Fatalf("unexpected certificate content: %#v", certificate["certificate"])
	}
	if !reflect.DeepEqual(certificate["key"], []string{"key"}) {
		t.Fatalf("unexpected key content: %#v", certificate["key"])
	}
}

func TestInlineTLSCertificateFilesKeepsExistingInlineContent(t *testing.T) {
	raw := map[string]any{
		"inbounds": []any{
			map[string]any{
				"tag": "inline-cert",
				"streamSettings": map[string]any{
					"tlsSettings": map[string]any{
						"certificates": []any{
							map[string]any{
								"certificateFile": "/does/not/need/to/exist",
								"keyFile":         "/does/not/need/to/exist",
								"certificate":     "cert-a\ncert-b\n",
								"key":             []any{"key-a", "key-b"},
							},
						},
					},
				},
			},
		},
	}

	if err := inlineTLSCertificateFiles(raw); err != nil {
		t.Fatal(err)
	}
	certificate := firstRuntimeCertificate(t, raw)
	if _, ok := certificate["certificateFile"]; ok {
		t.Fatalf("path fields should be removed even when inline content exists: %#v", certificate)
	}
	if !reflect.DeepEqual(certificate["certificate"], []string{"cert-a", "cert-b"}) {
		t.Fatalf("unexpected normalized certificate: %#v", certificate["certificate"])
	}
	if !reflect.DeepEqual(certificate["key"], []string{"key-a", "key-b"}) {
		t.Fatalf("unexpected normalized key: %#v", certificate["key"])
	}
}

func TestInlineTLSCertificateFilesErrorsWhenPathIsMissing(t *testing.T) {
	raw := map[string]any{
		"inbounds": []any{
			map[string]any{
				"tag": "broken-cert",
				"streamSettings": map[string]any{
					"tlsSettings": map[string]any{
						"certificates": []any{
							map[string]any{"certificateFile": "/missing/cert.pem", "key": "inline-key"},
						},
					},
				},
			},
		},
	}

	if err := inlineTLSCertificateFiles(raw); err == nil {
		t.Fatal("expected missing certificate file to fail")
	}
}

func firstRuntimeCertificate(t *testing.T, raw map[string]any) map[string]any {
	t.Helper()
	inbounds := listOfMaps(raw["inbounds"])
	if len(inbounds) != 1 {
		t.Fatalf("expected one inbound, got %#v", inbounds)
	}
	stream := mapValue(inbounds[0]["streamSettings"])
	tlsSettings := mapValue(stream["tlsSettings"])
	certificates := listOfMaps(tlsSettings["certificates"])
	if len(certificates) != 1 {
		t.Fatalf("expected one certificate, got %#v", certificates)
	}
	return certificates[0]
}
