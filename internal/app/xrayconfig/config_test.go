package xrayconfig

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func testConfig() map[string]any {
	return map[string]any{
		"log": map[string]any{"accessCleanupInterval": "3600", "errorCleanupInterval": "bad"},
		"inbounds": []any{
			map[string]any{
				"tag":      "vless-tcp",
				"port":     443,
				"protocol": "vless",
				"settings": map[string]any{"decryption": "none", "encryption": "none"},
				"streamSettings": map[string]any{
					"network":  "tcp",
					"security": "tls",
					"tcpSettings": map[string]any{
						"header": map[string]any{"type": "none"},
					},
					"tlsSettings": map[string]any{
						"serverName":    "example.com",
						"alpn":          []any{"h2", "http/1.1"},
						"allowInsecure": true,
					},
				},
			},
			map[string]any{
				"tag":      "vmess-ws",
				"port":     80,
				"protocol": "vmess",
				"settings": map[string]any{"clients": []any{}},
				"streamSettings": map[string]any{
					"network": "ws",
					"wsSettings": map[string]any{
						"path": "/ws",
						"headers": map[string]any{
							"Host": "legacy.example",
						},
					},
				},
			},
			map[string]any{
				"tag":      "blocked",
				"port":     1234,
				"protocol": "trojan",
			},
		},
		"outbounds": []any{
			map[string]any{"tag": "DIRECT", "protocol": "freedom"},
			map[string]any{"tag": "BLOCK", "protocol": "blackhole"},
		},
	}
}

func TestParseValidConfigResolvesInbounds(t *testing.T) {
	cfg, err := Parse(testConfig(), Options{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	byTag := cfg.InboundsByTag()
	if _, ok := byTag["blocked"]; !ok {
		t.Fatal("manageable inbound was not resolved")
	}
	vless := byTag["vless-tcp"]
	if vless["protocol"] != "vless" || vless["network"] != "tcp" || vless["tls"] != "tls" {
		t.Fatalf("unexpected vless resolution: %#v", vless)
	}
	if got := strings.Join(stringList(vless["sni"]), ","); got == "" {
		t.Fatal("expected sni to be resolved")
	}
	if vless["alpn"] != "h2,http/1.1" {
		t.Fatalf("unexpected alpn = %#v", vless["alpn"])
	}

	byProtocol := cfg.InboundsByProtocol()
	if len(byProtocol["vless"]) != 1 || len(byProtocol["vmess"]) != 1 || len(byProtocol["trojan"]) != 1 {
		t.Fatalf("unexpected protocol grouping: %#v", byProtocol)
	}
}

func TestParseMigratesWebSocketHostAndNormalizesLog(t *testing.T) {
	cfg, err := Parse(testConfig(), Options{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	raw := cfg.Raw()
	logCfg := raw["log"].(map[string]any)
	if logCfg["accessCleanupInterval"].(float64) != 3600 || logCfg["errorCleanupInterval"].(float64) != 0 {
		t.Fatalf("log cleanup not normalized: %#v", logCfg)
	}
	inbounds := raw["inbounds"].([]any)
	ws := inbounds[1].(map[string]any)
	wsSettings := ws["streamSettings"].(map[string]any)["wsSettings"].(map[string]any)
	if wsSettings["host"] != "legacy.example" {
		t.Fatalf("ws host was not migrated: %#v", wsSettings)
	}
	if _, ok := wsSettings["headers"]; ok {
		t.Fatalf("empty ws headers should be removed: %#v", wsSettings)
	}
}

func TestNormalizePayloadRemovesLegacyReverseAndRemovedTLSFields(t *testing.T) {
	cfg := map[string]any{
		"reverse": map[string]any{
			"bridges": []any{map[string]any{"tag": "old-bridge", "domain": "bridge.example"}},
			"portals": []any{map[string]any{"tag": "old-portal", "domain": "portal.example"}},
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"type": "field", "inboundTag": []any{"old-bridge"}, "outboundTag": "direct"},
			map[string]any{"type": "field", "inboundTag": []any{"source"}, "outboundTag": "old-portal"},
			map[string]any{"type": "field", "inboundTag": []any{"source"}, "outboundTag": "direct"},
		}},
		"inbounds": []any{map[string]any{
			"streamSettings": map[string]any{"security": "tls", "tlsSettings": map[string]any{
				"allowInsecure": true,
				"echForceQuery": "half",
			}},
		}},
		"outbounds": []any{map[string]any{
			"streamSettings": map[string]any{"security": "tls", "tlsSettings": map[string]any{
				"allowInsecure":         true,
				"verifyPeerCertInNames": []any{"example.com"},
			}},
		}},
	}

	normalized := NormalizePayload(cfg)
	if _, ok := normalized["reverse"]; ok {
		t.Fatal("legacy reverse config was not removed")
	}
	rules := listOfMaps(mapValue(normalized["routing"])["rules"])
	if len(rules) != 1 || stringValue(rules[0]["outboundTag"]) != "direct" {
		t.Fatalf("legacy reverse routing rules were not removed: %#v", rules)
	}
	inboundTLS := mapValue(mapValue(listOfMaps(normalized["inbounds"])[0]["streamSettings"])["tlsSettings"])
	if _, ok := inboundTLS["allowInsecure"]; ok {
		t.Fatalf("removed TLS field was retained: %#v", inboundTLS)
	}
	if _, ok := inboundTLS["echForceQuery"]; ok {
		t.Fatalf("removed ECH field was retained: %#v", inboundTLS)
	}
	if mapValue(inboundTLS["settings"])["allowInsecure"] != true {
		t.Fatalf("subscription metadata should be preserved: %#v", inboundTLS)
	}
	outboundTLS := mapValue(mapValue(listOfMaps(normalized["outbounds"])[0]["streamSettings"])["tlsSettings"])
	if _, ok := outboundTLS["allowInsecure"]; ok {
		t.Fatalf("removed outbound TLS field was retained: %#v", outboundTLS)
	}
	if outboundTLS["verifyPeerCertByName"] != "example.com" {
		t.Fatalf("certificate name migration failed: %#v", outboundTLS)
	}
	if mapValue(outboundTLS["settings"])["allowInsecure"] != true {
		t.Fatalf("outbound allowInsecure metadata was not preserved: %#v", outboundTLS)
	}
}

func TestParseAcceptsStreamMethod(t *testing.T) {
	cfg := testConfig()
	inbound := cfg["inbounds"].([]any)[0].(map[string]any)
	stream := inbound["streamSettings"].(map[string]any)
	delete(stream, "network")
	stream["method"] = "raw"

	parsed, err := Parse(cfg, Options{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got := parsed.InboundsByTag()["vless-tcp"]["network"]; got != "raw" {
		t.Fatalf("method alias was not resolved: %#v", got)
	}
}

func TestNormalizePayloadForXrayVersionUsesMatchingTransportField(t *testing.T) {
	payload := map[string]any{
		"inbounds": []any{map[string]any{
			"streamSettings": map[string]any{"network": "xhttp"},
		}},
		"outbounds": []any{map[string]any{
			"streamSettings": map[string]any{"method": "raw"},
		}},
	}

	legacy, warning := NormalizePayloadForXrayVersion(payload, "Xray 26.7.10")
	if warning != "" {
		t.Fatalf("legacy version warning = %q", warning)
	}
	legacyInbound := mapValue(listOfMaps(legacy["inbounds"])[0]["streamSettings"])
	legacyOutbound := mapValue(listOfMaps(legacy["outbounds"])[0]["streamSettings"])
	if legacyInbound["network"] != "xhttp" || legacyOutbound["network"] != "raw" {
		t.Fatalf("legacy transport mapping = %#v", legacy)
	}
	if _, exists := legacyOutbound["method"]; exists {
		t.Fatalf("legacy transport retained method: %#v", legacyOutbound)
	}

	modern, warning := NormalizePayloadForXrayVersion(payload, "Xray 26.7.11")
	if warning != "" {
		t.Fatalf("modern version warning = %q", warning)
	}
	modernInbound := mapValue(listOfMaps(modern["inbounds"])[0]["streamSettings"])
	modernOutbound := mapValue(listOfMaps(modern["outbounds"])[0]["streamSettings"])
	if modernInbound["method"] != "xhttp" || modernOutbound["method"] != "raw" {
		t.Fatalf("modern transport mapping = %#v", modern)
	}
	if _, exists := modernInbound["network"]; exists {
		t.Fatalf("modern transport retained network: %#v", modernInbound)
	}

	unknown, warning := NormalizePayloadForXrayVersion(payload, "custom build")
	if !strings.Contains(warning, "unknown or invalid") {
		t.Fatalf("unknown version warning = %q", warning)
	}
	unknownInbound := mapValue(listOfMaps(unknown["inbounds"])[0]["streamSettings"])
	if unknownInbound["network"] != "xhttp" {
		t.Fatalf("unknown version did not preserve legacy transport behavior: %#v", unknownInbound)
	}
}

func TestNormalizePayloadForXrayVersionGatesRemovedAllowInsecure(t *testing.T) {
	payload := NormalizePayload(map[string]any{
		"inbounds": []any{map[string]any{
			"tag": "server", "streamSettings": map[string]any{"security": "tls", "tlsSettings": map[string]any{"allowInsecure": true}},
		}},
		"outbounds": []any{
			map[string]any{
				"tag": "legacy-client", "protocol": "vless",
				"settings": map[string]any{"vnext": []any{map[string]any{"address": "private.example", "users": []any{map[string]any{"encryption": "none"}}}}},
				"streamSettings": map[string]any{"security": "tls", "tlsSettings": map[string]any{
					"allowInsecure": true, "pinnedPeerCertSha256": []any{"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
				}},
			},
			map[string]any{
				"tag": "public-trojan", "protocol": "trojan",
				"settings":       map[string]any{"servers": []any{map[string]any{"address": "public.example.com"}}},
				"streamSettings": map[string]any{"security": "none"},
			},
		},
	})

	for _, tc := range []struct {
		name        string
		version     string
		wantRuntime bool
		wantWarning string
	}{
		{name: "last supported release", version: "Xray 26.1.23", wantRuntime: true},
		{name: "first removed release", version: "Xray 26.1.31", wantWarning: "26.1.31+ removed tlsSettings.allowInsecure"},
		{name: "unknown", version: "custom build", wantWarning: "metadata-only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			normalized, warning := NormalizePayloadForXrayVersion(payload, tc.version)
			inboundTLS := mapValue(mapValue(listOfMaps(normalized["inbounds"])[0]["streamSettings"])["tlsSettings"])
			if _, exists := inboundTLS["allowInsecure"]; exists {
				t.Fatalf("client-only allowInsecure was restored on an inbound: %#v", inboundTLS)
			}
			outboundTLS := mapValue(mapValue(listOfMaps(normalized["outbounds"])[0]["streamSettings"])["tlsSettings"])
			_, runtimeExists := outboundTLS["allowInsecure"]
			if runtimeExists != tc.wantRuntime {
				t.Fatalf("runtime allowInsecure exists=%t want %t: %#v", runtimeExists, tc.wantRuntime, outboundTLS)
			}
			if mapValue(outboundTLS["settings"])["allowInsecure"] != true {
				t.Fatalf("legacy allowInsecure metadata was lost: %#v", outboundTLS)
			}
			if tc.wantWarning == "" {
				if strings.Contains(warning, "allowInsecure") {
					t.Fatalf("legacy Xray received modern warning: %s", warning)
				}
			} else if !strings.Contains(warning, tc.wantWarning) || !strings.Contains(warning, "legacy-client") {
				t.Fatalf("warning mismatch, want %q and tag: %s", tc.wantWarning, warning)
			}
			if tc.version == "Xray 26.1.31" && strings.Contains(warning, "26.7.11+") {
				t.Fatalf("future public-outbound warning leaked below its boundary: %s", warning)
			}
		})
	}

	_, warning := NormalizePayloadForXrayVersion(payload, "Xray 26.7.11")
	for _, expected := range []string{"26.1.31+ removed tlsSettings.allowInsecure", "Official VLESS transport-security guidance", "not covered by Xray's flat-config rejection", "legacy-client", "public-trojan"} {
		if !strings.Contains(warning, expected) {
			t.Fatalf("combined compatibility warning lost %q: %s", expected, warning)
		}
	}
}

func TestNormalizePayloadForXrayVersionWarnsForUnencryptedPublicOutbounds(t *testing.T) {
	payload := map[string]any{
		"outbounds": []any{
			map[string]any{
				"tag":      "public-vless-flat",
				"protocol": "vless",
				"settings": map[string]any{"address": "edge.public.net", "encryption": "none"},
			},
			map[string]any{
				"tag":      "public-vless-nested",
				"protocol": "vless",
				"settings": map[string]any{"vnext": []any{map[string]any{
					"address": "nested.public.net",
					"users":   []any{map[string]any{"encryption": "none"}},
				}}},
			},
			map[string]any{
				"tag":      "public-trojan-nested",
				"protocol": "trojan",
				"settings": map[string]any{"servers": []any{map[string]any{"address": "8.8.8.8"}}},
			},
			map[string]any{
				"tag":      "tls-vless",
				"protocol": "vless",
				"settings": map[string]any{"vnext": []any{map[string]any{
					"address": "tls.public.net",
					"users":   []any{map[string]any{"encryption": "none"}},
				}}},
				"streamSettings": map[string]any{"security": "tls"},
			},
			map[string]any{
				"tag":            "reality-trojan",
				"protocol":       "trojan",
				"settings":       map[string]any{"servers": []any{map[string]any{"address": "reality.public.net"}}},
				"streamSettings": map[string]any{"security": "reality"},
			},
			map[string]any{
				"tag":      "encrypted-vless",
				"protocol": "vless",
				"settings": map[string]any{"vnext": []any{map[string]any{
					"address": "encrypted.public.net",
					"users":   []any{map[string]any{"encryption": "mlkem768x25519plus"}},
				}}},
			},
			map[string]any{
				"tag":      "private-ip",
				"protocol": "vless",
				"settings": map[string]any{"vnext": []any{map[string]any{
					"address": "10.0.0.1",
					"users":   []any{map[string]any{"encryption": "none"}},
				}}},
			},
			map[string]any{
				"tag":      "private-domain",
				"protocol": "trojan",
				"settings": map[string]any{"address": "proxy.internal"},
			},
		},
	}

	_, warning := NormalizePayloadForXrayVersion(payload, "Xray 26.7.10")
	if warning != "" {
		t.Fatalf("below-threshold warning = %q", warning)
	}

	_, warning = NormalizePayloadForXrayVersion(payload, "Xray 26.7.11")
	var rejectWarning, guidanceWarning string
	for _, part := range strings.Split(warning, "; ") {
		switch {
		case strings.Contains(part, "rejects flat unencrypted"):
			rejectWarning = part
		case strings.Contains(part, "Official VLESS transport-security guidance"):
			guidanceWarning = part
		}
	}
	if !strings.Contains(rejectWarning, "public-vless-flat") || strings.Contains(rejectWarning, "public-vless-nested") || strings.Contains(rejectWarning, "public-trojan-nested") {
		t.Fatalf("flat Xray rejection warning has the wrong scope: %q", rejectWarning)
	}
	for _, tag := range []string{"public-vless-nested", "public-trojan-nested"} {
		if !strings.Contains(guidanceWarning, tag) {
			t.Fatalf("official safety-guidance warning does not include %q: %q", tag, guidanceWarning)
		}
	}
	if strings.Contains(guidanceWarning, "Xray 26.7.11+ rejects") || !strings.Contains(guidanceWarning, "preserved without auto-TLS mutation") {
		t.Fatalf("legacy nested warning overstates the core runtime guard: %q", guidanceWarning)
	}
	for _, tag := range []string{"tls-vless", "reality-trojan", "encrypted-vless", "private-ip", "private-domain"} {
		if strings.Contains(warning, tag) {
			t.Fatalf("threshold warning includes exempt outbound %q: %q", tag, warning)
		}
	}

	_, warning = NormalizePayloadForXrayVersion(payload, "custom build")
	if !strings.Contains(warning, "unknown or invalid") || strings.Contains(warning, "public-vless-nested") {
		t.Fatalf("unknown-version warning = %q", warning)
	}
}

func TestNormalizePayloadForXrayVersionGatesVLESSEncryptionWithoutMutation(t *testing.T) {
	const decryption = "mlkem768x25519plus.native.600s.server-key"
	const encryption = "mlkem768x25519plus.native.0rtt.client-key"
	payload := map[string]any{
		"inbounds": []any{map[string]any{
			"tag": "encrypted-in", "protocol": "vless",
			"settings": map[string]any{"decryption": decryption, "encryption": encryption},
		}},
		"outbounds": []any{map[string]any{
			"tag": "encrypted-out", "protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": "example.com", "users": []any{map[string]any{"encryption": encryption}},
			}}},
		}},
	}

	for _, tc := range []struct {
		version     string
		wantWarning string
	}{
		{version: "Xray 26.3.27", wantWarning: "Xray before 26.5.9 does not accept VLESS Encryption"},
		{version: "Xray 26.5.9"},
		{version: "custom build", wantWarning: "VLESS Encryption support starts at 26.5.9"},
	} {
		normalized, warning := NormalizePayloadForXrayVersion(payload, tc.version)
		inboundSettings := mapValue(listOfMaps(normalized["inbounds"])[0]["settings"])
		outboundUser := listOfMaps(listOfMaps(mapValue(listOfMaps(normalized["outbounds"])[0]["settings"])["vnext"])[0]["users"])[0]
		if inboundSettings["decryption"] != decryption || inboundSettings["encryption"] != encryption || outboundUser["encryption"] != encryption {
			t.Fatalf("VLESS Encryption settings were mutated for %s: %#v %#v", tc.version, inboundSettings, outboundUser)
		}
		if tc.wantWarning == "" {
			if strings.Contains(warning, "VLESS Encryption") {
				t.Fatalf("supported VLESS Encryption boundary warned: %s", warning)
			}
		} else if !strings.Contains(warning, tc.wantWarning) || !strings.Contains(warning, "encrypted-in") || !strings.Contains(warning, "encrypted-out") {
			t.Fatalf("VLESS Encryption warning mismatch for %s: %s", tc.version, warning)
		}
	}
}

func TestNormalizePayloadForXrayVersionGatesVLESSInboundDefaultFlow(t *testing.T) {
	payload := map[string]any{
		"inbounds": []any{map[string]any{
			"tag": "default-flow", "protocol": "vless",
			"settings": map[string]any{"flow": "xtls-rprx-vision"},
		}},
		"outbounds": []any{map[string]any{
			"tag": "client-flow", "protocol": "vless",
			"settings": map[string]any{"flow": "xtls-rprx-vision"},
		}},
	}

	for _, tc := range []struct {
		version     string
		wantWarning string
	}{
		{version: "Xray 25.8.28", wantWarning: "before 25.8.29"},
		{version: "Xray 25.8.29"},
		{version: "custom build", wantWarning: "support starts at 25.8.29"},
	} {
		normalized, warning := NormalizePayloadForXrayVersion(payload, tc.version)
		settings := mapValue(listOfMaps(normalized["inbounds"])[0]["settings"])
		if settings["flow"] != "xtls-rprx-vision" {
			t.Fatalf("default flow was mutated for %s: %#v", tc.version, settings)
		}
		if tc.wantWarning == "" {
			if strings.Contains(warning, "default flow") {
				t.Fatalf("supported default-flow boundary warned: %s", warning)
			}
		} else if !strings.Contains(warning, tc.wantWarning) || !strings.Contains(warning, "default-flow") {
			t.Fatalf("default-flow warning mismatch for %s: %s", tc.version, warning)
		}
		if strings.Contains(warning, "client-flow") {
			t.Fatalf("outbound flow was incorrectly version-gated: %s", warning)
		}
	}
}

func TestValidateVLESSInboundDefaultFlow(t *testing.T) {
	const encryption = "mlkem768x25519plus.native.600s.server-key"
	for _, tc := range []struct {
		name       string
		flow       string
		decryption string
		encryption string
		network    string
		security   string
		wantErr    string
	}{
		{name: "TLS vision", flow: "xtls-rprx-vision", decryption: "none", network: "tcp", security: "tls"},
		{name: "server encryption", flow: "xtls-rprx-vision", decryption: encryption, network: "xhttp", security: "none"},
		{name: "outbound-only enum", flow: "xtls-rprx-vision-udp443", decryption: "none", network: "tcp", security: "tls", wantErr: "must be xtls-rprx-vision"},
		{name: "client encryption is not server encryption", flow: "xtls-rprx-vision", decryption: "none", encryption: encryption, network: "xhttp", security: "none", wantErr: "requires TCP with TLS/REALITY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			inbound := cfg["inbounds"].([]any)[0].(map[string]any)
			inbound["settings"] = map[string]any{
				"flow": tc.flow, "decryption": tc.decryption, "encryption": tc.encryption,
			}
			inbound["streamSettings"] = map[string]any{
				"network": tc.network, "security": tc.security,
			}
			if tc.network == "tcp" {
				inbound["streamSettings"].(map[string]any)["tcpSettings"] = map[string]any{
					"header": map[string]any{"type": "none"},
				}
			}

			_, err := Parse(cfg, Options{})
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Parse() error = %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Parse() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestNormalizePayloadForXrayVersionUsesMatchingXHTTPSessionFields(t *testing.T) {
	payload := map[string]any{
		"inbounds": []any{map[string]any{
			"streamSettings": map[string]any{
				"network": "xhttp",
				"xhttpSettings": map[string]any{
					"sessionIDPlacement": "header",
					"sessionIDKey":       "X-Session",
					"sessionIDTable":     "0123456789abcdef",
					"sessionIDLength":    12,
					"futureOption":       "preserve-me",
				},
			},
		}},
		"outbounds": []any{map[string]any{
			"streamSettings": map[string]any{
				"network": "splithttp",
				"splithttpSettings": map[string]any{
					"sessionPlacement": "query",
					"sessionKey":       "x_session",
					"sessionTable":     "fedcba9876543210",
					"sessionLength":    16,
				},
			},
		}},
	}

	for _, tc := range []struct {
		name        string
		version     string
		currentKeys bool
		bothAliases bool
		wantWarning bool
	}{
		{name: "below threshold", version: "26.6.21"},
		{name: "at threshold", version: "26.6.22", currentKeys: true},
		{name: "above threshold", version: "26.6.23", currentKeys: true},
		{name: "unknown", bothAliases: true, wantWarning: true},
		{name: "invalid", version: "not-a-version", bothAliases: true, wantWarning: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			normalized, warning := NormalizePayloadForXrayVersion(payload, tc.version)
			if (warning != "") != tc.wantWarning {
				t.Fatalf("warning = %q", warning)
			}
			inbound := mapValue(mapValue(listOfMaps(normalized["inbounds"])[0]["streamSettings"])["xhttpSettings"])
			outbound := mapValue(mapValue(listOfMaps(normalized["outbounds"])[0]["streamSettings"])["splithttpSettings"])
			assertXHTTPSessionAliases(t, inbound, "header", "X-Session", "0123456789abcdef", 12, tc.currentKeys, tc.bothAliases)
			assertXHTTPSessionAliases(t, outbound, "query", "x_session", "fedcba9876543210", 16, tc.currentKeys, tc.bothAliases)
			if inbound["futureOption"] != "preserve-me" {
				t.Fatalf("unknown XHTTP field was lost: %#v", inbound)
			}
		})
	}

	originalInbound := mapValue(mapValue(listOfMaps(payload["inbounds"])[0]["streamSettings"])["xhttpSettings"])
	if _, exists := originalInbound["sessionPlacement"]; exists {
		t.Fatalf("normalization mutated persisted payload: %#v", originalInbound)
	}
}

func TestNormalizePayloadForXrayVersionGatesHysteria2WithoutGuessingLegacySemantics(t *testing.T) {
	compatible := func(version any) map[string]any {
		settings := map[string]any{"clients": []any{map[string]any{"password": "secret"}}}
		hysteria := map[string]any{"udpIdleTimeout": 60}
		if version != nil {
			settings["version"] = version
			hysteria["version"] = version
		}
		return map[string]any{
			"tag": "hy", "protocol": "hysteria", "settings": settings,
			"streamSettings": map[string]any{
				"network": "hysteria", "security": "tls", "hysteriaSettings": hysteria,
			},
		}
	}
	tests := []struct {
		name        string
		version     string
		shape       map[string]any
		wantVersion int
		warning     string
	}{
		{name: "boundary below stable support", version: "Xray 26.3.26", shape: compatible(nil), wantVersion: 0, warning: "before 26.3.27"},
		{name: "stable support boundary", version: "Xray 26.3.27", shape: compatible(nil), wantVersion: 2, warning: "Normalized compatible Hysteria"},
		{name: "current supported", version: "Xray 26.7.28", shape: compatible(nil), wantVersion: 2, warning: "Normalized compatible Hysteria"},
		{name: "explicit legacy semantics", version: "Xray 26.7.28", shape: compatible(1), wantVersion: 1, warning: "not safely recognizable"},
		{name: "unknown version", version: "custom build", shape: compatible(nil), wantVersion: 0, warning: "preserving Hysteria settings"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{"inbounds": []any{tc.shape}}
			normalized, warning := NormalizePayloadForXrayVersion(payload, tc.version)
			inbound := listOfMaps(normalized["inbounds"])[0]
			settings := mapValue(inbound["settings"])
			streamVersion := intValue(mapValue(mapValue(inbound["streamSettings"])["hysteriaSettings"])["version"])
			if got := intValue(settings["version"]); got != tc.wantVersion || streamVersion != tc.wantVersion {
				t.Fatalf("versions settings=%d stream=%d want=%d normalized=%#v", got, streamVersion, tc.wantVersion, normalized)
			}
			if !strings.Contains(warning, tc.warning) {
				t.Fatalf("warning %q does not contain %q", warning, tc.warning)
			}
			original := tc.shape
			if got := intValue(mapValue(original["settings"])["version"]); got != 0 && tc.wantVersion == 2 {
				t.Fatalf("original settings were mutated: %#v", original)
			}
		})
	}
}

func TestNormalizePayloadForXrayVersionUsesEarlierHysteriaOutboundBoundary(t *testing.T) {
	outbound := map[string]any{
		"tag": "hy-out", "protocol": "hysteria",
		"settings": map[string]any{"address": "example.com", "port": 443},
		"streamSettings": map[string]any{
			"network": "hysteria", "security": "tls", "hysteriaSettings": map[string]any{"udpIdleTimeout": 60},
		},
	}
	normalized, warning := NormalizePayloadForXrayVersion(map[string]any{"outbounds": []any{outbound}}, "Xray 26.1.23")
	got := listOfMaps(normalized["outbounds"])[0]
	if intValue(mapValue(got["settings"])["version"]) != 2 || intValue(mapValue(mapValue(got["streamSettings"])["hysteriaSettings"])["version"]) != 2 {
		t.Fatalf("pre-26.3.27 Hysteria outbound was not normalized to required version 2: %#v", got)
	}
	if !strings.Contains(warning, "Hysteria outbound") {
		t.Fatalf("outbound normalization warning missing: %s", warning)
	}
	inbound := deepCopyMap(outbound)
	inbound["settings"] = map[string]any{"clients": []any{}}
	normalized, warning = NormalizePayloadForXrayVersion(map[string]any{"inbounds": []any{inbound}}, "Xray 26.1.23")
	got = listOfMaps(normalized["inbounds"])[0]
	if intValue(mapValue(got["settings"])["version"]) != 0 || !strings.Contains(warning, "before 26.3.27") {
		t.Fatalf("pre-26.3.27 Hysteria inbound should remain untouched with warning: %#v warning=%s", got, warning)
	}
}

func TestNormalizePayloadForXrayVersionGatesTLSPinAndPeerNameSyntax(t *testing.T) {
	const pin = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	colonPin := strings.Join([]string{
		"fe", "dc", "ba", "98", "76", "54", "32", "10",
		"fe", "dc", "ba", "98", "76", "54", "32", "10",
		"fe", "dc", "ba", "98", "76", "54", "32", "10",
		"fe", "dc", "ba", "98", "76", "54", "32", "10",
	}, ":")
	payload := NormalizePayload(map[string]any{
		"outbounds": []any{map[string]any{
			"tag": "tls-client", "protocol": "vless",
			"streamSettings": map[string]any{"security": "tls", "tlsSettings": map[string]any{
				"allowInsecure":         true,
				"pinnedPeerCertSha256":  colonPin + "~" + pin,
				"verifyPeerCertInNames": []any{"one.example", "two.example"},
			}},
		}},
	})

	legacy, warning := NormalizePayloadForXrayVersion(payload, "Xray 26.1.23")
	if strings.Contains(warning, "Malformed") {
		t.Fatalf("valid legacy pins were rejected: %s", warning)
	}
	legacyTLS := mapValue(mapValue(listOfMaps(legacy["outbounds"])[0]["streamSettings"])["tlsSettings"])
	wantLegacyPin := strings.ReplaceAll(colonPin, ":", "") + "~" + pin
	if legacyTLS["pinnedPeerCertSha256"] != wantLegacyPin || legacyTLS["allowInsecure"] != true {
		t.Fatalf("legacy TLS syntax mismatch: %#v", legacyTLS)
	}
	if got := stringList(legacyTLS["verifyPeerCertInNames"]); len(got) != 2 || got[0] != "one.example" || got[1] != "two.example" {
		t.Fatalf("legacy peer-name array mismatch: %#v", legacyTLS)
	}
	if _, exists := legacyTLS["verifyPeerCertByName"]; exists {
		t.Fatalf("legacy runtime emitted modern peer-name field: %#v", legacyTLS)
	}

	modern, warning := NormalizePayloadForXrayVersion(payload, "Xray 26.1.31")
	if !strings.Contains(warning, "removed tlsSettings.allowInsecure") {
		t.Fatalf("modern allowInsecure warning missing: %s", warning)
	}
	modernTLS := mapValue(mapValue(listOfMaps(modern["outbounds"])[0]["streamSettings"])["tlsSettings"])
	if modernTLS["pinnedPeerCertSha256"] != colonPin+","+pin || modernTLS["verifyPeerCertByName"] != "one.example,two.example" {
		t.Fatalf("modern TLS syntax mismatch: %#v", modernTLS)
	}
	if _, exists := modernTLS["allowInsecure"]; exists {
		t.Fatalf("modern runtime restored removed allowInsecure: %#v", modernTLS)
	}
	if _, exists := modernTLS["verifyPeerCertInNames"]; exists {
		t.Fatalf("modern runtime emitted removed peer-name field: %#v", modernTLS)
	}

	unknown, warning := NormalizePayloadForXrayVersion(payload, "custom build")
	unknownTLS := mapValue(mapValue(listOfMaps(unknown["outbounds"])[0]["streamSettings"])["tlsSettings"])
	if unknownTLS["pinnedPeerCertSha256"] != colonPin+"~"+pin || unknownTLS["verifyPeerCertByName"] != "one.example,two.example" {
		t.Fatalf("unknown runtime did not preserve canonical metadata conservatively: %#v", unknownTLS)
	}
	if _, exists := unknownTLS["verifyPeerCertInNames"]; exists || !strings.Contains(warning, "mutually incompatible aliases") {
		t.Fatalf("unknown TLS alias handling mismatch: %#v warning=%s", unknownTLS, warning)
	}
}

func TestNormalizePayloadForXrayVersionMigratesLegacyMKCPWithoutLoss(t *testing.T) {
	payload := map[string]any{"outbounds": []any{map[string]any{
		"tag": "kcp-out", "protocol": "vless",
		"streamSettings": map[string]any{
			"network": "kcp",
			"kcpSettings": map[string]any{
				"mtu": 1350, "tti": 20, "seed": "seed-value",
				"header": map[string]any{"type": "dns", "domain": "dns.example"},
			},
			"finalmask": map[string]any{"udp": []any{map[string]any{"type": "noise", "settings": map[string]any{"packet": "x"}}}},
		},
	}}}

	legacy, warning := NormalizePayloadForXrayVersion(payload, "Xray 26.1.23")
	legacyStream := mapValue(listOfMaps(legacy["outbounds"])[0]["streamSettings"])
	if mapValue(legacyStream["kcpSettings"])["seed"] != "seed-value" || strings.Contains(warning, "Moved legacy mKCP") {
		t.Fatalf("old core did not retain legacy mKCP fields: %#v warning=%s", legacyStream, warning)
	}

	stable, warning := NormalizePayloadForXrayVersion(payload, "Xray 26.1.31")
	stableStream := mapValue(listOfMaps(stable["outbounds"])[0]["streamSettings"])
	stableKCP := mapValue(stableStream["kcpSettings"])
	if _, exists := stableKCP["seed"]; exists {
		t.Fatalf("new core retained removed mKCP seed: %#v", stableKCP)
	}
	udp := stableStream["finalmask"].(map[string]any)["udp"].([]any)
	if len(udp) != 3 || mapValue(udp[0])["type"] != "mkcp-aes128gcm" || mapValue(udp[1])["type"] != "header-dns" || mapValue(udp[2])["type"] != "noise" {
		t.Fatalf("v26.1.31 FinalMask order/shape mismatch: %#v", udp)
	}
	if mapValue(mapValue(udp[0])["settings"])["password"] != "seed-value" || mapValue(mapValue(udp[1])["settings"])["domain"] != "dns.example" || !strings.Contains(warning, "Moved legacy mKCP") {
		t.Fatalf("v26.1.31 mKCP semantics were lost: %#v warning=%s", udp, warning)
	}

	prerelease, _ := NormalizePayloadForXrayVersion(payload, "Xray 26.6.1")
	preStream := mapValue(listOfMaps(prerelease["outbounds"])[0]["streamSettings"])
	udp = preStream["finalmask"].(map[string]any)["udp"].([]any)
	if mapValue(udp[0])["type"] != "mkcp-legacy" || mapValue(mapValue(udp[0])["settings"])["value"] != "seed-value" || mapValue(mapValue(udp[1])["settings"])["header"] != "dns" {
		t.Fatalf("v26.6.1 mkcp-legacy shape mismatch: %#v", udp)
	}

	unknown, warning := NormalizePayloadForXrayVersion(payload, "custom build")
	unknownKCP := mapValue(mapValue(listOfMaps(unknown["outbounds"])[0]["streamSettings"])["kcpSettings"])
	if unknownKCP["seed"] != "seed-value" || !strings.Contains(warning, "version-sensitive legacy mKCP") {
		t.Fatalf("unknown core did not preserve mKCP fields: %#v warning=%s", unknownKCP, warning)
	}
}

func TestNormalizePayloadForXrayVersionKeepsRequiredUDPOuterMaskFirst(t *testing.T) {
	for _, outerType := range []string{"realm", "xicmp"} {
		t.Run(outerType, func(t *testing.T) {
			payload := map[string]any{"outbounds": []any{map[string]any{
				"tag": "kcp-out", "protocol": "vless",
				"streamSettings": map[string]any{
					"network": "kcp",
					"kcpSettings": map[string]any{
						"seed": "seed-value", "header": map[string]any{"type": "dns", "domain": "dns.example"},
					},
					"finalmask": map[string]any{"udp": []any{
						map[string]any{"type": outerType},
						map[string]any{"type": "noise"},
						map[string]any{"type": "sudoku"},
					}},
				},
			}}}

			normalized, _ := NormalizePayloadForXrayVersion(payload, "Xray 26.6.22")
			stream := mapValue(listOfMaps(normalized["outbounds"])[0]["streamSettings"])
			udp := listOfMaps(mapValue(stream["finalmask"])["udp"])
			want := []string{outerType, "mkcp-legacy", "mkcp-legacy", "noise", "sudoku"}
			if len(udp) != len(want) {
				t.Fatalf("UDP masks = %#v, want %#v", udp, want)
			}
			for index, maskType := range want {
				if stringValue(udp[index]["type"]) != maskType {
					t.Fatalf("UDP order = %#v, want %#v", udp, want)
				}
			}
			kcpSettings := mapValue(stream["kcpSettings"])
			_, hasHeader := kcpSettings["header"]
			_, hasSeed := kcpSettings["seed"]
			if hasHeader || hasSeed {
				t.Fatalf("legacy KCP fields were retained: %#v", stream["kcpSettings"])
			}
			originalStream := mapValue(listOfMaps(payload["outbounds"])[0]["streamSettings"])
			if mapValue(originalStream["kcpSettings"])["seed"] != "seed-value" {
				t.Fatalf("input payload was mutated: %#v", originalStream)
			}
		})
	}
}

func TestNormalizePayloadForXrayVersionWarnsForRemovedHTTPAndQUICTransports(t *testing.T) {
	payload := map[string]any{"inbounds": []any{
		map[string]any{"tag": "legacy-h2", "streamSettings": map[string]any{"network": "h2"}},
		map[string]any{"tag": "legacy-quic", "streamSettings": map[string]any{"network": "quic", "quicSettings": map[string]any{"security": "aes-128-gcm", "key": "secret"}}},
	}}
	if _, warning := NormalizePayloadForXrayVersion(payload, "Xray 26.1.23"); strings.Contains(warning, "removed HTTP/H2/H3") {
		t.Fatalf("removed transport warning leaked below boundary: %s", warning)
	}
	if _, warning := NormalizePayloadForXrayVersion(payload, "Xray 26.1.31"); !strings.Contains(warning, "legacy-h2") || !strings.Contains(warning, "legacy-quic") || !strings.Contains(warning, "review QUIC") {
		t.Fatalf("removed transport warning incomplete: %s", warning)
	}
	if _, warning := NormalizePayloadForXrayVersion(payload, "custom build"); !strings.Contains(warning, "were preserved without a lossy migration") {
		t.Fatalf("unknown transport warning missing: %s", warning)
	}
}

func TestParseValidatesMKCPMTUAndTTIBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name string
		mtu  any
		tti  int
		ok   bool
	}{
		{name: "canonical minimum", mtu: 21, tti: 10, ok: true},
		{name: "modern below legacy", mtu: 575, tti: 20, ok: true},
		{name: "minimum", mtu: 576, tti: 10, ok: true},
		{name: "legacy maximum", mtu: 1460, tti: 100, ok: true},
		{name: "modern above legacy", mtu: 1500, tti: 20, ok: true},
		{name: "uint32 maximum", mtu: "4294967295", tti: 20, ok: true},
		{name: "current above legacy", mtu: 1350, tti: 101, ok: true},
		{name: "canonical maximum", mtu: 1350, tti: 5000, ok: true},
		{name: "mtu below canonical", mtu: 20, tti: 20},
		{name: "mtu above uint32", mtu: "4294967296", tti: 20},
		{name: "tti below", mtu: 1350, tti: 9},
		{name: "tti above canonical", mtu: 1350, tti: 5001},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := testConfig()
			stream := mapValue(listOfMaps(payload["inbounds"])[0]["streamSettings"])
			stream["network"] = "kcp"
			stream["security"] = "none"
			delete(stream, "tcpSettings")
			stream["kcpSettings"] = map[string]any{"mtu": tc.mtu, "tti": tc.tti}
			_, err := Parse(payload, Options{})
			if (err == nil) != tc.ok {
				t.Fatalf("Parse() error=%v ok=%t", err, tc.ok)
			}
		})
	}
}

func TestNormalizePayloadForXrayVersionWarnsForLegacyMKCPMTUWithoutClamping(t *testing.T) {
	for _, tc := range []struct {
		name        string
		version     string
		mtu         int
		wantWarning bool
	}{
		{name: "legacy compatible", version: "26.1.23", mtu: 1460},
		{name: "legacy below range", version: "26.1.23", mtu: 575, wantWarning: true},
		{name: "legacy above range", version: "26.1.23", mtu: 1500, wantWarning: true},
		{name: "first relaxed release", version: "26.1.31", mtu: 1500},
		{name: "stable relaxed", version: "26.3.27", mtu: 1500},
		{name: "unknown compatible", version: "custom", mtu: 1350},
		{name: "unknown version-sensitive", version: "custom", mtu: 1500, wantWarning: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{"outbounds": []any{map[string]any{
				"tag": "kcp-out", "streamSettings": map[string]any{
					"network": "kcp", "kcpSettings": map[string]any{"mtu": tc.mtu},
				},
			}}}
			normalized, warning := NormalizePayloadForXrayVersion(payload, tc.version)
			got := intValue(mapValue(mapValue(listOfMaps(normalized["outbounds"])[0]["streamSettings"])["kcpSettings"])["mtu"])
			if got != tc.mtu {
				t.Fatalf("mtu was mutated: got=%d want=%d", got, tc.mtu)
			}
			if strings.Contains(warning, "mKCP mtu") != tc.wantWarning {
				t.Fatalf("warning=%q wantWarning=%t", warning, tc.wantWarning)
			}
		})
	}
}

func TestNormalizePayloadForXrayVersionUsesVersionedMKCPTTIMaximum(t *testing.T) {
	for _, tc := range []struct {
		name        string
		version     string
		tti         int
		wantWarning bool
	}{
		{name: "legacy maximum", version: "26.2.6", tti: 100},
		{name: "legacy over maximum", version: "26.2.6", tti: 101, wantWarning: true},
		{name: "expanded first tag", version: "26.3.23", tti: 5000},
		{name: "expanded stable", version: "26.3.27", tti: 5000},
		{name: "narrowed first tag maximum", version: "26.4.13", tti: 1000},
		{name: "narrowed first tag over maximum", version: "26.4.13", tti: 1001, wantWarning: true},
		{name: "latest prerelease over maximum", version: "26.7.28", tti: 5000, wantWarning: true},
		{name: "unknown conservative maximum", version: "custom", tti: 100},
		{name: "unknown version-sensitive", version: "custom", tti: 101, wantWarning: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]any{"outbounds": []any{map[string]any{
				"tag": "kcp-out", "streamSettings": map[string]any{
					"network": "kcp", "kcpSettings": map[string]any{"tti": tc.tti},
				},
			}}}
			normalized, warning := NormalizePayloadForXrayVersion(payload, tc.version)
			got := intValue(mapValue(mapValue(listOfMaps(normalized["outbounds"])[0]["streamSettings"])["kcpSettings"])["tti"])
			if got != tc.tti {
				t.Fatalf("tti was mutated: got=%d want=%d", got, tc.tti)
			}
			if strings.Contains(warning, "mKCP tti") != tc.wantWarning {
				t.Fatalf("warning=%q wantWarning=%t", warning, tc.wantWarning)
			}
		})
	}
}

func TestNormalizePayloadForXrayVersionUsesFragmentAliases(t *testing.T) {
	payload := map[string]any{"outbounds": []any{map[string]any{
		"tag": "fragment-out", "streamSettings": map[string]any{
			"network": "raw", "finalmask": map[string]any{"tcp": []any{map[string]any{
				"type": "fragment", "settings": map[string]any{
					"packets": "tlshello", "lengths": []any{"1-2"}, "delays": []any{"0-1"},
				},
			}}},
		},
	}}}

	legacy, warning := NormalizePayloadForXrayVersion(payload, "26.6.1")
	legacySettings := fragmentSettingsFromPayload(t, legacy)
	if legacySettings["length"] != "1-2" || legacySettings["delay"] != "0-1" || legacySettings["lengths"] != nil || legacySettings["delays"] != nil || !strings.Contains(warning, "Normalized FinalMask") {
		t.Fatalf("legacy fragment aliases mismatch: %#v warning=%s", legacySettings, warning)
	}

	modern, _ := NormalizePayloadForXrayVersion(legacy, "26.6.22")
	modernSettings := fragmentSettingsFromPayload(t, modern)
	if got := stringList(modernSettings["lengths"]); len(got) != 1 || got[0] != "1-2" || modernSettings["length"] != nil {
		t.Fatalf("modern fragment aliases mismatch: %#v", modernSettings)
	}

	multi := deepCopyMap(payload)
	fragmentSettingsFromPayload(t, multi)["lengths"] = []any{"1-2", "3-4"}
	preserved, warning := NormalizePayloadForXrayVersion(multi, "26.6.1")
	if got := stringList(fragmentSettingsFromPayload(t, preserved)["lengths"]); len(got) != 2 || !strings.Contains(warning, "cannot be represented losslessly") {
		t.Fatalf("multi-range fragment was not preserved visibly: %#v warning=%s", got, warning)
	}

	unknown, warning := NormalizePayloadForXrayVersion(payload, "custom")
	if got := stringList(fragmentSettingsFromPayload(t, unknown)["lengths"]); len(got) != 1 || !strings.Contains(warning, "version-sensitive FinalMask") {
		t.Fatalf("unknown fragment syntax mismatch: %#v warning=%s", got, warning)
	}
}

func TestFragmentFinalMaskNormalizationIsAtomicOnIncompatibleMasks(t *testing.T) {
	stream := map[string]any{"finalmask": map[string]any{"tcp": []any{
		map[string]any{"type": "fragment", "settings": map[string]any{"lengths": []any{"1-2"}, "delays": []any{"0-1"}}},
		map[string]any{"type": "fragment", "settings": map[string]any{"lengths": []any{"3-4", "5-6"}, "delays": []any{"2-3"}}},
	}}}
	before, err := json.Marshal(stream)
	if err != nil {
		t.Fatal(err)
	}
	if got := normalizeFragmentFinalMaskForXrayVersion(stream, false, true); got != fragmentIncompatible {
		t.Fatalf("normalization status=%v want fragmentIncompatible", got)
	}
	after, err := json.Marshal(stream)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatalf("incompatible FinalMask was partially mutated:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestNormalizePayloadForXrayVersionWarnsForHysteriaGeckoBoundary(t *testing.T) {
	payload := map[string]any{"outbounds": []any{map[string]any{
		"tag": "gecko-out", "protocol": "hysteria",
		"settings": map[string]any{"address": "example.com", "port": 443, "version": 2},
		"streamSettings": map[string]any{
			"network": "hysteria", "security": "tls", "hysteriaSettings": map[string]any{"version": 2},
			"finalmask": map[string]any{"udp": []any{map[string]any{
				"type": "salamander", "settings": map[string]any{"password": "mask", "packetSize": "512-1200"},
			}}},
		},
	}}}
	if _, warning := NormalizePayloadForXrayVersion(payload, "26.3.27"); !strings.Contains(warning, "before 26.6.1") || !strings.Contains(warning, "gecko-out") {
		t.Fatalf("old-node Gecko warning missing: %s", warning)
	}
	if _, warning := NormalizePayloadForXrayVersion(payload, "26.6.1"); strings.Contains(warning, "Gecko FinalMask") {
		t.Fatalf("Gecko warning leaked at supported boundary: %s", warning)
	}
	if _, warning := NormalizePayloadForXrayVersion(payload, "custom"); !strings.Contains(warning, "Gecko FinalMask support starts") {
		t.Fatalf("unknown-node Gecko warning missing: %s", warning)
	}
}

func fragmentSettingsFromPayload(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()
	stream := mapValue(listOfMaps(payload["outbounds"])[0]["streamSettings"])
	mask := listOfMaps(mapValue(stream["finalmask"])["tcp"])[0]
	return mapValue(mask["settings"])
}

func TestNormalizePayloadForXrayVersionAggregatesHysteriaAndVLESSWarnings(t *testing.T) {
	payload := map[string]any{
		"inbounds": []any{map[string]any{
			"tag": "hy", "protocol": "hysteria", "settings": map[string]any{"clients": []any{}},
			"streamSettings": map[string]any{
				"network": "hysteria", "security": "tls", "hysteriaSettings": map[string]any{"udpIdleTimeout": 60},
			},
		}},
		"outbounds": []any{map[string]any{
			"tag": "public-vless", "protocol": "vless",
			"settings": map[string]any{"vnext": []any{map[string]any{
				"address": "example.com", "users": []any{map[string]any{"encryption": "none"}},
			}}},
			"streamSettings": map[string]any{"network": "raw", "security": "none"},
		}},
	}
	_, warning := NormalizePayloadForXrayVersion(payload, "Xray 26.7.11")
	for _, expected := range []string{"Normalized compatible Hysteria", "Official VLESS transport-security guidance", "not covered by Xray's flat-config rejection", "public-vless"} {
		if !strings.Contains(warning, expected) {
			t.Fatalf("aggregated warning lost %q: %s", expected, warning)
		}
	}
}

func TestParseValidatesXHTTPSessionIDEntropy(t *testing.T) {
	for _, tc := range []struct {
		name   string
		table  string
		length any
		ok     bool
	}{
		{name: "legacy fields absent", ok: true},
		{name: "predefined Base62", table: "Base62", length: "16-32", ok: true},
		{name: "custom ASCII", table: "abcdef0123456789", length: 8, ok: true},
		{name: "non ASCII", table: "abc✓", length: 16},
		{name: "zero range", table: "Base62", length: "0-16"},
		{name: "too small", table: "ab", length: 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := testConfig()
			stream := mapValue(listOfMaps(payload["inbounds"])[0]["streamSettings"])
			stream["network"] = "xhttp"
			delete(stream, "tcpSettings")
			settings := map[string]any{"path": "/x"}
			if tc.table != "" {
				settings["sessionIDTable"] = tc.table
				settings["sessionIDLength"] = tc.length
			}
			stream["xhttpSettings"] = settings
			_, err := Parse(payload, Options{})
			if (err == nil) != tc.ok {
				t.Fatalf("Parse() error=%v ok=%t settings=%#v", err, tc.ok, settings)
			}
		})
	}
}

func assertXHTTPSessionAliases(t *testing.T, settings map[string]any, wantPlacement, wantKey, wantTable string, wantLength int, currentKeys, bothAliases bool) {
	t.Helper()
	wantCurrent := currentKeys || bothAliases
	wantLegacy := !currentKeys || bothAliases
	if got, exists := settings["sessionIDPlacement"]; exists != wantCurrent || (exists && got != wantPlacement) {
		t.Fatalf("current placement = %#v, exists=%t, settings=%#v", got, exists, settings)
	}
	if got, exists := settings["sessionIDKey"]; exists != wantCurrent || (exists && got != wantKey) {
		t.Fatalf("current key = %#v, exists=%t, settings=%#v", got, exists, settings)
	}
	if got, exists := settings["sessionPlacement"]; exists != wantLegacy || (exists && got != wantPlacement) {
		t.Fatalf("legacy placement = %#v, exists=%t, settings=%#v", got, exists, settings)
	}
	if got, exists := settings["sessionKey"]; exists != wantLegacy || (exists && got != wantKey) {
		t.Fatalf("legacy key = %#v, exists=%t, settings=%#v", got, exists, settings)
	}
	if got, exists := settings["sessionIDTable"]; exists != wantCurrent || (exists && got != wantTable) {
		t.Fatalf("current table = %#v, exists=%t, settings=%#v", got, exists, settings)
	}
	if got, exists := settings["sessionIDLength"]; exists != wantCurrent || (exists && intValue(got) != wantLength) {
		t.Fatalf("current length = %#v, exists=%t, settings=%#v", got, exists, settings)
	}
	if got, exists := settings["sessionTable"]; exists != wantLegacy || (exists && got != wantTable) {
		t.Fatalf("legacy table = %#v, exists=%t, settings=%#v", got, exists, settings)
	}
	if got, exists := settings["sessionLength"]; exists != wantLegacy || (exists && intValue(got) != wantLength) {
		t.Fatalf("legacy length = %#v, exists=%t, settings=%#v", got, exists, settings)
	}
}

func TestReverseClientsKeepsOnlyStaticReverseAccounts(t *testing.T) {
	clients := []any{
		map[string]any{"id": "regular"},
		map[string]any{"id": "reverse", "reverse": map[string]any{"tag": "reverse-in"}},
	}
	kept := ReverseClients(clients)
	if len(kept) != 1 || stringValue(kept[0].(map[string]any)["id"]) != "reverse" {
		t.Fatalf("unexpected reverse clients: %#v", kept)
	}
	kept[0].(map[string]any)["id"] = "changed"
	if clients[1].(map[string]any)["id"] != "reverse" {
		t.Fatal("ReverseClients mutated the source config")
	}
}

func TestInvalidConfig(t *testing.T) {
	cases := []struct {
		name string
		cfg  map[string]any
	}{
		{name: "missing inbounds", cfg: map[string]any{"outbounds": []any{map[string]any{"tag": "DIRECT"}}}},
		{name: "missing outbounds", cfg: map[string]any{"inbounds": []any{map[string]any{"tag": "in", "protocol": "vless"}}}},
		{name: "comma tag", cfg: map[string]any{
			"inbounds":  []any{map[string]any{"tag": "bad,tag", "protocol": "vless"}},
			"outbounds": []any{map[string]any{"tag": "DIRECT"}},
		}},
		{name: "duplicate inbound", cfg: map[string]any{
			"inbounds": []any{
				map[string]any{"tag": "same", "protocol": "vless"},
				map[string]any{"tag": "same", "protocol": "vmess"},
			},
			"outbounds": []any{map[string]any{"tag": "DIRECT"}},
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.cfg, Options{}); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestRuntimeInjectionDoesNotMutateRawConfig(t *testing.T) {
	cfg, err := Parse(testConfig(), Options{APIHost: "127.0.0.2", APIPort: 9090})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	raw := cfg.Raw()
	if _, ok := raw["api"]; ok {
		t.Fatal("raw config should not contain runtime api injection")
	}
	if _, ok := raw["stats"]; ok {
		t.Fatal("raw config should not contain runtime stats injection")
	}
	if hasAPIInbound(raw) {
		t.Fatal("raw config should not contain API_INBOUND")
	}

	runtime := cfg.Runtime()
	if runtime["api"] == nil || runtime["stats"] == nil {
		t.Fatalf("runtime injection missing api/stats: %#v", runtime)
	}
	if !hasAPIInbound(runtime) {
		t.Fatal("runtime config should include API_INBOUND")
	}
	policy := runtime["policy"].(map[string]any)
	levels := policy["levels"].(map[string]any)
	level0 := levels["0"].(map[string]any)
	if level0["statsUserOnline"] != true {
		t.Fatalf("runtime config should enable online user stats: %#v", level0)
	}
	routing := runtime["routing"].(map[string]any)
	rules := routing["rules"].([]any)
	if len(rules) == 0 {
		t.Fatal("runtime config should include API routing rule")
	}
}

func TestRealityPrivateKeyNormalizationAndDerivation(t *testing.T) {
	hexKey := strings.Repeat("01", 32)
	normalized, err := NormalizeRealityPrivateKey(hexKey)
	if err != nil {
		t.Fatalf("NormalizeRealityPrivateKey() error = %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(normalized)
	if err != nil {
		t.Fatalf("normalized key is not raw url base64: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("normalized key decoded length = %d", len(raw))
	}
	publicKey, err := DeriveRealityPublicKey(normalized)
	if err != nil {
		t.Fatalf("DeriveRealityPublicKey() error = %v", err)
	}
	publicRaw, err := base64.RawURLEncoding.DecodeString(publicKey)
	if err != nil {
		t.Fatalf("public key is not raw url base64: %v", err)
	}
	if len(publicRaw) != 32 {
		t.Fatalf("public key decoded length = %d", len(publicRaw))
	}
	if _, err := NormalizeRealityPrivateKey("short"); err == nil {
		t.Fatal("expected invalid key error")
	}
}

func TestRealityInboundDerivesPublicKey(t *testing.T) {
	cfg := testConfig()
	cfg["inbounds"] = []any{
		map[string]any{
			"tag":      "reality",
			"port":     443,
			"protocol": "vless",
			"streamSettings": map[string]any{
				"network":  "tcp",
				"security": "reality",
				"realitySettings": map[string]any{
					"privateKey":  strings.Repeat("02", 32),
					"target":      "example.com:443",
					"serverNames": []any{"example.com"},
					"shortIds":    []any{"abcd"},
				},
			},
		},
	}
	parsed, err := Parse(cfg, Options{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	inbound := parsed.InboundsByTag()["reality"]
	if inbound["tls"] != "reality" || inbound["fp"] != "chrome" {
		t.Fatalf("unexpected reality inbound: %#v", inbound)
	}
	if inbound["pbk"] == "" {
		t.Fatalf("expected public key derivation: %#v", inbound)
	}
}

func TestRealityInboundAcceptsSettingsShortID(t *testing.T) {
	cfg := testConfig()
	cfg["inbounds"] = []any{
		map[string]any{
			"tag":      "reality",
			"port":     443,
			"protocol": "vless",
			"streamSettings": map[string]any{
				"network":  "tcp",
				"security": "reality",
				"realitySettings": map[string]any{
					"privateKey": strings.Repeat("02", 32),
					"target":     "example.com:443",
					"settings": map[string]any{
						"serverName": "example.com",
						"shortId":    "abcd",
						"spiderX":    "/spider",
					},
				},
			},
		},
	}
	parsed, err := Parse(cfg, Options{})
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	inbound := parsed.InboundsByTag()["reality"]
	if got := firstStringList(inbound["sids"]); got != "abcd" {
		t.Fatalf("expected shortId compatibility, got %#v", inbound)
	}
	if got := firstStringList(inbound["sni"]); got != "example.com" {
		t.Fatalf("expected settings serverName compatibility, got %#v", inbound)
	}
	if got := stringValue(inbound["spx"]); got != "/spider" {
		t.Fatalf("expected spiderX compatibility, got %#v", inbound)
	}
}

func TestParseRejectsInvalidExecutableInbound(t *testing.T) {
	cases := []struct {
		name string
		edit func(map[string]any)
		want string
	}{
		{
			name: "bad reality target",
			edit: func(cfg map[string]any) {
				cfg["inbounds"] = []any{map[string]any{
					"tag":      "reality",
					"port":     443,
					"protocol": "vless",
					"streamSettings": map[string]any{
						"network":  "tcp",
						"security": "reality",
						"realitySettings": map[string]any{
							"privateKey":  strings.Repeat("02", 32),
							"target":      "google.com.443",
							"serverNames": []any{"google.com"},
							"shortIds":    []any{"abcd"},
						},
					},
				}}
			},
			want: "host:port",
		},
		{
			name: "bad inbound port",
			edit: func(cfg map[string]any) {
				inbound := cfg["inbounds"].([]any)[0].(map[string]any)
				inbound["port"] = "443x"
			},
			want: "port must be a number",
		},
		{
			name: "bad xpadding",
			edit: func(cfg map[string]any) {
				inbound := cfg["inbounds"].([]any)[0].(map[string]any)
				stream := inbound["streamSettings"].(map[string]any)
				stream["network"] = "xhttp"
				stream["xhttpSettings"] = map[string]any{"path": "/x", "xPaddingBytes": "+100-1000"}
			},
			want: "xPaddingBytes",
		},
		{
			name: "bad xhttp mode",
			edit: func(cfg map[string]any) {
				inbound := cfg["inbounds"].([]any)[0].(map[string]any)
				stream := inbound["streamSettings"].(map[string]any)
				stream["network"] = "xhttp"
				stream["xhttpSettings"] = map[string]any{"path": "/x", "mode": "invalid"}
			},
			want: "unsupported XHTTP mode",
		},
		{
			name: "GET outside packet-up",
			edit: func(cfg map[string]any) {
				inbound := cfg["inbounds"].([]any)[0].(map[string]any)
				stream := inbound["streamSettings"].(map[string]any)
				stream["network"] = "xhttp"
				stream["xhttpSettings"] = map[string]any{"path": "/x", "mode": "auto", "uplinkHTTPMethod": "GET"}
			},
			want: "GET requires packet-up",
		},
		{
			name: "unsafe session token",
			edit: func(cfg map[string]any) {
				inbound := cfg["inbounds"].([]any)[0].(map[string]any)
				stream := inbound["streamSettings"].(map[string]any)
				stream["network"] = "xhttp"
				stream["xhttpSettings"] = map[string]any{"path": "/x", "sessionIDKey": "X-Session\r\nInjected"}
			},
			want: "valid HTTP token",
		},
		{
			name: "bad uplink range",
			edit: func(cfg map[string]any) {
				inbound := cfg["inbounds"].([]any)[0].(map[string]any)
				stream := inbound["streamSettings"].(map[string]any)
				stream["network"] = "xhttp"
				stream["xhttpSettings"] = map[string]any{"path": "/x", "uplinkChunkSize": "4000-3000"}
			},
			want: "range start",
		},
		{
			name: "negative server header bytes",
			edit: func(cfg map[string]any) {
				inbound := cfg["inbounds"].([]any)[0].(map[string]any)
				stream := inbound["streamSettings"].(map[string]any)
				stream["network"] = "xhttp"
				stream["xhttpSettings"] = map[string]any{"path": "/x", "serverMaxHeaderBytes": -1}
			},
			want: "non-negative 32-bit integer",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			tc.edit(cfg)
			_, err := Parse(cfg, Options{})
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestParseNormalizesXHTTPSessionAliases(t *testing.T) {
	for _, tc := range []struct {
		name      string
		placement string
		key       string
	}{
		{name: "current", placement: "sessionIDPlacement", key: "sessionIDKey"},
		{name: "legacy", placement: "sessionPlacement", key: "sessionKey"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig()
			inbound := cfg["inbounds"].([]any)[0].(map[string]any)
			stream := inbound["streamSettings"].(map[string]any)
			stream["network"] = "xhttp"
			stream["xhttpSettings"] = map[string]any{
				"path":         "/x",
				tc.placement:   "header",
				tc.key:         "X-Session",
				"futureOption": "preserve-me",
			}

			parsed, err := Parse(cfg, Options{})
			if err != nil {
				t.Fatalf("Parse() error = %v", err)
			}
			resolved := parsed.InboundsByTag()["vless-tcp"]
			if got := stringValue(resolved["sessionIDPlacement"]); got != "header" {
				t.Fatalf("sessionIDPlacement = %q, want header: %#v", got, resolved)
			}
			if got := stringValue(resolved["sessionIDKey"]); got != "X-Session" {
				t.Fatalf("sessionIDKey = %q, want X-Session: %#v", got, resolved)
			}
			rawSettings := mapValue(mapValue(listOfMaps(parsed.Raw()["inbounds"])[0]["streamSettings"])["xhttpSettings"])
			if rawSettings[tc.placement] != "header" || rawSettings[tc.key] != "X-Session" || rawSettings["futureOption"] != "preserve-me" {
				t.Fatalf("raw XHTTP settings did not round-trip: %#v", rawSettings)
			}
		})
	}
}

func TestParseRejectsIncompleteOVInbound(t *testing.T) {
	base := func(settings map[string]any) map[string]any {
		return map[string]any{
			"inbounds": []any{
				map[string]any{
					"tag":      "ov",
					"port":     1194,
					"protocol": "openvpn",
					"settings": settings,
				},
			},
			"outbounds": []any{
				map[string]any{"tag": "DIRECT", "protocol": "freedom"},
			},
		}
	}
	validSettings := map[string]any{
		"transport":          "udp",
		"tunnel_port":        51194,
		"ipv4_pool_cidr":     "10.66.0.0/16",
		"ca":                 "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
		"server_certificate": "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
		"server_key":         "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
	}
	if _, err := Parse(base(validSettings), Options{}); err != nil {
		t.Fatalf("valid OV inbound rejected: %v", err)
	}
	directSettings := map[string]any{}
	for key, value := range validSettings {
		directSettings[key] = value
	}
	directSettings["tproxy_enabled"] = false
	delete(directSettings, "tunnel_port")
	if _, err := Parse(base(directSettings), Options{}); err != nil {
		t.Fatalf("direct OV inbound without tunnel_port rejected: %v", err)
	}
	dcoSettings := map[string]any{}
	for key, value := range validSettings {
		dcoSettings[key] = value
	}
	dcoSettings["require_dco"] = true
	dcoSettings["cipher"] = "AES-256-CBC"
	if _, err := Parse(base(dcoSettings), Options{}); err == nil || !strings.Contains(err.Error(), "not DCO-compatible") {
		t.Fatalf("expected DCO cipher validation error, got %v", err)
	}

	cases := []struct {
		name string
		key  string
		want string
	}{
		{name: "missing tunnel port", key: "tunnel_port", want: "tunnel_port is required"},
		{name: "missing ca", key: "ca", want: "ca is required"},
		{name: "missing server certificate", key: "server_certificate", want: "server_certificate is required"},
		{name: "missing server key", key: "server_key", want: "server_key is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			settings := map[string]any{}
			for key, value := range validSettings {
				settings[key] = value
			}
			delete(settings, tc.key)
			_, err := Parse(base(settings), Options{})
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestParseRejectsIncompleteL2TPInbound(t *testing.T) {
	base := func(settings map[string]any) map[string]any {
		return map[string]any{
			"inbounds": []any{
				map[string]any{
					"tag":      "l2tp",
					"port":     1701,
					"protocol": "l2tp",
					"settings": settings,
				},
			},
			"outbounds": []any{
				map[string]any{"tag": "DIRECT", "protocol": "freedom"},
			},
		}
	}
	validSettings := map[string]any{
		"tunnel_port":    1702,
		"ipv4_pool_cidr": "10.67.0.0/16",
		"ipsec_psk":      "secret",
	}
	if _, err := Parse(base(validSettings), Options{}); err != nil {
		t.Fatalf("valid L2TP inbound rejected: %v", err)
	}
	invalidPort := base(validSettings)
	invalidPort["inbounds"].([]any)[0].(map[string]any)["port"] = 4999
	if _, err := Parse(invalidPort, Options{}); err == nil || !strings.Contains(err.Error(), "L2TP port must be 1701") {
		t.Fatalf("expected L2TP port validation error, got %v", err)
	}
	for _, tc := range []struct {
		name string
		key  string
		want string
	}{
		{name: "missing psk", key: "ipsec_psk", want: "ipsec_psk is required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			settings := map[string]any{}
			for key, value := range validSettings {
				settings[key] = value
			}
			delete(settings, tc.key)
			_, err := Parse(base(settings), Options{})
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestTranslateVirtualInboundsToRuntimeTunnel(t *testing.T) {
	for _, protocol := range []string{OVProtocol, WGProtocol, L2TPProtocol, PPTPProtocol, IKEv2Protocol, AnyConnectProtocol, SSTPProtocol, AWGProtocol, GREProtocol} {
		t.Run(protocol, func(t *testing.T) {
			tag := protocol + "-edge"
			raw := map[string]any{
				"inbounds": []any{map[string]any{
					"tag":      tag,
					"port":     1194,
					"protocol": protocol,
					"settings": map[string]any{"tunnel_port": 41940},
				}},
				"routing": map[string]any{"rules": []any{
					map[string]any{"type": "field", "inboundTag": []any{tag}, "outboundTag": "warp"},
				}},
			}
			runtime := TranslateVirtualTunnelInboundsForRuntime(raw)
			inbound := runtime["inbounds"].([]any)[0].(map[string]any)
			wantTag := RuntimeTunnelTagForProtocol(protocol, tag)
			if inbound["protocol"] != "tunnel" || inbound["tag"] != wantTag {
				t.Fatalf("unexpected runtime inbound: %#v", inbound)
			}
			settings := inbound["settings"].(map[string]any)
			if settings["allowedNetwork"] != "tcp,udp" || settings["followRedirect"] != true {
				t.Fatalf("unexpected tunnel settings: %#v", settings)
			}
			rule := runtime["routing"].(map[string]any)["rules"].([]any)[0].(map[string]any)
			tags := rule["inboundTag"].([]any)
			if len(tags) != 1 || tags[0] != wantTag {
				t.Fatalf("unexpected translated rule: %#v", rule)
			}
		})
	}
}

func TestAdditionalProxyInboundValidationAndRuntimeTranslation(t *testing.T) {
	ssh := map[string]any{"tag": "ssh", "port": 2222, "protocol": "ssh", "settings": map[string]any{"user_limit": 2, "idle_timeout": 300}}
	mt := map[string]any{"tag": "telegram", "port": 8443, "protocol": "mtproto", "settings": map[string]any{
		"secret": strings.Repeat("ab", 16), "public_host": "proxy.example.com", "mode_classic": true,
		"mode_secure": true, "mode_tls": true, "tls_domain": "www.google.com", "max_connections": 4096,
	}}
	web := map[string]any{"tag": "web", "port": 443, "protocol": "web", "settings": map[string]any{"hostname": "proxy.example.com", "acme_email": "admin@example.com", "secret": strings.Repeat("cd", 16)}}
	for _, inbound := range []map[string]any{ssh, mt, web} {
		if err := validateExecutableInbound(inbound); err != nil {
			t.Fatalf("valid %s inbound rejected: %v", inbound["protocol"], err)
		}
	}
	if InboundSupportsHosts("mtproto") || InboundSupportsHosts("web") || !InboundSupportsHosts("ssh") {
		t.Fatal("unexpected Host support boundary for auxiliary inbounds")
	}
	runtime := TranslateVirtualTunnelInboundsForRuntime(map[string]any{
		"inbounds": []any{ssh, mt, web},
		"routing":  map[string]any{"rules": []any{map[string]any{"type": "field", "inboundTag": []any{"ssh"}, "outboundTag": "direct"}}},
	})
	inbounds := listOfMaps(runtime["inbounds"])
	if len(inbounds) != 0 {
		t.Fatalf("auxiliary inbounds leaked into the official Xray runtime: %#v", inbounds)
	}
	rules := listOfMaps(mapValue(runtime["routing"])["rules"])
	if len(rules) != 0 {
		t.Fatalf("auxiliary inbound tag was not removed from routing: %#v", rules)
	}
}

func TestParseRejectsInvalidMultiUserShadowsocks2022(t *testing.T) {
	base := func(method, password string) map[string]any {
		return map[string]any{
			"inbounds": []any{map[string]any{
				"tag": "ss", "port": 8388, "protocol": "shadowsocks",
				"settings": map[string]any{"method": method, "password": password},
			}},
			"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}},
		}
	}
	for _, test := range []struct {
		method   string
		password string
	}{
		{"2022-blake3-chacha20-poly1305", "c2VjcmV0"},
		{"2022-blake3-aes-256-gcm", "c2VjcmV0"},
	} {
		if _, err := Parse(base(test.method, test.password), Options{}); err == nil {
			t.Fatalf("expected %s to be rejected", test.method)
		}
	}
}

func TestParseAcceptsShadowsocks2022Chacha20(t *testing.T) {
	password := base64.StdEncoding.EncodeToString(make([]byte, 32))
	_, err := Parse(map[string]any{
		"inbounds": []any{map[string]any{
			"tag": "ss", "port": 8388, "protocol": "shadowsocks",
			"settings": map[string]any{
				"method": "2022-blake3-chacha20-poly1305", "password": password,
			},
		}},
		"outbounds": []any{map[string]any{"tag": "direct", "protocol": "freedom"}},
	}, Options{})
	if err != nil {
		t.Fatalf("valid Shadowsocks 2022 chacha20 config was rejected: %v", err)
	}
}

func TestTranslateDirectVirtualInboundSkipsRuntimeTunnelAndRouting(t *testing.T) {
	raw := map[string]any{
		"inbounds": []any{
			map[string]any{
				"tag":      "ov-direct",
				"port":     1194,
				"protocol": "openvpn",
				"settings": map[string]any{
					"tproxy_enabled":     false,
					"ipv4_pool_cidr":     "10.66.0.0/16",
					"ca":                 "-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----",
					"server_certificate": "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
					"server_key":         "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
				},
			},
			map[string]any{"tag": "vless", "port": 443, "protocol": "vless", "settings": map[string]any{}},
		},
		"routing": map[string]any{
			"rules": []any{
				map[string]any{"type": "field", "inboundTag": []any{"ov-direct"}, "outboundTag": "warp"},
				map[string]any{"type": "field", "inboundTag": []any{"vless", "ov-direct"}, "outboundTag": "direct"},
			},
		},
	}
	runtime := TranslateVirtualTunnelInboundsForRuntime(raw)
	inbounds := runtime["inbounds"].([]any)
	if len(inbounds) != 1 || inbounds[0].(map[string]any)["tag"] != "vless" {
		t.Fatalf("unexpected runtime inbounds: %#v", inbounds)
	}
	rules := runtime["routing"].(map[string]any)["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("unexpected runtime rules: %#v", rules)
	}
	tags := rules[0].(map[string]any)["inboundTag"].([]any)
	if len(tags) != 1 || tags[0] != "vless" {
		t.Fatalf("unexpected filtered rule: %#v", rules[0])
	}
}

func TestPPTPNATDoesNotReserveL2TPTunnelPort(t *testing.T) {
	ports := inboundRuntimePorts(map[string]any{
		"tag":      "pptp-direct",
		"port":     1723,
		"protocol": "pptp",
		"settings": map[string]any{"tproxy_enabled": false},
	})
	if len(ports) != 1 || ports[0] != 1723 {
		t.Fatalf("unexpected PPTP NAT runtime ports: %#v", ports)
	}
}

func TestRemoteAccessInboundValidation(t *testing.T) {
	for _, test := range []struct {
		protocol string
		port     int
		pool     string
	}{{IKEv2Protocol, 500, "10.70.0.0/24"}, {AnyConnectProtocol, 443, "10.71.0.0/24"}} {
		err := validateVirtualTunnelInbound(test.protocol, map[string]any{
			"tag": test.protocol, "port": test.port, "protocol": test.protocol,
			"settings": map[string]any{"auth_mode": "password", "ipv4_pool_cidr": test.pool, "tproxy_enabled": false, "ca_certificate": "ca", "server_certificate": "cert", "server_key": "key", "server_identity": "vpn.example.com"},
		})
		if err != nil {
			t.Fatalf("%s validation failed: %v", test.protocol, err)
		}
	}
}

func TestExtraVPNInboundValidation(t *testing.T) {
	privateKey := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, inbound := range []map[string]any{
		{"tag": "sstp", "port": 443, "protocol": SSTPProtocol, "settings": map[string]any{"ipv4_pool_cidr": "10.72.0.0/24", "tproxy_enabled": false, "server_certificate": "cert", "server_key": "key"}},
		{"tag": "awg", "port": 51820, "protocol": AWGProtocol, "settings": map[string]any{"address_pool": "10.73.0.0/24", "server_address": "10.73.0.1/24", "private_key": privateKey, "tproxy_enabled": false, "jc": 4, "jmin": 8, "jmax": 80}},
		{"tag": "gre", "port": 47, "protocol": GREProtocol, "settings": map[string]any{"ipv4_pool_cidr": "10.74.0.0/24", "tproxy_enabled": false, "mtu": 1476, "ttl": 64}},
	} {
		if err := validateVirtualTunnelInbound(stringValue(inbound["tag"]), inbound); err != nil {
			t.Fatalf("%s validation failed: %v", inbound["protocol"], err)
		}
	}
}

func TestRemoteAccessInboundRejectsUnsafeSettings(t *testing.T) {
	tests := []map[string]any{
		{"tag": "ikev2", "port": 500, "protocol": IKEv2Protocol, "settings": map[string]any{"auth_mode": "password", "ipv4_pool_cidr": "10.70.0.0/24", "tproxy_enabled": false, "ca_certificate": "ca", "server_certificate": "cert", "server_key": "key", "server_identity": "vpn.example.com\nauto=start"}},
		{"tag": "anyconnect", "port": 443, "protocol": AnyConnectProtocol, "settings": map[string]any{"auth_mode": "password", "ipv4_pool_cidr": "10.71.0.0/24", "tproxy_enabled": false, "server_certificate": "cert", "server_key": "key", "routes": []any{"not-a-cidr"}}},
	}
	for _, inbound := range tests {
		if err := validateVirtualTunnelInbound(stringValue(inbound["tag"]), inbound); err == nil {
			t.Fatalf("expected invalid settings to be rejected: %#v", inbound)
		}
	}
}

func TestAnyConnectAdvancedSettingsValidation(t *testing.T) {
	settings := map[string]any{
		"auth_mode": "password", "ipv4_pool_cidr": "10.71.0.0/24", "tproxy_enabled": false,
		"server_certificate": "cert", "server_key": "key", "udp_enabled": true, "udp_port": 8443,
		"listen_host": "vpn.example.com", "udp_listen_host": "192.0.2.10",
		"nbns_servers": []any{"192.0.2.53"}, "split_dns": []any{"corp.example.com"},
		"restrict_user_to_ports": "tcp(80,443), udp(53)", "rx_data_per_sec": 1000000000,
		"tls_priorities": "NORMAL:-VERS-TLS1.0", "cert_user_oid": "2.5.4.3",
	}
	if err := validateVirtualTunnelInbound(AnyConnectProtocol, map[string]any{
		"tag": "anyconnect", "port": 443, "protocol": AnyConnectProtocol, "settings": settings,
	}); err != nil {
		t.Fatalf("advanced AnyConnect settings failed validation: %v", err)
	}
	if got := normalizeAnyConnectSettings(settings)["rx_data_per_sec"]; got != 1000000000 {
		t.Fatalf("rx_data_per_sec was not preserved: %#v", got)
	}
}

func TestAnyConnectRejectsInvalidAdvancedSettings(t *testing.T) {
	for _, override := range []map[string]any{
		{"udp_enabled": true, "udp_port": 0},
		{"tls_priorities": "NORMAL\nrun-script"},
		{"split_dns": []any{"not a domain"}},
	} {
		settings := map[string]any{
			"auth_mode": "password", "ipv4_pool_cidr": "10.71.0.0/24", "tproxy_enabled": false,
			"server_certificate": "cert", "server_key": "key",
		}
		for key, value := range override {
			settings[key] = value
		}
		if err := validateVirtualTunnelInbound(AnyConnectProtocol, map[string]any{
			"tag": "anyconnect", "port": 443, "protocol": AnyConnectProtocol, "settings": settings,
		}); err == nil {
			t.Fatalf("expected invalid AnyConnect settings to be rejected: %#v", override)
		}
	}
}

func TestPPTPRejectsPoolLargerThan24(t *testing.T) {
	err := validateVirtualTunnelInbound("pptp", map[string]any{
		"tag":      "pptp",
		"port":     1723,
		"protocol": "pptp",
		"settings": map[string]any{
			"ipv4_pool_cidr": "10.68.0.0/16",
			"tproxy_enabled": false,
		},
	})
	if err == nil || !strings.Contains(err.Error(), "/24 or narrower") {
		t.Fatalf("expected PPTP pool validation error, got %v", err)
	}
}

func TestMergePolicyPreservesIndependentInboundStatsToggles(t *testing.T) {
	for _, test := range []struct {
		name     string
		uplink   bool
		downlink bool
	}{
		{name: "both disabled"},
		{name: "uplink only", uplink: true},
		{name: "downlink only", downlink: true},
		{name: "both enabled", uplink: true, downlink: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			runtime := map[string]any{"policy": map[string]any{"system": map[string]any{
				"statsInboundUplink":   test.uplink,
				"statsInboundDownlink": test.downlink,
			}}}
			mergePolicy(runtime)
			system := mapValue(mapValue(runtime["policy"])["system"])
			if system["statsInboundUplink"] != test.uplink || system["statsInboundDownlink"] != test.downlink {
				t.Fatalf("inbound stats toggles changed: %#v", system)
			}
			if system["statsOutboundUplink"] != true || system["statsOutboundDownlink"] != true {
				t.Fatalf("outbound stats were not enabled: %#v", system)
			}
		})
	}

	runtime := map[string]any{}
	mergePolicy(runtime)
	system := mapValue(mapValue(runtime["policy"])["system"])
	if system["statsInboundUplink"] != true {
		t.Fatalf("missing inbound uplink toggle should enable inbound statistics: %#v", system)
	}
	if system["statsInboundDownlink"] != true {
		t.Fatalf("missing inbound downlink toggle should enable inbound statistics: %#v", system)
	}
}

func hasAPIInbound(payload map[string]any) bool {
	for _, inbound := range payload["inbounds"].([]any) {
		if inbound.(map[string]any)["tag"] == "API_INBOUND" {
			return true
		}
	}
	return false
}
