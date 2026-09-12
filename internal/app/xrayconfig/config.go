package xrayconfig

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	DefaultAPIHost = "127.0.0.1"
	DefaultAPIPort = 8080
	maxMKCPMTU     = int64(1<<32 - 1)
)

var proxyProtocols = map[string]struct{}{
	"vmess":       {},
	"vless":       {},
	"trojan":      {},
	"shadowsocks": {},
	"hysteria":    {},
}

var auxiliaryInboundProtocols = map[string]struct{}{
	"ssh":     {},
	"mtproto": {},
	"web":     {},
}

var virtualTunnelProtocols = map[string]struct{}{
	OVProtocol:         {},
	WGProtocol:         {},
	L2TPProtocol:       {},
	PPTPProtocol:       {},
	IKEv2Protocol:      {},
	AnyConnectProtocol: {},
	SSTPProtocol:       {},
	AWGProtocol:        {},
	GREProtocol:        {},
}

var (
	validInboundNetworks = map[string]struct{}{
		"tcp":         {},
		"raw":         {},
		"ws":          {},
		"grpc":        {},
		"gun":         {},
		"kcp":         {},
		"quic":        {},
		"http":        {},
		"h2":          {},
		"h3":          {},
		"httpupgrade": {},
		"splithttp":   {},
		"xhttp":       {},
		"hysteria":    {},
	}
	realityShortIDPattern  = regexp.MustCompile(`^[0-9a-fA-F]{2,16}$`)
	xPaddingBytesPattern   = regexp.MustCompile(`^\d+(-\d+)?$`)
	httpTokenPattern       = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")
	xrayCoreVersionPattern = regexp.MustCompile(`(?:^|[^0-9])(\d+)\.(\d+)\.(\d+)(?:$|[^0-9])`)
	xrayPrivateNetworks    = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("169.254.0.0/16"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("192.168.0.0/16"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("224.0.0.0/3"),
		netip.MustParsePrefix("::/127"),
		netip.MustParsePrefix("fc00::/7"),
		netip.MustParsePrefix("fe80::/10"),
		netip.MustParsePrefix("ff00::/8"),
	}
	xrayPrivateDomains = []string{
		"lan",
		"localdomain",
		"example",
		"invalid",
		"localhost",
		"test",
		"local",
		"home.arpa",
		"internal",
	}
	xhttpSessionTables = map[string]string{
		"ALPHABET": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"Alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
		"BASE36":   "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ",
		"Base62":   "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
		"HEX":      "0123456789ABCDEF",
		"alphabet": "abcdefghijklmnopqrstuvwxyz",
		"base36":   "0123456789abcdefghijklmnopqrstuvwxyz",
		"hex":      "0123456789abcdef",
		"number":   "0123456789",
	}
)

type Options struct {
	APIHost                 string
	APIPort                 int
	UseVerifyPeerCertByName *bool
	MutationRecorder        MutationRecorder
	RollbackMarker          RollbackMarker
}

type Config struct {
	raw        map[string]any
	runtime    map[string]any
	inbounds   []ResolvedInbound
	byTag      map[string]ResolvedInbound
	byProtocol map[string][]ResolvedInbound
	options    Options
}

type ResolvedInbound map[string]any

func Parse(input any, opts Options) (*Config, error) {
	raw, err := mapInput(input)
	if err != nil {
		return nil, err
	}
	raw = NormalizePayload(raw)
	opts = normalizeOptions(opts)

	cfg := &Config{
		raw:        raw,
		options:    opts,
		byTag:      map[string]ResolvedInbound{},
		byProtocol: map[string][]ResolvedInbound{},
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	cfg.migrateDeprecated()
	if err := cfg.resolveInbounds(); err != nil {
		return nil, err
	}
	cfg.runtime = cfg.runtimePayload()
	return cfg, nil
}

func NormalizePayload(payload map[string]any) map[string]any {
	cfg := deepCopyMap(payload)
	removeLegacyReverse(cfg)
	for _, inbound := range listOfMaps(cfg["inbounds"]) {
		normalizeRemovedTLSFields(mapValue(inbound["streamSettings"]), true)
	}
	for _, outbound := range listOfMaps(cfg["outbounds"]) {
		normalizeRemovedTLSFields(mapValue(outbound["streamSettings"]), false)
	}
	logCfg := mapValue(cfg["log"])
	if _, ok := logCfg["access"]; !ok {
		logCfg["access"] = ""
	}
	if _, ok := logCfg["error"]; !ok {
		logCfg["error"] = ""
	}
	logCfg["accessCleanupInterval"] = normalizeLogCleanupInterval(logCfg["accessCleanupInterval"])
	logCfg["errorCleanupInterval"] = normalizeLogCleanupInterval(logCfg["errorCleanupInterval"])
	cfg["log"] = logCfg
	return cfg
}

// NormalizePayloadForXrayVersion prepares transport settings for the core
// running on a particular node without changing the persisted panel config.
func NormalizePayloadForXrayVersion(payload map[string]any, coreVersion string) (map[string]any, string) {
	cfg := deepCopyMap(payload)
	atLeast25829, knownVersion := xrayVersionAtLeast(coreVersion, 25, 8, 29)
	atLeast26113, _ := xrayVersionAtLeast(coreVersion, 26, 1, 13)
	atLeast26131, _ := xrayVersionAtLeast(coreVersion, 26, 1, 31)
	atLeast2659, _ := xrayVersionAtLeast(coreVersion, 26, 5, 9)
	mkcpTTIMaximum, _ := xrayMKCPTTIMax(coreVersion)
	atLeast26711, _ := xrayVersionAtLeast(coreVersion, 26, 7, 11)
	atLeast26327, _ := xrayVersionAtLeast(coreVersion, 26, 3, 27)
	atLeast2661, _ := xrayVersionAtLeast(coreVersion, 26, 6, 1)
	atLeast26622, _ := xrayVersionAtLeast(coreVersion, 26, 6, 22)
	useSessionIDFields := atLeast26622
	inbounds := listOfMaps(cfg["inbounds"])
	outbounds := listOfMaps(cfg["outbounds"])
	legacyInsecureTags := make([]string, 0)
	invalidPinTags := make([]string, 0)
	unknownTLSSyntaxTags := make([]string, 0)
	normalizedMKCPTags := make([]string, 0)
	incompatibleMKCPTags := make([]string, 0)
	unknownMKCPTags := make([]string, 0)
	incompatibleMKCPMTUTags := make([]string, 0)
	unknownMKCPMTUTags := make([]string, 0)
	incompatibleMKCPTTITags := make([]string, 0)
	unknownMKCPTTITags := make([]string, 0)
	normalizedFragmentTags := make([]string, 0)
	incompatibleFragmentTags := make([]string, 0)
	unknownFragmentTags := make([]string, 0)
	vlessEncryptionTags := append(vlessEncryptionEndpointTags(inbounds), vlessEncryptionEndpointTags(outbounds)...)
	vlessDefaultFlowTags := vlessDefaultFlowEndpointTags(inbounds)
	for index, inbound := range inbounds {
		stream := mapValue(inbound["streamSettings"])
		normalizeStreamForXrayVersion(stream, atLeast26711, useSessionIDFields, knownVersion)
		invalidPin, versionSensitive := normalizeTLSFieldsForXrayVersion(stream, atLeast26131, knownVersion)
		label := configEndpointLabel(inbound, index)
		if invalidPin {
			invalidPinTags = append(invalidPinTags, label)
		}
		if versionSensitive && !knownVersion {
			unknownTLSSyntaxTags = append(unknownTLSSyntaxTags, label)
		}
		switch normalizeLegacyMKCPForXrayVersion(stream, atLeast26131, atLeast2661, knownVersion) {
		case mkcpNormalized:
			normalizedMKCPTags = append(normalizedMKCPTags, label)
		case mkcpIncompatible:
			incompatibleMKCPTags = append(incompatibleMKCPTags, label)
		case mkcpUnknownVersion:
			unknownMKCPTags = append(unknownMKCPTags, label)
		}
		if incompatible, unknown := incompatibleMKCPMTU(stream, atLeast26131, knownVersion); incompatible {
			incompatibleMKCPMTUTags = append(incompatibleMKCPMTUTags, label)
		} else if unknown {
			unknownMKCPMTUTags = append(unknownMKCPMTUTags, label)
		}
		if incompatible, unknown := incompatibleMKCPTTI(stream, mkcpTTIMaximum, knownVersion); incompatible {
			incompatibleMKCPTTITags = append(incompatibleMKCPTTITags, label)
		} else if unknown {
			unknownMKCPTTITags = append(unknownMKCPTTITags, label)
		}
		switch normalizeFragmentFinalMaskForXrayVersion(stream, atLeast26622, knownVersion) {
		case fragmentNormalized:
			normalizedFragmentTags = append(normalizedFragmentTags, label)
		case fragmentIncompatible:
			incompatibleFragmentTags = append(incompatibleFragmentTags, label)
		case fragmentUnknownVersion:
			unknownFragmentTags = append(unknownFragmentTags, label)
		}
	}
	for index, outbound := range outbounds {
		stream := mapValue(outbound["streamSettings"])
		normalizeStreamForXrayVersion(stream, atLeast26711, useSessionIDFields, knownVersion)
		invalidPin, versionSensitive := normalizeTLSFieldsForXrayVersion(stream, atLeast26131, knownVersion)
		label := configEndpointLabel(outbound, index)
		if invalidPin {
			invalidPinTags = append(invalidPinTags, label)
		}
		if versionSensitive && !knownVersion {
			unknownTLSSyntaxTags = append(unknownTLSSyntaxTags, label)
		}
		if normalizeOutboundAllowInsecureForXrayVersion(stream, atLeast26131, knownVersion) {
			legacyInsecureTags = append(legacyInsecureTags, configEndpointLabel(outbound, index))
		}
		switch normalizeLegacyMKCPForXrayVersion(stream, atLeast26131, atLeast2661, knownVersion) {
		case mkcpNormalized:
			normalizedMKCPTags = append(normalizedMKCPTags, label)
		case mkcpIncompatible:
			incompatibleMKCPTags = append(incompatibleMKCPTags, label)
		case mkcpUnknownVersion:
			unknownMKCPTags = append(unknownMKCPTags, label)
		}
		if incompatible, unknown := incompatibleMKCPMTU(stream, atLeast26131, knownVersion); incompatible {
			incompatibleMKCPMTUTags = append(incompatibleMKCPMTUTags, label)
		} else if unknown {
			unknownMKCPMTUTags = append(unknownMKCPMTUTags, label)
		}
		if incompatible, unknown := incompatibleMKCPTTI(stream, mkcpTTIMaximum, knownVersion); incompatible {
			incompatibleMKCPTTITags = append(incompatibleMKCPTTITags, label)
		} else if unknown {
			unknownMKCPTTITags = append(unknownMKCPTTITags, label)
		}
		switch normalizeFragmentFinalMaskForXrayVersion(stream, atLeast26622, knownVersion) {
		case fragmentNormalized:
			normalizedFragmentTags = append(normalizedFragmentTags, label)
		case fragmentIncompatible:
			incompatibleFragmentTags = append(incompatibleFragmentTags, label)
		case fragmentUnknownVersion:
			unknownFragmentTags = append(unknownFragmentTags, label)
		}
	}
	warnings := make([]string, 0, 12)
	if !knownVersion {
		warnings = append(warnings, "Xray core version is unknown or invalid; using legacy transport naming, preserving both XHTTP session aliases, and preserving Hysteria settings")
	} else {
		if !atLeast26327 {
			if tags := hysteriaEndpointTags(inbounds); len(tags) > 0 {
				warnings = append(warnings, fmt.Sprintf("Xray before 26.3.27 does not support Hysteria 2 inbounds; preserving inbound settings for: %s", strings.Join(tags, ", ")))
			}
		} else {
			normalized, incompatible := normalizeCompatibleHysteria2(inbounds)
			if len(normalized) > 0 {
				warnings = append(warnings, fmt.Sprintf("Normalized compatible Hysteria inbound runtime settings to version 2 for: %s", strings.Join(normalized, ", ")))
			}
			if len(incompatible) > 0 {
				warnings = append(warnings, fmt.Sprintf("Hysteria inbound settings are not safely recognizable as version 2 and were preserved for: %s", strings.Join(incompatible, ", ")))
			}
		}
		if !atLeast26113 {
			if tags := hysteriaEndpointTags(outbounds); len(tags) > 0 {
				warnings = append(warnings, fmt.Sprintf("This Xray version predates the first released Hysteria 2 outbound transport; preserving outbound settings for: %s", strings.Join(tags, ", ")))
			}
		} else {
			normalized, incompatible := normalizeCompatibleHysteria2(outbounds)
			if len(normalized) > 0 {
				warnings = append(warnings, fmt.Sprintf("Normalized compatible Hysteria outbound runtime settings to version 2 for: %s", strings.Join(normalized, ", ")))
			}
			if len(incompatible) > 0 {
				warnings = append(warnings, fmt.Sprintf("Hysteria outbound settings are not safely recognizable as version 2 and were preserved for: %s", strings.Join(incompatible, ", ")))
			}
		}
	}
	if tags := hysteriaGeckoEndpointTags(append(append([]map[string]any{}, inbounds...), outbounds...)); len(tags) > 0 {
		switch {
		case !knownVersion:
			warnings = append(warnings, fmt.Sprintf("Xray core version is unknown; Hysteria Gecko FinalMask support starts at 26.6.1 and settings were preserved for: %s", strings.Join(tags, ", ")))
		case !atLeast2661:
			warnings = append(warnings, fmt.Sprintf("Xray before 26.6.1 cannot run Hysteria Gecko FinalMask; settings were preserved without semantic downgrade for: %s", strings.Join(tags, ", ")))
		}
	}
	if len(vlessEncryptionTags) > 0 {
		switch {
		case !knownVersion:
			warnings = append(warnings, fmt.Sprintf("Xray core version is unknown; VLESS Encryption support starts at 26.5.9 and non-none settings were preserved without downgrade for: %s", strings.Join(vlessEncryptionTags, ", ")))
		case !atLeast2659:
			warnings = append(warnings, fmt.Sprintf("Xray before 26.5.9 does not accept VLESS Encryption decryption/encryption values; settings were preserved without downgrade for: %s", strings.Join(vlessEncryptionTags, ", ")))
		}
	}
	if len(vlessDefaultFlowTags) > 0 {
		switch {
		case !knownVersion:
			warnings = append(warnings, fmt.Sprintf("Xray core version is unknown; VLESS inbound default flow support starts at 25.8.29 and settings were preserved for: %s", strings.Join(vlessDefaultFlowTags, ", ")))
		case !atLeast25829:
			warnings = append(warnings, fmt.Sprintf("Xray before 25.8.29 does not support VLESS inbound default flow; settings were preserved without downgrade for: %s", strings.Join(vlessDefaultFlowTags, ", ")))
		}
	}
	if atLeast26711 {
		flatTags, nestedTags := insecurePublicOutboundTags(outbounds)
		if len(flatTags) > 0 {
			warnings = append(warnings, fmt.Sprintf("Xray 26.7.11+ rejects flat unencrypted VLESS/Trojan outbounds for public destinations. Add TLS, REALITY, or VLESS encryption to: %s", strings.Join(flatTags, ", ")))
		}
		if len(nestedTags) > 0 {
			warnings = append(warnings, fmt.Sprintf("Official VLESS transport-security guidance treats unencrypted public destinations as unsafe. These legacy nested VLESS/Trojan outbounds are not covered by Xray's flat-config rejection and were preserved without auto-TLS mutation: %s", strings.Join(nestedTags, ", ")))
		}
	}
	if len(legacyInsecureTags) > 0 {
		switch {
		case !knownVersion:
			warnings = append(warnings, fmt.Sprintf("Xray core version is unknown; tlsSettings.allowInsecure stays metadata-only because Xray 26.1.31+ requires certificate pinning or peer-name verification for: %s", strings.Join(legacyInsecureTags, ", ")))
		case atLeast26131:
			warnings = append(warnings, fmt.Sprintf("Xray 26.1.31+ removed tlsSettings.allowInsecure; it was omitted from runtime config and certificate pinning or peer-name verification is required for: %s", strings.Join(legacyInsecureTags, ", ")))
		}
	}
	if len(invalidPinTags) > 0 {
		warnings = append(warnings, fmt.Sprintf("Malformed pinnedPeerCertSha256 values could not be converted safely and were preserved for: %s", strings.Join(invalidPinTags, ", ")))
	}
	if len(unknownTLSSyntaxTags) > 0 {
		warnings = append(warnings, fmt.Sprintf("Xray core version is unknown; preserving canonical TLS pin and peer-name syntax without emitting mutually incompatible aliases for: %s", strings.Join(unknownTLSSyntaxTags, ", ")))
	}
	if len(normalizedMKCPTags) > 0 {
		warnings = append(warnings, fmt.Sprintf("Moved legacy mKCP header/seed semantics to version-compatible FinalMask for: %s", strings.Join(normalizedMKCPTags, ", ")))
	}
	if len(incompatibleMKCPTags) > 0 {
		warnings = append(warnings, fmt.Sprintf("Legacy mKCP header/seed settings could not be translated losslessly and were preserved for: %s", strings.Join(incompatibleMKCPTags, ", ")))
	}
	if len(unknownMKCPTags) > 0 {
		warnings = append(warnings, fmt.Sprintf("Xray core version is unknown; preserving version-sensitive legacy mKCP header/seed settings for: %s", strings.Join(unknownMKCPTags, ", ")))
	}
	if len(incompatibleMKCPMTUTags) > 0 {
		warnings = append(warnings, fmt.Sprintf("Xray before 26.1.31 accepts mKCP mtu only from 576 through 1460; other canonical values were preserved without clamping for: %s", strings.Join(incompatibleMKCPMTUTags, ", ")))
	}
	if len(unknownMKCPMTUTags) > 0 {
		warnings = append(warnings, fmt.Sprintf("Xray core version is unknown; mKCP mtu outside the legacy 576 through 1460 range is version-sensitive and was preserved without clamping for: %s", strings.Join(unknownMKCPMTUTags, ", ")))
	}
	if len(incompatibleMKCPTTITags) > 0 {
		warnings = append(warnings, fmt.Sprintf("This Xray version accepts mKCP tti only up to %d ms; larger values were preserved without clamping for: %s", mkcpTTIMaximum, strings.Join(incompatibleMKCPTTITags, ", ")))
	}
	if len(unknownMKCPTTITags) > 0 {
		warnings = append(warnings, fmt.Sprintf("Xray core version is unknown; mKCP tti above the conservative 100 ms limit is version-sensitive and was preserved without clamping for: %s", strings.Join(unknownMKCPTTITags, ", ")))
	}
	if len(normalizedFragmentTags) > 0 {
		warnings = append(warnings, fmt.Sprintf("Normalized FinalMask fragment length/delay aliases for this Xray version for: %s", strings.Join(normalizedFragmentTags, ", ")))
	}
	if len(incompatibleFragmentTags) > 0 {
		warnings = append(warnings, fmt.Sprintf("FinalMask fragment arrays with multiple ranges cannot be represented losslessly before Xray 26.6.22 and were preserved for: %s", strings.Join(incompatibleFragmentTags, ", ")))
	}
	if len(unknownFragmentTags) > 0 {
		warnings = append(warnings, fmt.Sprintf("Xray core version is unknown; preserving version-sensitive FinalMask fragment lengths/delays arrays for: %s", strings.Join(unknownFragmentTags, ", ")))
	}
	if tags := removedTransportEndpointTags(append(append([]map[string]any{}, inbounds...), outbounds...)); len(tags) > 0 && (!knownVersion || atLeast26131) {
		if knownVersion {
			warnings = append(warnings, fmt.Sprintf("Xray 26.1.31+ removed HTTP/H2/H3 and QUIC transports; migrate HTTP to XHTTP stream-one and review QUIC security/key/header semantics for: %s", strings.Join(tags, ", ")))
		} else {
			warnings = append(warnings, fmt.Sprintf("Xray core version is unknown; HTTP/H2/H3 and QUIC transports are removed in 26.1.31+ and were preserved without a lossy migration for: %s", strings.Join(tags, ", ")))
		}
	}
	return cfg, strings.Join(warnings, "; ")
}

func normalizeOutboundAllowInsecureForXrayVersion(stream map[string]any, atLeast26131 bool, knownVersion bool) bool {
	if len(stream) == 0 {
		return false
	}
	tlsSettings := mapValue(stream["tlsSettings"])
	if len(tlsSettings) == 0 {
		return false
	}
	metadata := mapValue(tlsSettings["settings"])
	if allow, exists := tlsSettings["allowInsecure"]; exists {
		if _, preserved := metadata["allowInsecure"]; !preserved {
			metadata["allowInsecure"] = allow
		}
		delete(tlsSettings, "allowInsecure")
	}
	allow, exists := metadata["allowInsecure"]
	if !exists {
		stream["tlsSettings"] = tlsSettings
		return false
	}
	tlsSettings["settings"] = metadata
	if knownVersion && !atLeast26131 {
		tlsSettings["allowInsecure"] = allow
	}
	stream["tlsSettings"] = tlsSettings
	return boolValue(allow)
}

func normalizeTLSFieldsForXrayVersion(stream map[string]any, atLeast26131 bool, knownVersion bool) (invalidPin bool, versionSensitive bool) {
	tlsSettings := mapValue(stream["tlsSettings"])
	if len(tlsSettings) == 0 {
		return false, false
	}
	if pin := strings.TrimSpace(joinStringList(tlsSettings["pinnedPeerCertSha256"])); pin != "" {
		versionSensitive = true
		pins, valid := parseXrayCertificatePins(pin)
		if !valid {
			invalidPin = true
		} else if knownVersion && atLeast26131 {
			tlsSettings["pinnedPeerCertSha256"] = strings.Join(pins, ",")
		} else if knownVersion {
			for index, value := range pins {
				pins[index] = strings.ReplaceAll(value, ":", "")
			}
			tlsSettings["pinnedPeerCertSha256"] = strings.Join(pins, "~")
		}
	}
	byName := stringList(tlsSettings["verifyPeerCertByName"])
	inNames := stringList(tlsSettings["verifyPeerCertInNames"])
	if len(byName) > 0 || len(inNames) > 0 {
		versionSensitive = true
		names := byName
		if len(names) == 0 {
			names = inNames
		}
		if knownVersion && !atLeast26131 {
			tlsSettings["verifyPeerCertInNames"] = names
			delete(tlsSettings, "verifyPeerCertByName")
		} else {
			tlsSettings["verifyPeerCertByName"] = strings.Join(names, ",")
			delete(tlsSettings, "verifyPeerCertInNames")
		}
	}
	stream["tlsSettings"] = tlsSettings
	return invalidPin, versionSensitive
}

func parseXrayCertificatePins(raw string) ([]string, bool) {
	normalized := strings.ReplaceAll(strings.TrimSpace(raw), "~", ",")
	if normalized == "" {
		return nil, false
	}
	parts := strings.Split(normalized, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		compact := strings.ReplaceAll(value, ":", "")
		if len(compact) != 64 {
			return nil, false
		}
		decoded, err := hex.DecodeString(compact)
		if err != nil || len(decoded) != 32 {
			return nil, false
		}
		result = append(result, value)
	}
	return result, len(result) > 0
}

func ValidCertificatePins(raw string) bool {
	_, valid := parseXrayCertificatePins(raw)
	return valid
}

type mkcpNormalization int

const (
	mkcpUnchanged mkcpNormalization = iota
	mkcpNormalized
	mkcpIncompatible
	mkcpUnknownVersion
)

func normalizeLegacyMKCPForXrayVersion(stream map[string]any, atLeast26131, atLeast2661, knownVersion bool) mkcpNormalization {
	if streamNetwork(stream) != "kcp" {
		return mkcpUnchanged
	}
	settings := mapValue(stream["kcpSettings"])
	headerValue, headerExists := settings["header"]
	seedValue, seedExists := settings["seed"]
	headerExists = headerExists && headerValue != nil
	seedExists = seedExists && seedValue != nil
	if !headerExists && !seedExists {
		return mkcpUnchanged
	}
	if !knownVersion {
		return mkcpUnknownVersion
	}
	if !atLeast26131 {
		return mkcpUnchanged
	}
	headerType := "none"
	headerDomain := ""
	if headerExists {
		header := mapValue(headerValue)
		headerType = strings.ToLower(strings.TrimSpace(stringValue(header["type"])))
		if headerType == "" {
			headerType = "none"
		}
		headerDomain = strings.TrimSpace(stringValue(header["domain"]))
	}
	headerType = normalizeLegacyMKCPHeader(headerType)
	if headerType == "invalid" {
		return mkcpIncompatible
	}
	seed := stringValue(seedValue)
	masks := make([]any, 0, 2)
	if atLeast2661 {
		masks = append(masks, map[string]any{"type": "mkcp-legacy", "settings": map[string]any{"header": "", "value": seed}})
		if headerType != "none" {
			value := ""
			if headerType == "dns" {
				value = headerDomain
			}
			masks = append(masks, map[string]any{"type": "mkcp-legacy", "settings": map[string]any{"header": headerType, "value": value}})
		}
	} else {
		if seedExists {
			masks = append(masks, map[string]any{"type": "mkcp-aes128gcm", "settings": map[string]any{"password": seed}})
		} else {
			masks = append(masks, map[string]any{"type": "mkcp-original", "settings": map[string]any{}})
		}
		if headerType != "none" {
			settings := map[string]any{}
			if headerType == "dns" && headerDomain != "" {
				settings["domain"] = headerDomain
			}
			masks = append(masks, map[string]any{"type": "header-" + headerType, "settings": settings})
		}
	}
	finalMask := mapValue(stream["finalmask"])
	if existing, ok := finalMask["udp"].([]any); ok {
		if len(existing) > 0 {
			outerType := strings.ToLower(strings.TrimSpace(stringValue(mapValue(existing[0])["type"])))
			if outerType == "realm" || outerType == "xicmp" {
				masks = append(append([]any{existing[0]}, masks...), existing[1:]...)
			} else {
				masks = append(masks, existing...)
			}
		}
	}
	finalMask["udp"] = masks
	stream["finalmask"] = finalMask
	delete(settings, "header")
	delete(settings, "seed")
	stream["kcpSettings"] = settings
	return mkcpNormalized
}

func normalizeLegacyMKCPHeader(value string) string {
	switch value {
	case "", "none":
		return "none"
	case "dns", "dtls", "srtp", "utp", "wireguard":
		return value
	case "wechat", "wechat-video":
		return "wechat"
	default:
		return "invalid"
	}
}

func xrayMKCPTTIMax(coreVersion string) (int, bool) {
	atLeast26323, known := xrayVersionAtLeast(coreVersion, 26, 3, 23)
	if !known {
		return 100, false
	}
	atLeast26413, _ := xrayVersionAtLeast(coreVersion, 26, 4, 13)
	if atLeast26413 {
		return 1000, true
	}
	if atLeast26323 {
		return 5000, true
	}
	return 100, true
}

func incompatibleMKCPTTI(stream map[string]any, maximum int, knownVersion bool) (incompatible bool, unknown bool) {
	if streamNetwork(stream) != "kcp" {
		return false, false
	}
	tti := intValue(mapValue(stream["kcpSettings"])["tti"])
	if tti <= 100 {
		return false, false
	}
	if !knownVersion {
		return false, true
	}
	return tti > maximum, false
}

func incompatibleMKCPMTU(stream map[string]any, atLeast26131, knownVersion bool) (incompatible bool, unknown bool) {
	if streamNetwork(stream) != "kcp" {
		return false, false
	}
	mtu, err := strconv.ParseInt(strings.TrimSpace(stringValue(mapValue(stream["kcpSettings"])["mtu"])), 10, 64)
	if err != nil || mtu == 0 || (mtu >= 576 && mtu <= 1460) {
		return false, false
	}
	if !knownVersion {
		return false, true
	}
	return !atLeast26131, false
}

type fragmentNormalization int

const (
	fragmentUnchanged fragmentNormalization = iota
	fragmentNormalized
	fragmentIncompatible
	fragmentUnknownVersion
)

func normalizeFragmentFinalMaskForXrayVersion(stream map[string]any, usePlural, knownVersion bool) fragmentNormalization {
	finalMask := mapValue(stream["finalmask"])
	tcpMasks := listOfMaps(finalMask["tcp"])
	if len(tcpMasks) == 0 {
		return fragmentUnchanged
	}
	if status := fragmentFinalMaskCompatibility(tcpMasks, usePlural, knownVersion); status != fragmentUnchanged {
		return status
	}
	changed := false
	for _, mask := range tcpMasks {
		if !strings.EqualFold(stringValue(mask["type"]), "fragment") {
			continue
		}
		settings := mapValue(mask["settings"])
		for _, pair := range [][2]string{{"lengths", "length"}, {"delays", "delay"}} {
			plural, singular := pair[0], pair[1]
			values, hasValues := anyList(settings[plural])
			singularValue, hasSingular := settings[singular]
			if usePlural {
				if !hasValues && hasSingular {
					settings[plural] = []any{singularValue}
					delete(settings, singular)
					changed = true
				} else if hasValues && hasSingular {
					delete(settings, singular)
					changed = true
				}
				continue
			}
			if !hasValues {
				continue
			}
			settings[singular] = values[0]
			delete(settings, plural)
			changed = true
		}
		mask["settings"] = settings
	}
	if changed {
		return fragmentNormalized
	}
	return fragmentUnchanged
}

func fragmentFinalMaskCompatibility(tcpMasks []map[string]any, usePlural, knownVersion bool) fragmentNormalization {
	for _, mask := range tcpMasks {
		if !strings.EqualFold(stringValue(mask["type"]), "fragment") {
			continue
		}
		settings := mapValue(mask["settings"])
		if !knownVersion && (isList(settings["lengths"]) || isList(settings["delays"])) {
			return fragmentUnknownVersion
		}
		for _, pair := range [][2]string{{"lengths", "length"}, {"delays", "delay"}} {
			values, hasValues := anyList(settings[pair[0]])
			singularValue, hasSingular := settings[pair[1]]
			if usePlural {
				if hasValues && hasSingular && (len(values) != 1 || stringValue(values[0]) != stringValue(singularValue)) {
					return fragmentIncompatible
				}
				continue
			}
			if hasValues && (len(values) != 1 || (hasSingular && stringValue(values[0]) != stringValue(singularValue))) {
				return fragmentIncompatible
			}
		}
	}
	return fragmentUnchanged
}

func anyList(value any) ([]any, bool) {
	switch typed := value.(type) {
	case []any:
		return typed, true
	case []string:
		values := make([]any, len(typed))
		for index, item := range typed {
			values[index] = item
		}
		return values, true
	default:
		return nil, false
	}
}

func removedTransportEndpointTags(endpoints []map[string]any) []string {
	tags := make([]string, 0)
	for index, endpoint := range endpoints {
		switch streamNetwork(mapValue(endpoint["streamSettings"])) {
		case "http", "h2", "h3", "quic":
			tags = append(tags, configEndpointLabel(endpoint, index))
		}
	}
	return tags
}

func hysteriaEndpointTags(endpoints []map[string]any) []string {
	tags := make([]string, 0)
	for index, endpoint := range endpoints {
		if strings.EqualFold(stringValue(endpoint["protocol"]), "hysteria") {
			tags = append(tags, configEndpointLabel(endpoint, index))
		}
	}
	return tags
}

func normalizeCompatibleHysteria2(endpoints []map[string]any) (normalized []string, incompatible []string) {
	for index, endpoint := range endpoints {
		if !strings.EqualFold(stringValue(endpoint["protocol"]), "hysteria") {
			continue
		}
		label := configEndpointLabel(endpoint, index)
		settings := mapValue(endpoint["settings"])
		stream := mapValue(endpoint["streamSettings"])
		hysteria := mapValue(stream["hysteriaSettings"])
		if !hysteria2ProtocolShapeCompatible(settings) || len(hysteria) == 0 ||
			!strings.EqualFold(firstNonEmptyString(stream["method"], stream["network"]), "hysteria") ||
			!strings.EqualFold(stringValue(stream["security"]), "tls") ||
			!hysteriaVersionCompatible(settings["version"]) || !hysteriaVersionCompatible(hysteria["version"]) {
			incompatible = append(incompatible, label)
			continue
		}
		changed := intValue(settings["version"]) != 2 || intValue(hysteria["version"]) != 2
		settings["version"] = 2
		hysteria["version"] = 2
		if changed {
			normalized = append(normalized, label)
		}
	}
	return normalized, incompatible
}

func hysteria2ProtocolShapeCompatible(settings map[string]any) bool {
	if _, hasClients := settings["clients"]; hasClients {
		return true
	}
	return strings.TrimSpace(stringValue(settings["address"])) != "" && intValue(settings["port"]) > 0
}

func hysteriaVersionCompatible(value any) bool {
	version := intValue(value)
	return version == 0 || version == 2
}

func hysteriaGeckoEndpointTags(endpoints []map[string]any) []string {
	tags := make([]string, 0)
	for index, endpoint := range endpoints {
		stream := mapValue(endpoint["streamSettings"])
		if streamNetwork(stream) != "hysteria" {
			continue
		}
		for _, mask := range listOfMaps(mapValue(stream["finalmask"])["udp"]) {
			if strings.EqualFold(stringValue(mask["type"]), "salamander") && stringValue(mapValue(mask["settings"])["packetSize"]) != "" {
				tags = append(tags, configEndpointLabel(endpoint, index))
				break
			}
		}
	}
	return tags
}

func configEndpointLabel(endpoint map[string]any, index int) string {
	if tag := strings.TrimSpace(stringValue(endpoint["tag"])); tag != "" {
		return tag
	}
	return fmt.Sprintf("endpoint #%d", index+1)
}

func insecurePublicOutboundTags(outbounds []map[string]any) (flatTags, nestedTags []string) {
	for index, outbound := range outbounds {
		protocol := strings.ToLower(stringValue(outbound["protocol"]))
		if protocol != "vless" && protocol != "trojan" {
			continue
		}
		security := strings.ToLower(stringValue(mapValue(outbound["streamSettings"])["security"]))
		if security != "" && security != "none" {
			continue
		}
		settings := mapValue(outbound["settings"])
		flat, nested := unencryptedPublicDestinationShapes(protocol, settings)
		if !flat && !nested {
			continue
		}
		tag := stringValue(outbound["tag"])
		if tag == "" {
			tag = fmt.Sprintf("outbound #%d", index+1)
		}
		if flat {
			flatTags = append(flatTags, tag)
		}
		if nested {
			nestedTags = append(nestedTags, tag)
		}
	}
	return flatTags, nestedTags
}

func unencryptedPublicDestinationShapes(protocol string, settings map[string]any) (flat, nested bool) {
	if protocol == "trojan" {
		if isXrayPublicDestination(stringValue(settings["address"])) {
			flat = true
		}
		for _, server := range listOfMaps(settings["servers"]) {
			if isXrayPublicDestination(stringValue(server["address"])) {
				nested = true
				break
			}
		}
		return flat, nested
	}

	if isXrayPublicDestination(stringValue(settings["address"])) && !vlessEncryptionEnabled(settings["encryption"]) {
		flat = true
	}
	for _, server := range listOfMaps(settings["vnext"]) {
		if !isXrayPublicDestination(stringValue(server["address"])) {
			continue
		}
		users := listOfMaps(server["users"])
		if len(users) == 0 {
			nested = true
			continue
		}
		for _, user := range users {
			if !vlessEncryptionEnabled(user["encryption"]) {
				nested = true
				break
			}
		}
	}
	return flat, nested
}

func vlessEncryptionEnabled(value any) bool {
	encryption := strings.ToLower(stringValue(value))
	return encryption != "" && encryption != "none"
}

func vlessEncryptionEndpointTags(endpoints []map[string]any) []string {
	tags := make([]string, 0)
	for index, endpoint := range endpoints {
		if !strings.EqualFold(stringValue(endpoint["protocol"]), "vless") {
			continue
		}
		settings := mapValue(endpoint["settings"])
		enabled := vlessEncryptionEnabled(settings["decryption"]) || vlessEncryptionEnabled(settings["encryption"])
		for _, server := range listOfMaps(settings["vnext"]) {
			for _, user := range listOfMaps(server["users"]) {
				enabled = enabled || vlessEncryptionEnabled(user["encryption"])
			}
		}
		if enabled {
			tags = append(tags, configEndpointLabel(endpoint, index))
		}
	}
	return tags
}

func vlessDefaultFlowEndpointTags(inbounds []map[string]any) []string {
	tags := make([]string, 0)
	for index, inbound := range inbounds {
		if !strings.EqualFold(stringValue(inbound["protocol"]), "vless") {
			continue
		}
		settings := mapValue(inbound["settings"])
		flow := firstNonEmptyString(settings["flow"])
		if flow != "" {
			tags = append(tags, configEndpointLabel(inbound, index))
		}
	}
	return tags
}

func isXrayPublicDestination(value string) bool {
	return strings.TrimSpace(value) != "" && !isXrayPrivateDestination(value)
}

func isXrayPrivateDestination(value string) bool {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if host == "" {
		return true
	}
	if address, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		address = address.Unmap()
		for _, network := range xrayPrivateNetworks {
			if network.Contains(address) {
				return true
			}
		}
		return false
	}
	if !strings.Contains(host, ".") {
		return true
	}
	for _, domain := range xrayPrivateDomains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func normalizeStreamForXrayVersion(stream map[string]any, useMethod, useSessionIDFields, knownVersion bool) {
	normalizeStreamTransportMethod(stream, useMethod)
	for _, key := range []string{"xhttpSettings", "splithttpSettings"} {
		settings := mapValue(stream[key])
		if len(settings) > 0 {
			normalizeXHTTPSessionFields(settings, useSessionIDFields, knownVersion)
		}
	}
}

func normalizeStreamTransportMethod(stream map[string]any, useMethod bool) {
	if len(stream) == 0 {
		return
	}
	transport := firstNonEmptyString(stream["method"], stream["network"])
	if transport == "" {
		return
	}
	if useMethod {
		stream["method"] = transport
		delete(stream, "network")
		return
	}
	stream["network"] = transport
	delete(stream, "method")
}

func normalizeXHTTPSessionFields(settings map[string]any, useSessionIDFields, knownVersion bool) {
	placement := firstNonEmptyString(settings["sessionIDPlacement"], settings["sessionPlacement"])
	key := firstNonEmptyString(settings["sessionIDKey"], settings["sessionKey"])
	table, hasTable := firstXHTTPAliasValue(settings, "sessionIDTable", "sessionTable")
	length, hasLength := firstXHTTPAliasValue(settings, "sessionIDLength", "sessionLength")
	if !knownVersion {
		if placement != "" {
			settings["sessionIDPlacement"] = placement
			settings["sessionPlacement"] = placement
		}
		if key != "" {
			settings["sessionIDKey"] = key
			settings["sessionKey"] = key
		}
		if hasTable {
			settings["sessionIDTable"] = table
			settings["sessionTable"] = table
		}
		if hasLength {
			settings["sessionIDLength"] = length
			settings["sessionLength"] = length
		}
		return
	}
	if useSessionIDFields {
		if placement != "" {
			settings["sessionIDPlacement"] = placement
		}
		if key != "" {
			settings["sessionIDKey"] = key
		}
		if hasTable {
			settings["sessionIDTable"] = table
		}
		if hasLength {
			settings["sessionIDLength"] = length
		}
		delete(settings, "sessionPlacement")
		delete(settings, "sessionKey")
		delete(settings, "sessionTable")
		delete(settings, "sessionLength")
		return
	}
	if placement != "" {
		settings["sessionPlacement"] = placement
	}
	if key != "" {
		settings["sessionKey"] = key
	}
	if hasTable {
		settings["sessionTable"] = table
	}
	if hasLength {
		settings["sessionLength"] = length
	}
	delete(settings, "sessionIDPlacement")
	delete(settings, "sessionIDKey")
	delete(settings, "sessionIDTable")
	delete(settings, "sessionIDLength")
}

func firstXHTTPAliasValue(settings map[string]any, current, legacy string) (any, bool) {
	if value, ok := settings[current]; ok && value != nil && strings.TrimSpace(stringValue(value)) != "" {
		return value, true
	}
	if value, ok := settings[legacy]; ok && value != nil && strings.TrimSpace(stringValue(value)) != "" {
		return value, true
	}
	return nil, false
}

func xrayVersionAtLeast(coreVersion string, wantMajor, wantMinor, wantPatch int) (bool, bool) {
	match := xrayCoreVersionPattern.FindStringSubmatch(coreVersion)
	if len(match) != 4 {
		return false, false
	}
	major, _ := strconv.Atoi(match[1])
	minor, _ := strconv.Atoi(match[2])
	patch, _ := strconv.Atoi(match[3])
	if major != wantMajor {
		return major > wantMajor, true
	}
	if minor != wantMinor {
		return minor > wantMinor, true
	}
	return patch >= wantPatch, true
}

func (c *Config) Raw() map[string]any {
	return deepCopyMap(c.raw)
}

func (c *Config) Runtime() map[string]any {
	return deepCopyMap(c.runtime)
}

func (c *Config) Inbounds() []ResolvedInbound {
	result := make([]ResolvedInbound, 0, len(c.inbounds))
	for _, inbound := range c.inbounds {
		result = append(result, deepCopyResolved(inbound))
	}
	return result
}

func (c *Config) InboundsByTag() map[string]ResolvedInbound {
	result := make(map[string]ResolvedInbound, len(c.byTag))
	for tag, inbound := range c.byTag {
		result[tag] = deepCopyResolved(inbound)
	}
	return result
}

func (c *Config) InboundsByProtocol() map[string][]ResolvedInbound {
	result := make(map[string][]ResolvedInbound, len(c.byProtocol))
	for protocol, inbounds := range c.byProtocol {
		result[protocol] = make([]ResolvedInbound, 0, len(inbounds))
		for _, inbound := range inbounds {
			result[protocol] = append(result[protocol], deepCopyResolved(inbound))
		}
	}
	return result
}

func (c *Config) GetInbound(tag string) (map[string]any, bool) {
	inbound := c.rawInbound(tag)
	if len(inbound) == 0 {
		return nil, false
	}
	return deepCopyMap(inbound), true
}

func IsManageableInbound(inbound map[string]any) bool {
	tag := stringValue(inbound["tag"])
	protocol := normalizeProxyProtocol(stringValue(inbound["protocol"]))
	if tag == "" || protocol == "" {
		return false
	}
	if !isManageableInboundProtocol(protocol) {
		return false
	}
	return true
}

func (c *Config) validate() error {
	inbounds := listOfMaps(c.raw["inbounds"])
	if len(inbounds) == 0 {
		return errors.New("config doesn't have inbounds")
	}
	outbounds := listOfMaps(c.raw["outbounds"])
	if len(outbounds) == 0 {
		return errors.New("config doesn't have outbounds")
	}

	seenInboundTags := map[string]struct{}{}
	for _, inbound := range inbounds {
		tag := stringValue(inbound["tag"])
		if tag == "" {
			return errors.New("all inbounds must have a unique tag")
		}
		if strings.Contains(tag, ",") {
			return errors.New("character «,» is not allowed in inbound tag")
		}
		if _, exists := seenInboundTags[tag]; exists {
			return fmt.Errorf("duplicate inbound tag: %s", tag)
		}
		seenInboundTags[tag] = struct{}{}
		if err := validateExecutableInbound(inbound); err != nil {
			return err
		}
	}

	seenOutboundTags := map[string]struct{}{}
	for _, outbound := range outbounds {
		tag := stringValue(outbound["tag"])
		if tag == "" {
			return errors.New("all outbounds must have a unique tag")
		}
		if _, exists := seenOutboundTags[tag]; exists {
			return fmt.Errorf("duplicate outbound tag: %s", tag)
		}
		seenOutboundTags[tag] = struct{}{}
	}
	return nil
}

func validateExecutableInbound(inbound map[string]any) error {
	tag := stringValue(inbound["tag"])
	protocol := normalizeProxyProtocol(stringValue(inbound["protocol"]))
	if isVirtualTunnelProtocol(protocol) {
		return validateVirtualTunnelInbound(tag, inbound)
	}
	if IsAuxiliaryInboundProtocol(protocol) {
		return validateAuxiliaryInbound(tag, protocol, inbound)
	}
	if _, ok := proxyProtocols[protocol]; !ok {
		return nil
	}
	if _, ok := inbound["port"]; !ok {
		return fmt.Errorf("invalid inbound %q: port is required", tag)
	}
	port, err := parseConfigPort(inbound["port"])
	if err != nil {
		return fmt.Errorf("invalid inbound %q: %w", tag, err)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid inbound %q: port must be between 1 and 65535", tag)
	}
	if protocol == "vless" {
		settings := mapValue(inbound["settings"])
		stream := mapValue(inbound["streamSettings"])
		flow := firstNonEmptyString(settings["flow"])

		if flow != "" {
			if flow != "xtls-rprx-vision" {
				return fmt.Errorf("invalid inbound %q: VLESS flow must be xtls-rprx-vision", tag)
			}
			network := streamNetwork(stream)
			security := strings.ToLower(strings.TrimSpace(stringValue(stream["security"])))

			hasEncryption := vlessEncryptionEnabled(settings["decryption"])

			networkSettings := mapValue(stream[networkSettingsKey(network)])
			headerType := strings.ToLower(stringValue(mapValue(networkSettings["header"])["type"]))
			isStandardFlowSupported := (security == "tls" || security == "reality") &&
				(network == "tcp" || network == "raw") &&
				headerType != "http"

			if !hasEncryption && !isStandardFlowSupported {
				return fmt.Errorf("invalid inbound %q: VLESS flow requires TCP with TLS/REALITY (without HTTP header) or VLESS Encryption", tag)
			}
		}
	}
	if protocol == "shadowsocks" {
		settings := mapValue(inbound["settings"])
		method := stringValue(settings["method"])
		if strings.HasPrefix(method, "2022-") {
			keyLength := map[string]int{
				"2022-blake3-aes-128-gcm":       16,
				"2022-blake3-aes-256-gcm":       32,
				"2022-blake3-chacha20-poly1305": 32,
			}[method]
			if keyLength == 0 {
				return fmt.Errorf("invalid inbound %q: unsupported multi-user Shadowsocks 2022 method %q", tag, method)
			}
			key, err := base64.StdEncoding.DecodeString(stringValue(settings["password"]))
			if err != nil || len(key) != keyLength {
				return fmt.Errorf("invalid inbound %q: Shadowsocks 2022 server password must be a base64-encoded %d-byte key", tag, keyLength)
			}
		}
	}

	stream := mapValue(inbound["streamSettings"])
	if len(stream) == 0 {
		return nil
	}
	network := streamNetwork(stream)
	if network == "" {
		network = "tcp"
	}
	if _, ok := validInboundNetworks[network]; !ok {
		return fmt.Errorf("invalid inbound %q: unsupported stream network %q", tag, network)
	}
	if protocol == "hysteria" && network != "hysteria" {
		return fmt.Errorf("invalid inbound %q: hysteria protocol requires hysteria stream network", tag)
	}
	networkSettings := mapValue(stream[networkSettingsKey(network)])
	if err := validateNetworkSettings(tag, network, networkSettings); err != nil {
		return err
	}

	security := strings.ToLower(strings.TrimSpace(stringValue(stream["security"])))
	switch security {
	case "", "none":
		if protocol == "hysteria" {
			return fmt.Errorf("invalid inbound %q: %s protocol requires TLS security", tag, strings.ToUpper(protocol))
		}
		return nil
	case "tls":
		return nil
	case "reality":
		return validateRealitySettings(tag, protocol, network, mapValue(stream["realitySettings"]))
	default:
		return fmt.Errorf("invalid inbound %q: unsupported stream security %q", tag, security)
	}
}

func validateAuxiliaryInbound(tag, protocol string, inbound map[string]any) error {
	port, err := parseConfigPort(inbound["port"])
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid inbound %q: port must be between 1 and 65535", tag)
	}
	settings := mapValue(inbound["settings"])
	switch protocol {
	case "ssh":
		limit := intValue(settings["user_limit"])
		if limit < 0 || limit > 64 {
			return fmt.Errorf("invalid inbound %q: SSH user limit must be between 0 and 64", tag)
		}
		idle := intValue(settings["idle_timeout"])
		if idle != 0 && (idle < 30 || idle > 86400) {
			return fmt.Errorf("invalid inbound %q: SSH idle timeout must be between 30 and 86400 seconds", tag)
		}
	case "mtproto":
		if err := validateProxySecret(settings["secret"], false); err != nil {
			return fmt.Errorf("invalid inbound %q: %w", tag, err)
		}
		publicHost := strings.TrimSpace(stringValue(settings["public_host"]))
		if net.ParseIP(publicHost) == nil && !isValidPublicHostname(strings.ToLower(publicHost)) {
			return fmt.Errorf("invalid inbound %q: MTProxy requires a public hostname or IP", tag)
		}
		classic, secure, fakeTLS := boolValue(settings["mode_classic"]), boolValue(settings["mode_secure"]), boolValue(settings["mode_tls"])
		if !classic && !secure && !fakeTLS {
			return fmt.Errorf("invalid inbound %q: at least one MTProxy connection mode is required", tag)
		}
		if fakeTLS && !isValidPublicHostname(strings.ToLower(strings.TrimSpace(stringValue(settings["tls_domain"])))) {
			return fmt.Errorf("invalid inbound %q: MTProxy FakeTLS requires a public TLS domain", tag)
		}
		if sponsor := strings.TrimSpace(stringValue(settings["sponsor_tag"])); sponsor != "" {
			if len(sponsor) != 32 {
				return fmt.Errorf("invalid inbound %q: MTProxy sponsor tag must contain 32 hexadecimal characters", tag)
			}
			if _, err := hex.DecodeString(sponsor); err != nil {
				return fmt.Errorf("invalid inbound %q: MTProxy sponsor tag must contain 32 hexadecimal characters", tag)
			}
		}
		limit := intValue(settings["user_limit"])
		if limit < 0 || limit > 64 {
			return fmt.Errorf("invalid inbound %q: MTProxy unique IP limit must be between 0 and 64", tag)
		}
		connections := intValue(settings["max_connections"])
		if connections < 0 || connections > 1000000 {
			return fmt.Errorf("invalid inbound %q: MTProxy maximum connections must be between 0 and 1000000", tag)
		}
	case "web":
		if port != 443 {
			return fmt.Errorf("invalid inbound %q: Telegram WEB proxy requires public port 443", tag)
		}
		hostname := strings.ToLower(strings.TrimSpace(stringValue(settings["hostname"])))
		if !isValidPublicHostname(hostname) {
			return fmt.Errorf("invalid inbound %q: Web proxy hostname must be a public DNS name", tag)
		}
		email := strings.TrimSpace(stringValue(settings["acme_email"]))
		if !strings.Contains(email, "@") || strings.ContainsAny(email, "\r\n") {
			return fmt.Errorf("invalid inbound %q: a valid ACME email is required", tag)
		}
		if err := validateProxySecret(settings["secret"], true); err != nil {
			return fmt.Errorf("invalid inbound %q: Web proxy %w", tag, err)
		}
		if upstream := strings.TrimSpace(stringValue(settings["site_upstream"])); upstream != "" {
			parsed, err := url.Parse(upstream)
			if err != nil || parsed.Scheme != "http" || parsed.Hostname() == "" || parsed.Port() == "" {
				return fmt.Errorf("invalid inbound %q: Web proxy site upstream must be a loopback HTTP URL with a port", tag)
			}
			ip := net.ParseIP(parsed.Hostname())
			if ip == nil || !ip.IsLoopback() {
				return fmt.Errorf("invalid inbound %q: Web proxy site upstream must use a numeric loopback address", tag)
			}
		}
	}
	return nil
}

func validateProxySecret(value any, allowDDPrefix bool) error {
	secret := strings.ToLower(strings.TrimSpace(stringValue(value)))
	if allowDDPrefix && strings.HasPrefix(secret, "dd") {
		secret = secret[2:]
	}
	if len(secret) != 32 {
		return fmt.Errorf("secret must contain 32 hexadecimal characters")
	}
	if _, err := hex.DecodeString(secret); err != nil {
		return fmt.Errorf("secret must contain 32 hexadecimal characters")
	}
	return nil
}

func isValidPublicHostname(value string) bool {
	if value == "" || len(value) > 253 || !strings.Contains(value, ".") || net.ParseIP(value) != nil {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func validateNetworkSettings(tag string, network string, settings map[string]any) error {
	switch network {
	case "ws":
		if path := strings.TrimSpace(stringValue(settings["path"])); path != "" && !strings.HasPrefix(path, "/") {
			return fmt.Errorf("invalid inbound %q: WebSocket path must start with /", tag)
		}
	case "httpupgrade":
		if path := strings.TrimSpace(stringValue(settings["path"])); path != "" && !strings.HasPrefix(path, "/") {
			return fmt.Errorf("invalid inbound %q: HTTPUpgrade path must start with /", tag)
		}
	case "splithttp", "xhttp":
		if path := strings.TrimSpace(stringValue(settings["path"])); path != "" && !strings.HasPrefix(path, "/") {
			return fmt.Errorf("invalid inbound %q: %s path must start with /", tag, network)
		}
		if err := validateInt32RangeSetting(tag, "xPaddingBytes", settings["xPaddingBytes"], true); err != nil {
			return err
		}
		if err := validateInt32RangeSetting(tag, "uplinkChunkSize", settings["uplinkChunkSize"], false); err != nil {
			return err
		}
		mode := strings.TrimSpace(stringValue(settings["mode"]))
		if mode == "" {
			mode = "auto"
		}
		if !oneOf(mode, "auto", "packet-up", "stream-up", "stream-one") {
			return fmt.Errorf("invalid inbound %q: unsupported XHTTP mode %q", tag, mode)
		}
		paddingPlacement := strings.TrimSpace(stringValue(settings["xPaddingPlacement"]))
		if paddingPlacement != "" && !oneOf(paddingPlacement, "queryInHeader", "query", "header", "cookie") {
			return fmt.Errorf("invalid inbound %q: unsupported xPaddingPlacement %q", tag, paddingPlacement)
		}
		paddingMethod := strings.TrimSpace(stringValue(settings["xPaddingMethod"]))
		if paddingMethod != "" && !oneOf(paddingMethod, "repeat-x", "tokenish") {
			return fmt.Errorf("invalid inbound %q: unsupported xPaddingMethod %q", tag, paddingMethod)
		}
		sessionPlacement := firstNonEmptyString(settings["sessionIDPlacement"], settings["sessionPlacement"])
		if sessionPlacement != "" && !oneOf(sessionPlacement, "path", "query", "header", "cookie") {
			return fmt.Errorf("invalid inbound %q: unsupported sessionIDPlacement %q", tag, sessionPlacement)
		}
		if err := validateXHTTPSessionID(tag, settings); err != nil {
			return err
		}
		seqPlacement := strings.TrimSpace(stringValue(settings["seqPlacement"]))
		if seqPlacement != "" && !oneOf(seqPlacement, "path", "query", "header", "cookie") {
			return fmt.Errorf("invalid inbound %q: unsupported seqPlacement %q", tag, seqPlacement)
		}
		uplinkDataPlacement := strings.TrimSpace(stringValue(settings["uplinkDataPlacement"]))
		if uplinkDataPlacement != "" && !oneOf(uplinkDataPlacement, "auto", "body", "header", "cookie") {
			return fmt.Errorf("invalid inbound %q: unsupported uplinkDataPlacement %q", tag, uplinkDataPlacement)
		}
		if oneOf(uplinkDataPlacement, "header", "cookie") && mode != "packet-up" {
			return fmt.Errorf("invalid inbound %q: uplinkDataPlacement %q requires packet-up mode", tag, uplinkDataPlacement)
		}
		method := strings.TrimSpace(stringValue(settings["uplinkHTTPMethod"]))
		if err := validateHTTPTokenSetting(tag, "uplinkHTTPMethod", method); err != nil {
			return err
		}
		if strings.EqualFold(method, "GET") && mode != "packet-up" {
			return fmt.Errorf("invalid inbound %q: uplinkHTTPMethod GET requires packet-up mode", tag)
		}
		for _, field := range []struct {
			name  string
			value any
		}{
			{"xPaddingKey", settings["xPaddingKey"]},
			{"xPaddingHeader", settings["xPaddingHeader"]},
			{"sessionIDKey", firstNonEmptyString(settings["sessionIDKey"], settings["sessionKey"])},
			{"seqKey", settings["seqKey"]},
			{"uplinkDataKey", settings["uplinkDataKey"]},
		} {
			if err := validateHTTPTokenSetting(tag, field.name, stringValue(field.value)); err != nil {
				return err
			}
		}
		if value, ok := settings["serverMaxHeaderBytes"]; ok && value != nil && stringValue(value) != "" {
			parsed, err := parseConfigInt32(value)
			if err != nil || parsed < 0 {
				return fmt.Errorf("invalid inbound %q: serverMaxHeaderBytes must be a non-negative 32-bit integer", tag)
			}
		}
	case "grpc", "gun":
		if value := strings.TrimSpace(stringValue(settings["serviceName"])); strings.Contains(value, "/") {
			return fmt.Errorf("invalid inbound %q: gRPC serviceName must not contain /", tag)
		}
	case "kcp":
		if err := validateMKCPNumber(tag, "mtu", settings["mtu"], 21, maxMKCPMTU); err != nil {
			return err
		}
		if err := validateMKCPNumber(tag, "tti", settings["tti"], 10, 5000); err != nil {
			return err
		}
	}
	return nil
}

func validateMKCPNumber(tag, field string, value any, minimum, maximum int64) error {
	if value == nil || strings.TrimSpace(stringValue(value)) == "" {
		return nil
	}
	parsed, err := strconv.ParseInt(strings.TrimSpace(stringValue(value)), 10, 64)
	if err != nil || parsed < minimum || parsed > maximum {
		return fmt.Errorf("invalid inbound %q: mKCP %s must be an integer between %d and %d", tag, field, minimum, maximum)
	}
	return nil
}

func validateInt32RangeSetting(tag string, key string, value any, requirePositive bool) error {
	text := strings.TrimSpace(stringValue(value))
	if text == "" {
		return nil
	}
	if !xPaddingBytesPattern.MatchString(text) {
		return fmt.Errorf("invalid inbound %q: %s must look like 100 or 100-1000", tag, key)
	}
	parts := strings.Split(text, "-")
	bounds := make([]int64, 0, len(parts))
	for _, part := range parts {
		parsed, err := strconv.ParseInt(part, 10, 32)
		if err != nil || (requirePositive && parsed <= 0) {
			return fmt.Errorf("invalid inbound %q: %s must use valid 32-bit integer values", tag, key)
		}
		bounds = append(bounds, parsed)
	}
	if len(bounds) == 2 && bounds[0] > bounds[1] {
		return fmt.Errorf("invalid inbound %q: %s range start must be less than or equal to end", tag, key)
	}
	return nil
}

func validateXHTTPSessionID(tag string, settings map[string]any) error {
	table := firstNonEmptyString(settings["sessionIDTable"], settings["sessionTable"])
	if table == "" {
		return nil
	}
	if predefined, ok := xhttpSessionTables[table]; ok {
		table = predefined
	}
	for index := 0; index < len(table); index++ {
		if table[index] >= 0x80 {
			return fmt.Errorf("invalid inbound %q: sessionIDTable must contain only ASCII characters", tag)
		}
	}
	minimum, maximum, err := parsePositiveInt32Range(firstNonEmptyString(settings["sessionIDLength"], settings["sessionLength"]))
	if err != nil {
		return fmt.Errorf("invalid inbound %q: sessionIDLength must be a positive integer or range", tag)
	}
	if !xhttpSessionRoomIsLargeEnough(len(table), minimum, maximum) {
		return fmt.Errorf("invalid inbound %q: sessionIDTable/sessionIDLength provide fewer than 2^31 possible IDs", tag)
	}
	return nil
}

func parsePositiveInt32Range(value any) (int64, int64, error) {
	text := strings.TrimSpace(stringValue(value))
	if text == "" || !xPaddingBytesPattern.MatchString(text) {
		return 0, 0, fmt.Errorf("invalid range")
	}
	parts := strings.Split(text, "-")
	minimum, err := strconv.ParseInt(parts[0], 10, 32)
	if err != nil || minimum <= 0 {
		return 0, 0, fmt.Errorf("invalid range")
	}
	maximum := minimum
	if len(parts) == 2 {
		maximum, err = strconv.ParseInt(parts[1], 10, 32)
		if err != nil || maximum < minimum {
			return 0, 0, fmt.Errorf("invalid range")
		}
	}
	return minimum, maximum, nil
}

func xhttpSessionRoomIsLargeEnough(tableSize int, minimum, maximum int64) bool {
	threshold := big.NewInt(2 << 30)
	if tableSize <= 0 || minimum <= 0 || maximum < minimum {
		return false
	}
	if tableSize == 1 {
		count := new(big.Int).SetInt64(maximum)
		count.Sub(count, big.NewInt(minimum))
		count.Add(count, big.NewInt(1))
		return count.Cmp(threshold) >= 0
	}
	base := big.NewInt(int64(tableSize))
	power := big.NewInt(1)
	for exponent := int64(0); exponent < minimum; exponent++ {
		power.Mul(power, base)
		if power.Cmp(threshold) >= 0 {
			return true
		}
	}
	room := new(big.Int)
	for exponent := minimum; exponent <= maximum; exponent++ {
		room.Add(room, power)
		if room.Cmp(threshold) >= 0 {
			return true
		}
		power.Mul(power, base)
	}
	return false
}

func validateHTTPTokenSetting(tag string, key string, value string) error {
	if value == "" {
		return nil
	}
	if !httpTokenPattern.MatchString(value) {
		return fmt.Errorf("invalid inbound %q: %s must be a valid HTTP token without spaces or line breaks", tag, key)
	}
	return nil
}

func parseConfigInt32(value any) (int64, error) {
	text := strings.TrimSpace(stringValue(value))
	if text == "" {
		return 0, fmt.Errorf("value is required")
	}
	return strconv.ParseInt(text, 10, 32)
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func validateRealitySettings(tag string, protocol string, network string, reality map[string]any) error {
	if protocol != "vless" && protocol != "trojan" {
		return fmt.Errorf("invalid inbound %q: REALITY is only supported for vless or trojan", tag)
	}
	switch network {
	case "tcp", "raw", "grpc", "gun", "http", "h2", "xhttp", "splithttp":
	default:
		return fmt.Errorf("invalid inbound %q: REALITY is not supported on %s network", tag, network)
	}
	if len(reality) == 0 {
		return fmt.Errorf("invalid inbound %q: realitySettings is required", tag)
	}
	settings := mapValue(reality["settings"])
	target := firstNonEmptyString(reality["target"], reality["dest"], settings["target"], settings["dest"])
	if err := validateHostPortTarget(target); err != nil {
		return fmt.Errorf("invalid inbound %q: realitySettings target %w", tag, err)
	}
	privateKey := firstNonEmptyString(reality["privateKey"], settings["privateKey"])
	if strings.TrimSpace(privateKey) == "" {
		return fmt.Errorf("invalid inbound %q: realitySettings privateKey is required", tag)
	}
	if _, err := normalizeRealityPrivateKey(privateKey); err != nil {
		return fmt.Errorf("invalid inbound %q: %w", tag, err)
	}
	serverNames := stringList(reality["serverNames"])
	if len(serverNames) == 0 {
		serverNames = nonEmptyStrings(firstNonEmptyString(reality["serverName"], settings["serverName"], settings["sni"]))
	}
	if len(serverNames) == 0 {
		return fmt.Errorf("invalid inbound %q: realitySettings serverNames is required", tag)
	}
	for _, serverName := range serverNames {
		if err := validateServerNameValue(serverName); err != nil {
			return fmt.Errorf("invalid inbound %q: realitySettings serverName %w", tag, err)
		}
	}
	shortIDs := stringList(reality["shortIds"])
	if len(shortIDs) == 0 {
		shortIDs = stringList(reality["shortId"])
	}
	if len(shortIDs) == 0 {
		shortIDs = stringList(settings["shortIds"])
		if len(shortIDs) == 0 {
			shortIDs = stringList(settings["shortId"])
		}
	}
	if len(shortIDs) == 0 {
		return fmt.Errorf("invalid inbound %q: realitySettings shortIds is required", tag)
	}
	for _, shortID := range shortIDs {
		clean := strings.TrimSpace(shortID)
		if !realityShortIDPattern.MatchString(clean) || len(clean)%2 != 0 {
			return fmt.Errorf("invalid inbound %q: realitySettings shortId must be even-length hex with 2-16 characters", tag)
		}
	}
	return nil
}

func validateHostPortTarget(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("is required and must be host:port, for example google.com:443")
	}
	if strings.Contains(value, "://") || strings.Contains(value, "/") {
		return fmt.Errorf("must be host:port without scheme or path")
	}
	host, portText, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("must be host:port, for example google.com:443")
	}
	if strings.TrimSpace(host) == "" {
		return fmt.Errorf("host is required")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

func validateServerNameValue(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("is required")
	}
	if strings.Contains(value, "://") || strings.Contains(value, "/") {
		return fmt.Errorf("must not include scheme or path")
	}
	if _, _, err := net.SplitHostPort(value); err == nil {
		return fmt.Errorf("must not include a port")
	}
	return nil
}

func parseConfigPort(value any) (int, error) {
	switch typed := value.(type) {
	case int:
		return typed, nil
	case int64:
		return int(typed), nil
	case float64:
		if typed != float64(int(typed)) {
			return 0, fmt.Errorf("port must be an integer")
		}
		return int(typed), nil
	case json.Number:
		parsed, err := typed.Int64()
		if err != nil {
			return 0, fmt.Errorf("port must be an integer")
		}
		return int(parsed), nil
	case string:
		text := strings.TrimSpace(typed)
		if text == "" {
			return 0, fmt.Errorf("port is required")
		}
		parsed, err := strconv.Atoi(text)
		if err != nil {
			return 0, fmt.Errorf("port must be a number")
		}
		return parsed, nil
	default:
		return 0, fmt.Errorf("port must be a number")
	}
}

func (c *Config) migrateDeprecated() {
	for _, inbound := range listOfMaps(c.raw["inbounds"]) {
		migrateStreamSettings(mapValue(inbound["streamSettings"]), c.useVerifyPeerCertByName())
	}
	for _, outbound := range listOfMaps(c.raw["outbounds"]) {
		migrateStreamSettings(mapValue(outbound["streamSettings"]), c.useVerifyPeerCertByName())
	}
}

func (c *Config) resolveInbounds() error {
	for _, inbound := range listOfMaps(c.raw["inbounds"]) {
		tag := stringValue(inbound["tag"])
		protocol := normalizeProxyProtocol(stringValue(inbound["protocol"]))
		if tag == "" || protocol == "" {
			continue
		}
		if !isManageableInboundProtocol(protocol) {
			continue
		}
		resolved, err := c.resolveInbound(inbound)
		if err != nil {
			return err
		}
		c.inbounds = append(c.inbounds, resolved)
		c.byTag[tag] = resolved
		c.byProtocol[protocol] = append(c.byProtocol[protocol], resolved)
	}
	return nil
}

func (c *Config) resolveInbound(inbound map[string]any) (ResolvedInbound, error) {
	tag := stringValue(inbound["tag"])
	protocol := normalizeProxyProtocol(stringValue(inbound["protocol"]))
	resolved := ResolvedInbound{
		"tag":         tag,
		"protocol":    protocol,
		"port":        nil,
		"network":     "tcp",
		"tls":         "none",
		"sni":         []string{},
		"host":        []string{},
		"path":        "",
		"header_type": "",
		"flow":        "",
		"is_fallback": false,
	}

	settings := mapValue(inbound["settings"])
	if _, ok := inbound["port"]; ok {
		resolved["port"] = inbound["port"]
	}
	if protocol == "vless" {
		if encryption := firstNonEmptyString(settings["encryption"]); encryption != "" {
			resolved["encryption"] = encryption
		}
		if flow := firstNonEmptyString(settings["flow"]); flow != "" {
			resolved["flow"] = flow
		}
	}
	if protocol == "shadowsocks" {
		resolved["settings"] = settings
	}

	if isVirtualTunnelProtocol(protocol) {
		applyVirtualTunnelResolvedSettings(resolved, inbound)
		return resolved, nil
	}
	if IsAuxiliaryInboundProtocol(protocol) {
		resolved["settings"] = settings
		resolved["network"] = "tcp"
		if protocol == "web" {
			resolved["tls"] = "tls"
			resolved["sni"] = []string{stringValue(settings["hostname"])}
		}
		return resolved, nil
	}

	stream := mapValue(inbound["streamSettings"])
	if len(stream) == 0 {
		return resolved, nil
	}
	network := streamNetwork(stream)
	networkSettings := mapValue(stream[networkSettingsKey(network)])
	security := strings.ToLower(stringValue(stream["security"]))
	securitySettings := mapValue(stream[security+"Settings"])
	securityMeta := mapValue(securitySettings["settings"])

	resolved["network"] = network

	switch security {
	case "tls":
		resolved["tls"] = "tls"
		if fp := firstNonEmptyString(securityMeta["fingerprint"], securitySettings["fingerprint"]); fp != "" {
			resolved["fp"] = fp
		}
		if allow, ok := firstPresent(securityMeta, securitySettings, "allowInsecure"); ok {
			resolved["ais"] = boolValue(allow)
			resolved["allowinsecure"] = boolValue(allow)
		}
		if alpn := joinStringList(securitySettings["alpn"]); alpn != "" {
			resolved["alpn"] = alpn
		}
		if sni := firstNonEmptyString(securitySettings["serverName"], securitySettings["sni"], securityMeta["serverName"], securityMeta["sni"]); sni != "" {
			resolved["sni"] = []string{sni}
		}
	case "reality":
		resolved["tls"] = "reality"
		resolved["fp"] = firstNonEmptyString(securityMeta["fingerprint"], securitySettings["fingerprint"], "chrome")
		sni := stringList(securitySettings["serverNames"])
		if len(sni) == 0 {
			sni = nonEmptyStrings(firstNonEmptyString(securityMeta["serverName"], securitySettings["serverName"], securityMeta["sni"], securitySettings["sni"]))
		}
		resolved["sni"] = sni
		pbk := firstNonEmptyString(securityMeta["publicKey"], securitySettings["publicKey"], securityMeta["public_key"], securitySettings["public_key"])
		if pbk == "" {
			privateKey := firstNonEmptyString(securitySettings["privateKey"], securityMeta["privateKey"])
			if privateKey == "" {
				return nil, fmt.Errorf("You need to provide privateKey in realitySettings of %s", tag)
			}
			derived, err := DeriveRealityPublicKey(privateKey)
			if err != nil {
				return nil, fmt.Errorf("Invalid privateKey in realitySettings of %s: %w", tag, err)
			}
			pbk = derived
		}
		resolved["pbk"] = pbk
		sids := stringList(securitySettings["shortIds"])
		if len(sids) == 0 {
			sids = stringList(securitySettings["shortId"])
		}
		if len(sids) == 0 {
			sids = stringList(securityMeta["shortIds"])
		}
		if len(sids) == 0 {
			sids = stringList(securityMeta["shortId"])
		}
		resolved["sids"] = sids
		if len(sids) > 0 {
			resolved["sid"] = sids[0]
		}
		resolved["spx"] = firstNonEmptyString(securityMeta["spiderX"], securitySettings["SpiderX"], securitySettings["spiderX"])
	}

	if err := applyNetworkSettings(resolved, network, networkSettings); err != nil {
		return nil, fmt.Errorf("Settings of %s %s", tag, err)
	}
	return resolved, nil
}

func (c *Config) runtimePayload() map[string]any {
	runtime := TranslateVirtualTunnelInboundsForRuntime(c.raw)
	runtime["api"] = map[string]any{
		"services": []any{"HandlerService", "StatsService", "LoggerService"},
		"tag":      "API",
	}
	runtime["stats"] = map[string]any{}
	mergePolicy(runtime)
	ensureAPIInbound(runtime, c.options.APIHost, c.options.APIPort)
	ensureAPIRoutingRule(runtime)
	return runtime
}

func (c *Config) rawInbound(tag string) map[string]any {
	if strings.TrimSpace(tag) == "" {
		return nil
	}
	for _, inbound := range listOfMaps(c.raw["inbounds"]) {
		if stringValue(inbound["tag"]) == tag {
			return inbound
		}
	}
	return nil
}

func (c *Config) useVerifyPeerCertByName() bool {
	if c.options.UseVerifyPeerCertByName == nil {
		return true
	}
	return *c.options.UseVerifyPeerCertByName
}

func normalizeOptions(opts Options) Options {
	if strings.TrimSpace(opts.APIHost) == "" {
		opts.APIHost = DefaultAPIHost
	}
	if opts.APIPort <= 0 {
		opts.APIPort = DefaultAPIPort
	}
	return opts
}

func mapInput(input any) (map[string]any, error) {
	switch typed := input.(type) {
	case nil:
		return map[string]any{}, nil
	case map[string]any:
		return deepCopyMap(typed), nil
	case []byte:
		return jsonMapStrict(typed)
	case string:
		return jsonMapStrict([]byte(typed))
	default:
		raw, err := json.Marshal(typed)
		if err != nil {
			return nil, err
		}
		return jsonMapStrict(raw)
	}
}

func jsonMapStrict(raw []byte) (map[string]any, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return map[string]any{}, nil
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, err
	}
	if result == nil {
		return map[string]any{}, nil
	}
	return result, nil
}

func normalizeLogCleanupInterval(value any) int {
	parsed := intValue(value)
	switch parsed {
	case 0, 3600, 10800, 21600, 86400:
		return parsed
	default:
		return 0
	}
}

func migrateStreamSettings(stream map[string]any, useVerifyPeerCertByName bool) {
	if len(stream) == 0 {
		return
	}
	switch streamNetwork(stream) {
	case "ws":
		ws := mapValue(stream["wsSettings"])
		headers := mapValue(ws["headers"])
		if host := stringValue(headers["Host"]); host != "" && stringValue(ws["host"]) == "" {
			ws["host"] = host
			delete(headers, "Host")
			if len(headers) == 0 {
				delete(ws, "headers")
			} else {
				ws["headers"] = headers
			}
			stream["wsSettings"] = ws
		}
	case "tcp", "raw":
		key := networkSettingsKey(streamNetwork(stream))
		tcp := mapValue(stream[key])
		header := mapValue(tcp["header"])
		request := mapValue(header["request"])
		headers := mapValue(request["headers"])
		if host := stringValue(headers["Host"]); host != "" {
			headers["Host"] = []any{host}
			request["headers"] = headers
			header["request"] = request
			tcp["header"] = header
			stream[key] = tcp
		}
	}
	if tlsSettings := mapValue(stream["tlsSettings"]); len(tlsSettings) > 0 {
		stream["tlsSettings"] = normalizeTLSVerifyPeerFields(tlsSettings, useVerifyPeerCertByName)
	}
}

func streamNetwork(stream map[string]any) string {
	return normalizeNetwork(firstNonEmptyString(stream["method"], stream["network"]))
}

func normalizeRemovedTLSFields(stream map[string]any, preserveMetadata bool) {
	if len(stream) == 0 {
		return
	}
	tlsSettings := mapValue(stream["tlsSettings"])
	if len(tlsSettings) == 0 {
		return
	}
	if allow, exists := tlsSettings["allowInsecure"]; exists {
		metadata := mapValue(tlsSettings["settings"])
		if _, configured := metadata["allowInsecure"]; !configured {
			metadata["allowInsecure"] = allow
		}
		tlsSettings["settings"] = metadata
	}
	delete(tlsSettings, "allowInsecure")
	delete(tlsSettings, "echForceQuery")

	if oldNames := stringList(tlsSettings["verifyPeerCertInNames"]); stringValue(tlsSettings["verifyPeerCertByName"]) == "" && len(oldNames) > 0 {
		tlsSettings["verifyPeerCertByName"] = strings.Join(oldNames, ",")
	}
	delete(tlsSettings, "verifyPeerCertInNames")
	if preserveMetadata {
		stream["tlsSettings"] = tlsSettings
		return
	}

	legacySettings := mapValue(tlsSettings["settings"])
	for _, key := range []string{"fingerprint", "echConfigList", "pinnedPeerCertSha256", "verifyPeerCertByName"} {
		if _, exists := tlsSettings[key]; !exists {
			if value, ok := legacySettings[key]; ok {
				tlsSettings[key] = value
			}
		}
		delete(legacySettings, key)
	}
	if len(legacySettings) == 0 {
		delete(tlsSettings, "settings")
	} else {
		tlsSettings["settings"] = legacySettings
	}
	stream["tlsSettings"] = tlsSettings
}

func normalizeTLSVerifyPeerFields(settings map[string]any, useVerifyPeerCertByName bool) map[string]any {
	normalized := deepCopyMap(settings)
	byName := firstNonEmptyString(normalized["verifyPeerCertByName"])
	inNames := stringList(normalized["verifyPeerCertInNames"])
	if byName == "" && len(inNames) > 0 {
		byName = inNames[0]
	}
	if len(inNames) == 0 && byName != "" {
		inNames = []string{byName}
	}
	if useVerifyPeerCertByName {
		if byName != "" {
			normalized["verifyPeerCertByName"] = byName
		} else {
			delete(normalized, "verifyPeerCertByName")
		}
		delete(normalized, "verifyPeerCertInNames")
		return normalized
	}
	if len(inNames) > 0 {
		normalized["verifyPeerCertInNames"] = inNames
	} else {
		delete(normalized, "verifyPeerCertInNames")
	}
	delete(normalized, "verifyPeerCertByName")
	return normalized
}

func applyNetworkSettings(resolved ResolvedInbound, network string, settings map[string]any) error {
	switch network {
	case "tcp", "raw":
		header := mapValue(settings["header"])
		request := mapValue(header["request"])
		pathRaw := request["path"]
		headers := mapValue(request["headers"])
		hostRaw := headers["Host"]
		resolved["header_type"] = stringValue(header["type"])
		if isString(pathRaw) || isString(hostRaw) {
			return errors.New("for path and host must be list, not str")
		}
		resolved["path"] = firstStringList(pathRaw)
		resolved["host"] = stringList(hostRaw)
	case "ws":
		pathRaw := settings["path"]
		hostRaw := firstNonEmptyString(settings["host"])
		headers := mapValue(settings["headers"])
		if hostRaw == "" {
			hostRaw = firstNonEmptyString(headers["Host"])
		}
		if isList(pathRaw) || isList(settings["host"]) || isList(headers["Host"]) {
			return errors.New("for path and host must be str, not list")
		}
		resolved["header_type"] = ""
		resolved["path"] = stringValue(pathRaw)
		resolved["host"] = nonEmptyStrings(hostRaw)
		copyOptional(resolved, "heartbeatPeriod", settings)
	case "grpc", "gun":
		resolved["header_type"] = ""
		resolved["path"] = stringValue(settings["serviceName"])
		resolved["host"] = nonEmptyStrings(stringValue(settings["authority"]))
		copyOptional(resolved, "multiMode", settings)
	case "quic":
		header := mapValue(settings["header"])
		resolved["header_type"] = stringValue(header["type"])
		resolved["path"] = stringValue(settings["key"])
		resolved["host"] = nonEmptyStrings(stringValue(settings["security"]))
	case "httpupgrade":
		resolved["path"] = stringValue(settings["path"])
		resolved["host"] = stringList(settings["host"])
	case "splithttp", "xhttp":
		resolved["path"] = stringValue(settings["path"])
		resolved["host"] = stringList(settings["host"])
		for _, key := range []string{
			"scMaxBufferedPosts", "scMaxEachPostBytes", "scMaxConcurrentPosts", "scMinPostsIntervalMs",
			"scStreamUpServerSecs", "xPaddingBytes", "noSSEHeader", "xmux", "mode", "noGRPCHeader",
			"keepAlivePeriod", "xPaddingObfsMode", "xPaddingKey", "xPaddingHeader", "xPaddingPlacement",
			"xPaddingMethod", "uplinkHTTPMethod", "seqPlacement",
			"seqKey", "uplinkDataPlacement", "uplinkDataKey", "uplinkChunkSize", "serverMaxHeaderBytes",
		} {
			copyOptional(resolved, key, settings)
		}
		copyOptionalAlias(resolved, "sessionIDPlacement", settings, "sessionPlacement")
		copyOptionalAlias(resolved, "sessionIDKey", settings, "sessionKey")
	case "kcp":
		header := mapValue(settings["header"])
		resolved["header_type"] = stringValue(header["type"])
		resolved["path"] = stringValue(settings["seed"])
		resolved["host"] = nonEmptyStrings(stringValue(header["domain"]))
	case "http", "h2", "h3":
		resolved["path"] = stringValue(settings["path"])
		resolved["host"] = stringList(settings["host"])
	default:
		resolved["path"] = stringValue(settings["path"])
		host := settings["host"]
		if stringValue(host) == "" {
			host = settings["Host"]
		}
		if isList(host) {
			resolved["host"] = firstStringList(host)
		} else if text := stringValue(host); text != "" {
			resolved["host"] = text
		}
	}
	return nil
}

func mergePolicy(runtime map[string]any) {
	current := mapValue(runtime["policy"])
	system := mapValue(current["system"])
	systemDefaults := map[string]any{
		"statsOutboundDownlink": true,
		"statsOutboundUplink":   true,
	}
	if _, ok := system["statsInboundDownlink"]; !ok {
		systemDefaults["statsInboundDownlink"] = true
	}
	if _, ok := system["statsInboundUplink"]; !ok {
		systemDefaults["statsInboundUplink"] = true
	}
	forced := map[string]any{
		"levels": map[string]any{"0": map[string]any{
			"statsUserUplink":   true,
			"statsUserDownlink": true,
			"statsUserOnline":   true,
		}},
		"system": systemDefaults,
	}
	runtime["policy"] = mergeMaps(current, forced)
}

func ensureAPIInbound(runtime map[string]any, host string, port int) {
	inbounds := listOfMaps(runtime["inbounds"])
	for _, inbound := range inbounds {
		if stringValue(inbound["tag"]) != "API_INBOUND" {
			continue
		}
		if listen := mapValue(inbound["listen"]); len(listen) > 0 {
			listen["address"] = host
			inbound["listen"] = listen
		} else {
			inbound["listen"] = host
		}
		inbound["port"] = port
		inbound["protocol"] = "tunnel"
		settings := mapValue(inbound["settings"])
		delete(settings, "address")
		settings["allowedNetwork"] = "tcp"
		settings["rewriteAddress"] = host
		inbound["settings"] = settings
		runtime["inbounds"] = mapsToAnySlice(inbounds)
		return
	}
	apiInbound := map[string]any{
		"listen":   host,
		"port":     port,
		"protocol": "tunnel",
		"settings": map[string]any{
			"allowedNetwork": "tcp",
			"rewriteAddress": host,
		},
		"tag": "API_INBOUND",
	}
	anyInbounds := mapsToAnySlice(inbounds)
	runtime["inbounds"] = append([]any{apiInbound}, anyInbounds...)
}

func ensureAPIRoutingRule(runtime map[string]any) {
	routing := mapValue(runtime["routing"])
	rules, ok := routing["rules"].([]any)
	if !ok {
		rules = []any{}
	}
	for _, item := range rules {
		rule := mapValue(item)
		if stringValue(rule["type"]) != "field" || stringValue(rule["outboundTag"]) != "API" {
			continue
		}
		for _, tag := range stringList(rule["inboundTag"]) {
			if tag == "API_INBOUND" {
				routing["rules"] = rules
				runtime["routing"] = routing
				return
			}
		}
	}
	apiRule := map[string]any{"inboundTag": []any{"API_INBOUND"}, "outboundTag": "API", "type": "field"}
	routing["rules"] = append([]any{apiRule}, rules...)
	runtime["routing"] = routing
}

func mergeMaps(left, right map[string]any) map[string]any {
	result := deepCopyMap(left)
	for key, value := range right {
		if valueMap := mapValue(value); len(valueMap) > 0 {
			if existing := mapValue(result[key]); len(existing) > 0 {
				result[key] = mergeMaps(existing, valueMap)
				continue
			}
		}
		result[key] = value
	}
	return result
}

func mapsToAnySlice(items []map[string]any) []any {
	result := make([]any, 0, len(items))
	for _, item := range items {
		result = append(result, item)
	}
	return result
}

func networkSettingsKey(network string) string {
	switch network {
	case "raw":
		return "rawSettings"
	case "gun":
		return "grpcSettings"
	case "h2":
		return "h2Settings"
	case "h3":
		return "h3Settings"
	default:
		return network + "Settings"
	}
}

func normalizeNetwork(value string) string {
	cleaned := strings.ToLower(strings.TrimSpace(value))
	if cleaned == "" {
		return "tcp"
	}
	return cleaned
}

func normalizeProxyProtocol(value string) string {
	cleaned := strings.ToLower(strings.TrimSpace(value))
	if cleaned == "ss" {
		return "shadowsocks"
	}
	return cleaned
}

func copyOptional(target map[string]any, key string, source map[string]any) {
	if value, ok := source[key]; ok {
		target[key] = value
	}
}

func copyOptionalAlias(target map[string]any, key string, source map[string]any, aliases ...string) {
	if value, ok := source[key]; ok {
		target[key] = value
		return
	}
	for _, alias := range aliases {
		if value, ok := source[alias]; ok {
			target[key] = value
			return
		}
	}
}

func firstPresent(first, second map[string]any, key string) (any, bool) {
	if value, ok := first[key]; ok {
		return value, true
	}
	value, ok := second[key]
	return value, ok
}

func containsString(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func isString(value any) bool {
	_, ok := value.(string)
	return ok
}

func isList(value any) bool {
	switch value.(type) {
	case []any, []string:
		return true
	default:
		return false
	}
}

func listOfMaps(value any) []map[string]any {
	switch typed := value.(type) {
	case []map[string]any:
		return typed
	case []any:
		result := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			if mapped := mapValue(item); len(mapped) > 0 {
				result = append(result, mapped)
			}
		}
		return result
	default:
		return nil
	}
}

func mapValue(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case map[string]string:
		result := make(map[string]any, len(typed))
		for key, value := range typed {
			result[key] = value
		}
		return result
	default:
		return map[string]any{}
	}
}

func stringList(value any) []string {
	switch typed := value.(type) {
	case []string:
		return typed
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			if text := stringValue(item); text != "" {
				result = append(result, text)
			}
		}
		return result
	case string:
		cleaned := strings.TrimSpace(typed)
		if cleaned == "" {
			return nil
		}
		parts := strings.Split(cleaned, ",")
		result := make([]string, 0, len(parts))
		for _, part := range parts {
			if text := strings.TrimSpace(part); text != "" {
				result = append(result, text)
			}
		}
		return result
	default:
		if text := stringValue(value); text != "" {
			return []string{text}
		}
		return nil
	}
}

func nonEmptyStrings(values ...string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value != "" {
			result = append(result, value)
		}
	}
	return result
}

func firstStringList(value any) string {
	values := stringList(value)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func joinStringList(value any) string {
	values := stringList(value)
	if len(values) == 0 {
		return ""
	}
	return strings.Join(values, ",")
}

func firstNonEmptyString(values ...any) string {
	for _, value := range values {
		if text := stringValue(value); text != "" {
			return text
		}
	}
	return ""
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(typed)
	case []byte:
		return strings.TrimSpace(string(typed))
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case float64:
		if float64(int64(typed)) == typed {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	default:
		return strings.TrimSpace(fmt.Sprint(typed))
	}
}

func boolValue(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		cleaned := strings.ToLower(strings.TrimSpace(typed))
		return cleaned == "true" || cleaned == "1" || cleaned == "yes"
	case int:
		return typed != 0
	case int64:
		return typed != 0
	case float64:
		return typed != 0
	default:
		return false
	}
}

func intValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case string:
		parsed, _ := strconv.Atoi(strings.TrimSpace(typed))
		return parsed
	default:
		return 0
	}
}

func deepCopyMap(source map[string]any) map[string]any {
	if source == nil {
		return map[string]any{}
	}
	raw, err := json.Marshal(source)
	if err != nil {
		result := make(map[string]any, len(source))
		for key, value := range source {
			result[key] = value
		}
		return result
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil || result == nil {
		return map[string]any{}
	}
	return result
}

func deepCopyResolved(source ResolvedInbound) ResolvedInbound {
	raw, _ := json.Marshal(source)
	var result ResolvedInbound
	if err := json.Unmarshal(raw, &result); err != nil || result == nil {
		result = ResolvedInbound{}
		for key, value := range source {
			result[key] = value
		}
	}
	return result
}
