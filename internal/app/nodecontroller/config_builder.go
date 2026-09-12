package nodecontroller

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"strings"

	"github.com/rebeccapanel/rebecca/internal/app/logging"
	userread "github.com/rebeccapanel/rebecca/internal/app/user"
	"github.com/rebeccapanel/rebecca/internal/app/xrayconfig"
)

var proxyProtocols = map[string]struct{}{
	"vmess":       {},
	"vless":       {},
	"trojan":      {},
	"shadowsocks": {},
	"hysteria":    {},
	"ssh":         {},
}

type runtimeUserRow struct {
	ID            int64
	Username      string
	CredentialKey string
	Flow          string
	ServiceID     sql.NullInt64
	Protocol      string
	Settings      map[string]any
}

type runtimeUserIdentity struct {
	ID       int64
	Username string
}

type runtimeConfigData struct {
	users        []runtimeUserRow
	serviceTags  map[int64]map[string]bool
	serviceFlows map[int64]string
	masks        map[string][]byte
}

type preparedRuntimeConfig struct {
	nodeID           int64
	userSyncDecided  bool
	userSyncRequired bool
	configJSON       string
	ovRuntimeJSON    string
}

func (p *preparedRuntimeConfig) userSyncDecision(nodeID int64) (bool, bool) {
	if p == nil || p.nodeID != nodeID || !p.userSyncDecided {
		return false, false
	}
	return p.userSyncRequired, true
}

func (c Controller) runtimeInbounds(ctx context.Context) ([]map[string]any, error) {
	return xrayconfig.NewRepository(c.repo.db, c.repo.dialect, xrayconfig.Options{}).FullInbounds(ctx)
}

func (c Controller) prepareRuntimeConfigOperation(ctx context.Context, operation OperationRow) (*preparedRuntimeConfig, error) {
	if !operation.NodeID.Valid {
		return nil, nil
	}
	switch operation.OperationType {
	case "sync_config", "add_user", "update_user", "remove_user", "disable_user", "enable_user":
	default:
		return nil, nil
	}
	var payload operationPayload
	if len(operation.Payload) > 0 {
		if err := json.Unmarshal(operation.Payload, &payload); err != nil {
			return nil, err
		}
	}
	node, err := c.repo.Node(ctx, operation.NodeID.Int64)
	if err != nil {
		return nil, err
	}
	if node.Status == "disabled" || node.Status == "limited" {
		return nil, nil
	}
	unlock, err := c.lockRuntimeConfigPreparation(ctx)
	if err != nil {
		return nil, err
	}
	defer unlock()
	prepared := &preparedRuntimeConfig{nodeID: node.ID}
	var inbounds []map[string]any
	if isRuntimeUserOperation(operation.OperationType) {
		required, loadedInbounds, err := c.userOperationConfigSyncDecision(ctx, node, operation)
		if err != nil {
			return nil, err
		}
		inbounds = loadedInbounds
		if !required && (operation.OperationType == "remove_user" || operation.OperationType == "disable_user") {
			_, err = c.legacyOperationEmail(ctx, operation)
			required = err != nil
		}
		prepared.userSyncDecided = true
		prepared.userSyncRequired = required
		if !required {
			return prepared, nil
		}
	}
	if inbounds == nil {
		inbounds, err = c.runtimeInbounds(ctx)
		if err != nil {
			return nil, err
		}
	}
	configJSON := strings.TrimSpace(payload.ConfigJSON)
	if configJSON == "" {
		configJSON, err = c.buildRuntimeConfig(ctx, node)
		if err != nil {
			return nil, err
		}
	}
	runtimeReq, err := c.runtimeConfigRequestFromInbounds(ctx, node, "prepare", configJSON, inbounds)
	if err != nil {
		return nil, err
	}
	prepared.configJSON = configJSON
	prepared.ovRuntimeJSON = runtimeReq.GetOvRuntimeJson()
	return prepared, nil
}

func (c Controller) buildRuntimeConfig(ctx context.Context, node NodeRow) (string, error) {
	return c.buildRuntimeConfigWithData(ctx, node, nil)
}

func (c Controller) buildRuntimeConfigWithData(ctx context.Context, node NodeRow, data *runtimeConfigData) (string, error) {
	raw, err := c.repo.NodeRawConfig(ctx, node)
	if err != nil {
		return "", err
	}
	if merged, err := c.outboundSubs.MergeActiveIntoConfig(ctx, raw); err == nil {
		raw = merged
	}
	raw = xrayconfig.NormalizePayload(raw)
	raw = mergeNodeVirtualTunnelConfig(raw, node.XrayConfig)
	raw = xrayconfig.TranslateVirtualTunnelInboundsForRuntime(raw)
	raw, compatibilityWarning := xrayconfig.NormalizePayloadForXrayVersion(raw, node.XrayVersion)
	if compatibilityWarning != "" {
		logging.Warnf(logging.ComponentNode, "node=%d %s", node.ID, compatibilityWarning)
	}
	if err := inlineTLSCertificateFiles(raw); err != nil {
		return "", err
	}
	if err := c.includeDBUsers(ctx, raw, data); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func mergeNodeVirtualTunnelConfig(raw map[string]any, nodeConfig json.RawMessage) map[string]any {
	if len(nodeConfig) == 0 {
		return raw
	}
	nodeRaw := jsonMap(nodeConfig)
	if len(nodeRaw) == 0 {
		return raw
	}
	nodeVirtualInbounds := []map[string]any{}
	nodeVirtualTags := map[string]struct{}{}
	existingTags := map[string]struct{}{}
	for _, inbound := range listOfMaps(raw["inbounds"]) {
		if tag := stringValue(inbound["tag"]); tag != "" {
			existingTags[tag] = struct{}{}
		}
	}
	for _, inbound := range listOfMaps(nodeRaw["inbounds"]) {
		protocol := strings.ToLower(stringValue(inbound["protocol"]))
		if !xrayconfig.IsVirtualTunnelInboundProtocol(protocol) {
			continue
		}
		tag := stringValue(inbound["tag"])
		if tag == "" {
			continue
		}
		nodeVirtualTags[tag] = struct{}{}
		if _, exists := existingTags[tag]; exists {
			continue
		}
		nodeVirtualInbounds = append(nodeVirtualInbounds, inbound)
		existingTags[tag] = struct{}{}
	}
	if len(nodeVirtualInbounds) == 0 && len(nodeVirtualTags) == 0 {
		return raw
	}
	inbounds := interfaceSlice(raw["inbounds"])
	for _, inbound := range nodeVirtualInbounds {
		inbounds = append(inbounds, inbound)
	}
	raw["inbounds"] = inbounds

	nodeRules := interfaceSlice(mapValue(nodeRaw["routing"])["rules"])
	if len(nodeRules) == 0 {
		return raw
	}
	routing := ensureMap(raw, "routing")
	rules := interfaceSlice(routing["rules"])
	seenRules := map[string]struct{}{}
	for _, rule := range rules {
		if encoded, err := json.Marshal(rule); err == nil {
			seenRules[string(encoded)] = struct{}{}
		}
	}
	for _, item := range nodeRules {
		rule := mapValue(item)
		if len(rule) == 0 || !ruleReferencesAnyInbound(rule, nodeVirtualTags) {
			continue
		}
		encoded, err := json.Marshal(rule)
		if err == nil {
			if _, exists := seenRules[string(encoded)]; exists {
				continue
			}
			seenRules[string(encoded)] = struct{}{}
		}
		rules = append(rules, rule)
	}
	routing["rules"] = rules
	return raw
}

func ruleReferencesAnyInbound(rule map[string]any, tags map[string]struct{}) bool {
	if len(tags) == 0 {
		return false
	}
	for _, item := range interfaceSlice(rule["inboundTag"]) {
		if _, ok := tags[stringValue(item)]; ok {
			return true
		}
	}
	return false
}

func (c Controller) includeDBUsers(ctx context.Context, raw map[string]any, data *runtimeConfigData) error {
	inbounds := listOfMaps(raw["inbounds"])
	inboundsByProtocol := map[string][]map[string]any{}
	for _, inbound := range inbounds {
		protocol := strings.ToLower(stringValue(inbound["protocol"]))
		if _, ok := proxyProtocols[protocol]; !ok {
			continue
		}
		settings := ensureMap(inbound, "settings")
		settings["clients"] = xrayconfig.ReverseClients(settings["clients"])
		inboundsByProtocol[protocol] = append(inboundsByProtocol[protocol], inbound)
	}
	if len(inboundsByProtocol) == 0 {
		return nil
	}

	if data == nil {
		protocols := make([]string, 0, len(inboundsByProtocol))
		for protocol := range inboundsByProtocol {
			protocols = append(protocols, protocol)
		}
		loaded, err := c.loadRuntimeConfigDataForProtocols(ctx, protocols)
		if err != nil {
			return err
		}
		data = loaded
	}

	for _, user := range data.users {
		if !user.ServiceID.Valid || user.ServiceID.Int64 <= 0 {
			continue
		}
		targets := inboundsByProtocol[user.Protocol]
		if len(targets) == 0 {
			continue
		}
		flow := user.Flow
		if data.serviceFlows != nil {
			if serviceFlow, ok := data.serviceFlows[user.ServiceID.Int64]; ok {
				flow = serviceFlow
			}
		}
		baseSettings, err := userread.RuntimeProxySettings(user.Settings, user.Protocol, user.CredentialKey, flow, data.masks)
		if err != nil {
			continue
		}
		for _, inbound := range targets {
			tag := stringValue(inbound["tag"])
			if !data.serviceTags[user.ServiceID.Int64][tag] {
				continue
			}
			settings := maps.Clone(baseSettings)
			if user.Protocol == "shadowsocks" {
				settings = userread.RuntimeShadowsocksSettings(baseSettings, ensureMap(inbound, "settings"))
			}
			if flow := stringValue(settings["flow"]); flow != "" && !flowSupportedForInbound(inbound) {
				delete(settings, "flow")
			}
			settings["email"] = inboundRuntimeUserEmail(user.ID, user.Username, tag)
			clients := ensureMap(inbound, "settings")["clients"].([]any)
			ensureMap(inbound, "settings")["clients"] = append(clients, settings)
		}
	}
	return nil
}

func (c Controller) userOperationRequiresConfigSync(ctx context.Context, node NodeRow, operation OperationRow) (bool, error) {
	required, _, err := c.userOperationConfigSyncDecision(ctx, node, operation)
	return required, err
}

func (c Controller) userOperationConfigSyncDecision(ctx context.Context, node NodeRow, operation OperationRow) (bool, []map[string]any, error) {
	if !isRuntimeUserOperation(operation.OperationType) || !operation.UserID.Valid {
		return false, nil, nil
	}
	// Updated nodes reconcile one user against their cached runtime config. Old
	// nodes are detected after dial and keep the full-sync compatibility path.
	if operation.OperationType == "update_user" {
		return false, nil, nil
	}
	var serviceID sql.NullInt64
	if err := c.repo.db.QueryRowContext(ctx, `SELECT service_id FROM users WHERE id = ?`, operation.UserID.Int64).Scan(&serviceID); err != nil {
		if err == sql.ErrNoRows {
			return false, nil, nil
		}
		return false, nil, err
	}
	if !serviceID.Valid || serviceID.Int64 <= 0 {
		return false, nil, nil
	}
	serviceTags, err := c.repo.ServiceAllowedTags(ctx)
	if err != nil {
		return false, nil, err
	}
	inbounds, err := c.runtimeInbounds(ctx)
	if err != nil {
		return false, nil, err
	}
	target := xrayconfig.NodeTargetID(node.ID)
	for _, inbound := range inbounds {
		if !protocolRequiresFullUserSync(stringValue(inbound["protocol"])) {
			continue
		}
		tag := stringValue(inbound["tag"])
		if tag != "" && serviceTags[serviceID.Int64][tag] && OVInboundMatchesTarget(inbound, target) {
			return true, inbounds, nil
		}
	}
	return false, inbounds, nil
}

func protocolRequiresFullUserSync(protocol string) bool {
	switch strings.ToLower(strings.TrimSpace(protocol)) {
	case xrayconfig.OVProtocol, xrayconfig.L2TPProtocol, xrayconfig.PPTPProtocol, xrayconfig.WGProtocol, xrayconfig.IKEv2Protocol, xrayconfig.AnyConnectProtocol, "ssh":
		return true
	default:
		return false
	}
}

func (c Controller) loadRuntimeConfigData(ctx context.Context) (*runtimeConfigData, error) {
	return c.loadRuntimeConfigDataForProtocols(ctx, nil)
}

func (c Controller) loadRuntimeConfigDataForProtocols(ctx context.Context, protocols []string) (*runtimeConfigData, error) {
	users, err := c.repo.RuntimeUsersForProtocols(ctx, protocols)
	if err != nil {
		return nil, err
	}
	serviceTags, err := c.repo.ServiceAllowedTags(ctx)
	if err != nil {
		return nil, err
	}
	serviceFlows, err := c.repo.ServiceFlows(ctx)
	if err != nil {
		return nil, err
	}
	masks, err := c.repo.UUIDMasks(ctx)
	if err != nil {
		return nil, err
	}
	return &runtimeConfigData{users: users, serviceTags: serviceTags, serviceFlows: serviceFlows, masks: masks}, nil
}

func applyRuntimeAPI(raw map[string]any, apiPort int) {
	if apiPort <= 0 {
		apiPort = 8080
	}
	raw["api"] = map[string]any{"services": []any{"HandlerService", "StatsService", "LoggerService"}, "tag": "API"}
	raw["stats"] = map[string]any{}
	policy := mapValue(raw["policy"])
	levels := mapValue(policy["levels"])
	levels["0"] = mergeMaps(mapValue(levels["0"]), map[string]any{
		"statsUserUplink":   true,
		"statsUserDownlink": true,
		"statsUserOnline":   true,
	})
	system := mapValue(policy["system"])
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
	policy["levels"] = levels
	policy["system"] = mergeMaps(system, systemDefaults)
	raw["policy"] = policy

	inbounds := listOfMaps(raw["inbounds"])
	var apiInbound map[string]any
	for _, inbound := range inbounds {
		if stringValue(inbound["tag"]) == "API_INBOUND" {
			apiInbound = inbound
			break
		}
	}
	if apiInbound == nil {
		apiInbound = map[string]any{
			"listen":   "127.0.0.1",
			"port":     apiPort,
			"protocol": "tunnel",
			"settings": map[string]any{
				"allowedNetwork": "tcp",
				"rewriteAddress": "127.0.0.1",
			},
			"tag": "API_INBOUND",
		}
		raw["inbounds"] = append([]any{apiInbound}, interfaceSlice(raw["inbounds"])...)
	} else {
		apiInbound["listen"] = "127.0.0.1"
		apiInbound["port"] = apiPort
		apiInbound["protocol"] = "tunnel"
		settings := ensureMap(apiInbound, "settings")
		delete(settings, "address")
		settings["allowedNetwork"] = "tcp"
		settings["rewriteAddress"] = "127.0.0.1"
	}

	routing := ensureMap(raw, "routing")
	rules := interfaceSlice(routing["rules"])
	for _, item := range rules {
		rule, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if stringValue(rule["outboundTag"]) == "API" && containsInterfaceString(rule["inboundTag"], "API_INBOUND") {
			routing["rules"] = rules
			return
		}
	}
	routing["rules"] = append([]any{map[string]any{"inboundTag": []any{"API_INBOUND"}, "outboundTag": "API", "type": "field"}}, rules...)
}

func inlineTLSCertificateFiles(raw map[string]any) error {
	for _, section := range []string{"inbounds", "outbounds"} {
		for _, item := range listOfMaps(raw[section]) {
			if err := inlineStreamTLSCertificateFiles(item); err != nil {
				tag := stringValue(item["tag"])
				if tag == "" {
					tag = "<untagged>"
				}
				return fmt.Errorf("%s %s TLS certificate: %w", strings.TrimSuffix(section, "s"), tag, err)
			}
		}
	}
	return nil
}

func inlineStreamTLSCertificateFiles(item map[string]any) error {
	stream := mapValue(item["streamSettings"])
	if len(stream) == 0 {
		return nil
	}
	tlsSettings := mapValue(stream["tlsSettings"])
	if len(tlsSettings) == 0 {
		return nil
	}
	certificates, ok := certificateMaps(tlsSettings["certificates"])
	if !ok || len(certificates) == 0 {
		return nil
	}
	for index, certificate := range certificates {
		if err := inlineCertificatePair(certificate); err != nil {
			return fmt.Errorf("certificate[%d]: %w", index, err)
		}
	}
	tlsSettings["certificates"] = mapsToInterfaces(certificates)
	stream["tlsSettings"] = tlsSettings
	item["streamSettings"] = stream
	return nil
}

func inlineCertificatePair(certificate map[string]any) error {
	if err := inlineCertificateFile(certificate, "certificate", []string{"certificateFile", "certFile", "certfile"}); err != nil {
		return err
	}
	if err := inlineCertificateFile(certificate, "key", []string{"keyFile", "keyfile"}); err != nil {
		return err
	}
	return nil
}

func inlineCertificateFile(certificate map[string]any, contentKey string, pathKeys []string) error {
	if contentLines, ok := certificateContentLines(certificate[contentKey]); ok {
		certificate[contentKey] = contentLines
		deleteCertificatePathKeys(certificate, pathKeys)
		return nil
	}
	path := firstCertificatePath(certificate, pathKeys)
	if path == "" {
		deleteCertificatePathKeys(certificate, pathKeys)
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s file %q: %w", contentKey, path, err)
	}
	lines, ok := certificateContentLines(string(raw))
	if !ok {
		return fmt.Errorf("%s file %q is empty", contentKey, path)
	}
	certificate[contentKey] = lines
	deleteCertificatePathKeys(certificate, pathKeys)
	return nil
}

func certificateMaps(value any) ([]map[string]any, bool) {
	switch typed := value.(type) {
	case []map[string]any:
		return typed, true
	case []any:
		result := make([]map[string]any, 0, len(typed))
		for _, item := range typed {
			mapped, ok := item.(map[string]any)
			if !ok {
				continue
			}
			result = append(result, mapped)
		}
		return result, true
	case map[string]any:
		return []map[string]any{typed}, true
	default:
		return nil, false
	}
}

func certificateContentLines(value any) ([]string, bool) {
	switch typed := value.(type) {
	case []string:
		result := make([]string, 0, len(typed))
		for _, line := range typed {
			result = append(result, strings.TrimRight(line, "\r"))
		}
		return result, len(strings.TrimSpace(strings.Join(result, "\n"))) > 0
	case []any:
		result := make([]string, 0, len(typed))
		for _, item := range typed {
			result = append(result, strings.TrimRight(stringValue(item), "\r"))
		}
		return result, len(strings.TrimSpace(strings.Join(result, "\n"))) > 0
	case string:
		normalized := strings.ReplaceAll(typed, "\r\n", "\n")
		normalized = strings.ReplaceAll(normalized, "\r", "\n")
		normalized = strings.TrimSpace(normalized)
		if normalized == "" {
			return nil, false
		}
		return strings.Split(normalized, "\n"), true
	default:
		return nil, false
	}
}

func firstCertificatePath(certificate map[string]any, pathKeys []string) string {
	for _, key := range pathKeys {
		if path := stringValue(certificate[key]); path != "" {
			return path
		}
	}
	return ""
}

func deleteCertificatePathKeys(certificate map[string]any, pathKeys []string) {
	for _, key := range pathKeys {
		delete(certificate, key)
	}
}

func mapsToInterfaces(items []map[string]any) []any {
	result := make([]any, 0, len(items))
	for _, item := range items {
		result = append(result, item)
	}
	return result
}

func flowSupportedForInbound(inbound map[string]any) bool {
	stream := mapValue(inbound["streamSettings"])
	security := strings.ToLower(stringValue(stream["security"]))
	network := strings.ToLower(stringValue(stream["method"]))
	if network == "" {
		network = strings.ToLower(stringValue(stream["network"]))
	}
	tcpSettings := mapValue(stream["tcpSettings"])
	header := mapValue(tcpSettings["header"])
	headerType := strings.ToLower(stringValue(header["type"]))
	return (security == "tls" || security == "reality") &&
		(network == "tcp" || network == "raw" || network == "kcp") &&
		headerType != "http"
}

func ensureMap(parent map[string]any, key string) map[string]any {
	value := mapValue(parent[key])
	parent[key] = value
	return value
}

func mergeMaps(base map[string]any, override map[string]any) map[string]any {
	if base == nil {
		base = map[string]any{}
	}
	for key, value := range override {
		base[key] = value
	}
	return base
}

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func containsInterfaceString(value any, needle string) bool {
	for _, item := range interfaceSlice(value) {
		if stringValue(item) == needle {
			return true
		}
	}
	return false
}

func interfaceSlice(value any) []any {
	switch typed := value.(type) {
	case []any:
		return typed
	case []map[string]any:
		result := make([]any, 0, len(typed))
		for _, item := range typed {
			result = append(result, item)
		}
		return result
	default:
		return []any{}
	}
}

func listOfMaps(value any) []map[string]any {
	items := interfaceSlice(value)
	result := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if mapped, ok := item.(map[string]any); ok {
			result = append(result, mapped)
		}
	}
	return result
}

func mapValue(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case []byte:
		return jsonMap(string(typed))
	case string:
		return jsonMap(typed)
	case nil:
		return map[string]any{}
	default:
		return map[string]any{}
	}
}

func jsonMap(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	case json.RawMessage:
		return jsonMap([]byte(typed))
	case []byte:
		return jsonMap(string(typed))
	case string:
		var result map[string]any
		if strings.TrimSpace(typed) == "" {
			return map[string]any{}
		}
		if err := json.Unmarshal([]byte(typed), &result); err != nil {
			return map[string]any{}
		}
		return result
	default:
		return map[string]any{}
	}
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []byte:
		return string(typed)
	case fmt.Stringer:
		return typed.String()
	default:
		return ""
	}
}
