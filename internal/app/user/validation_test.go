package user

import (
	"strings"
	"testing"

	adminapp "github.com/rebeccapanel/rebecca/internal/app/admin"
)

func TestUserPayloadValidation(t *testing.T) {
	longNote := strings.Repeat("x", 501)
	negativeIP := int64(-3)
	validFlow := " XTLS-RPRX-VISION-UDP443 "
	dataLimit := int64(1024)
	duration := int64(3600)
	expire := int64(1700000000)

	tests := []struct {
		name    string
		payload UserCreate
		wantErr string
	}{
		{
			name: "valid create normalizes flow and ip",
			payload: UserCreate{
				Username: "valid-user",
				UserPayloadBase: UserPayloadBase{
					Flow:    &validFlow,
					IPLimit: &negativeIP,
				},
			},
		},
		{
			name:    "invalid username",
			payload: UserCreate{Username: "no"},
			wantErr: UsernameValidationMessage,
		},
		{
			name: "long note",
			payload: UserCreate{
				Username: "valid-user",
				UserPayloadBase: UserPayloadBase{
					Note: &longNote,
				},
			},
			wantErr: "maximum of 500",
		},
		{
			name: "invalid telegram",
			payload: UserCreate{
				Username: "valid-user",
				UserPayloadBase: UserPayloadBase{
					TelegramID: strPtr("bad/telegram"),
				},
			},
			wantErr: "Invalid telegram_id",
		},
		{
			name: "invalid contact",
			payload: UserCreate{
				Username: "valid-user",
				UserPayloadBase: UserPayloadBase{
					ContactNumber: strPtr("phoneABC"),
				},
			},
			wantErr: "Invalid contact_number",
		},
		{
			name: "invalid flow",
			payload: UserCreate{
				Username: "valid-user",
				UserPayloadBase: UserPayloadBase{
					Flow: strPtr("reality"),
				},
			},
			wantErr: "Unsupported flow",
		},
		{
			name: "legacy proxies payload accepted",
			payload: UserCreate{
				Username:        "valid-user",
				UserPayloadBase: UserPayloadBase{Proxies: map[string]map[string]any{"vless": {}}},
			},
		},
		{
			name: "on hold needs duration",
			payload: UserCreate{
				Username:        "valid-user",
				Status:          UserStatusCreateOnHold,
				UserPayloadBase: UserPayloadBase{},
			},
			wantErr: "on_hold_expire_duration",
		},
		{
			name: "on hold rejects finite expire",
			payload: UserCreate{
				Username: "valid-user",
				Status:   UserStatusCreateOnHold,
				UserPayloadBase: UserPayloadBase{
					OnHoldExpireDuration: &duration,
					Expire:               &expire,
				},
			},
			wantErr: "specified expire",
		},
		{
			name: "bad inbound",
			payload: UserCreate{
				Username: "valid-user",
				UserPayloadBase: UserPayloadBase{
					Inbounds: map[string][]string{"vless": {"missing"}},
				},
			},
			wantErr: ManualInboundSelectionRemovedMessage,
		},
		{
			name: "negative data limit",
			payload: UserCreate{
				Username: "valid-user",
				UserPayloadBase: UserPayloadBase{
					DataLimit: i64(-1),
				},
			},
			wantErr: "data_limit",
		},
		{
			name: "valid finite data",
			payload: UserCreate{
				Username: "valid-user",
				UserPayloadBase: UserPayloadBase{
					DataLimit: &dataLimit,
				},
			},
		},
	}

	catalog := MutationContext{
		Inbounds: map[string]InboundInfo{
			"vless-in": {Tag: "vless-in", Protocol: "vless", HasEnabledHosts: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateUserCreate(&tt.payload, catalog)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if tt.payload.Flow != nil && *tt.payload.Flow != "xtls-rprx-vision-udp443" {
					t.Fatalf("flow was not normalized: %#v", *tt.payload.Flow)
				}
				if tt.payload.IPLimit != nil && *tt.payload.IPLimit < 0 {
					t.Fatalf("ip limit was not normalized: %#v", *tt.payload.IPLimit)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want contains %q", err, tt.wantErr)
			}
		})
	}
}

func TestLegacyProxiesCredentialKeyCompatibility(t *testing.T) {
	payload := UserPayloadBase{
		Proxies: ProxyPayload{
			"vless": {"id": "11111111-1111-4111-8111-111111111111"},
		},
	}
	applyCredentialKeyFromLegacyProxies(&payload)
	if payload.CredentialKey == nil || *payload.CredentialKey != "11111111111141118111111111111111" {
		t.Fatalf("credential_key from proxies = %v", payload.CredentialKey)
	}

	explicit := "22222222222242228222222222222222"
	payload = UserPayloadBase{
		CredentialKey: &explicit,
		Proxies: ProxyPayload{
			"vless": {"id": "11111111-1111-4111-8111-111111111111"},
		},
	}
	applyCredentialKeyFromLegacyProxies(&payload)
	if payload.CredentialKey == nil || *payload.CredentialKey != explicit {
		t.Fatalf("explicit credential_key was not preserved: %v", payload.CredentialKey)
	}

	payload = UserPayloadBase{
		Proxies: ProxyPayload{
			"trojan": {"password": "legacy-password"},
		},
	}
	applyCredentialKeyFromLegacyProxies(&payload)
	if payload.CredentialKey != nil {
		t.Fatalf("password-only legacy proxies must be ignored, got %v", *payload.CredentialKey)
	}
}

func TestBulkUsersActionValidation(t *testing.T) {
	days := int64(3)
	conditionDays := int64(14)
	gb := 2.5
	serviceID := int64(9)
	nullService := true
	tests := []struct {
		name    string
		payload BulkUsersActionRequest
		wantErr string
	}{
		{name: "extend needs days", payload: BulkUsersActionRequest{Action: AdvancedUserActionExtendExpire}, wantErr: "days"},
		{name: "traffic needs gigabytes", payload: BulkUsersActionRequest{Action: AdvancedUserActionIncreaseTraffic}, wantErr: "gigabytes"},
		{name: "cleanup rejects active", payload: BulkUsersActionRequest{Action: AdvancedUserActionCleanupStatus, Days: &days, Statuses: []UserStatus{UserStatusActive}}, wantErr: "cleanup_status"},
		{name: "scope strips deleted", payload: BulkUsersActionRequest{Action: AdvancedUserActionDisableUsers, Scope: []UserStatus{UserStatusDeleted}}, wantErr: "scope"},
		{name: "service null conflicts service id", payload: BulkUsersActionRequest{Action: AdvancedUserActionDisableUsers, ServiceID: &serviceID, ServiceIDIsNull: &nullService}, wantErr: "cannot both"},
		{name: "delete needs target", payload: BulkUsersActionRequest{Action: AdvancedUserActionDeleteUsers}, wantErr: "requires usernames"},
		{name: "status age needs scope", payload: BulkUsersActionRequest{Action: AdvancedUserActionDeleteUsers, StatusAgeDays: &conditionDays}, wantErr: "requires at least one status"},
		{name: "valid conditional delete", payload: BulkUsersActionRequest{Action: AdvancedUserActionDeleteUsers, Scope: []UserStatus{UserStatusExpired}, StatusAgeDays: &conditionDays}},
		{name: "valid traffic", payload: BulkUsersActionRequest{Action: AdvancedUserActionIncreaseTraffic, Gigabytes: &gb}},
		{name: "multiply needs factor", payload: BulkUsersActionRequest{Action: AdvancedUserActionMultiplyExpire}, wantErr: "factor"},
		{name: "valid multiply", payload: BulkUsersActionRequest{Action: AdvancedUserActionMultiplyExpire, Factor: &gb}},
		{name: "multiply traffic needs factor", payload: BulkUsersActionRequest{Action: AdvancedUserActionMultiplyTraffic}, wantErr: "factor"},
		{name: "valid multiply traffic", payload: BulkUsersActionRequest{Action: AdvancedUserActionMultiplyTraffic, Factor: &gb}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBulkUsersAction(&tt.payload)
			if tt.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tt.wantErr)) {
				t.Fatalf("error = %v, want contains %q", err, tt.wantErr)
			}
		})
	}
}

func TestAutoServiceDetection(t *testing.T) {
	result, err := DetectAutoServiceFromInbounds(map[string][]string{"vless": {"setservice-42"}})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Detected || result.ServiceID != 42 || result.Tag != "setservice-42" {
		t.Fatalf("unexpected detection: %#v", result)
	}

	_, err = DetectAutoServiceFromInbounds(map[string][]string{"vless": {"setservice-42", "real-inbound"}})
	if err == nil || !strings.Contains(err.Error(), ManualInboundSelectionRemovedMessage) {
		t.Fatalf("expected manual inbound removal error, got %v", err)
	}

	_, err = DetectAutoServiceFromInbounds(map[string][]string{"vless": {"setservice-42"}, "vmess": {"setservice-43"}})
	if err == nil || !strings.Contains(err.Error(), "Only one service inbound") {
		t.Fatalf("expected multi-service error, got %v", err)
	}
}

func TestPermissionAndLimitEnforcement(t *testing.T) {
	admin := standardAdmin()
	admin.Permissions.Users.Create = false
	if err := EnsureUserPermission(admin, UserPermissionCreate); err == nil || !strings.Contains(err.Error(), "create users") {
		t.Fatalf("expected create denied, got %v", err)
	}

	admin = standardAdmin()
	admin.Permissions.Users.AllowUnlimitedData = false
	admin.Permissions.Users.AllowUnlimitedExpire = false
	admin.Permissions.Users.AllowNextPlan = false
	admin.Permissions.Users.CreateOnHold = false
	if err := EnsureUserConstraints(admin, UserConstraintInput{Data: i64(0)}); err == nil || !strings.Contains(err.Error(), "Unlimited data") {
		t.Fatalf("expected unlimited data denied, got %v", err)
	}
	if err := EnsureUserConstraints(admin, UserConstraintInput{Expire: i64(0)}); err == nil || !strings.Contains(err.Error(), "Unlimited validity") {
		t.Fatalf("expected unlimited expire denied, got %v", err)
	}
	if err := EnsureUserConstraints(admin, UserConstraintInput{NextPlans: []NextPlanPayload{{DataLimit: i64(1024)}}}); err == nil || !strings.Contains(err.Error(), "next plans") {
		t.Fatalf("expected next plan denied, got %v", err)
	}
	if err := EnsureUserConstraints(admin, UserConstraintInput{Status: "on_hold"}); err == nil || !strings.Contains(err.Error(), "on-hold") {
		t.Fatalf("expected on hold denied, got %v", err)
	}
	if err := EnsureFlowPermission(admin, true); err == nil || !strings.Contains(err.Error(), "flow") {
		t.Fatalf("expected flow denied, got %v", err)
	}
	if err := EnsureCustomKeyPermission(admin, true); err == nil || !strings.Contains(err.Error(), "custom credential") {
		t.Fatalf("expected custom key denied, got %v", err)
	}
}

func TestCreatedTrafficAndServiceLimits(t *testing.T) {
	limit := int64(1000)
	admin := standardAdmin()
	admin.TrafficLimitMode = adminapp.TrafficLimitCreatedTraffic
	admin.DataLimit = &limit
	admin.CreatedTraffic = 900

	if _, err := ValidateCreatedTrafficDataLimitChange(admin, nil, i64(0), 0, nil); err == nil || !strings.Contains(err.Error(), "حجم یوزر باید محدود") {
		t.Fatalf("expected finite required, got %v", err)
	}
	if _, err := ValidateCreatedTrafficDataLimitChange(admin, i64(100), i64(50), 80, nil); err == nil || !strings.Contains(err.Error(), "کمتر از مصرف") {
		t.Fatalf("expected below used denied, got %v", err)
	}
	if _, err := ValidateCreatedTrafficDataLimitChange(admin, nil, i64(200), 0, nil); err == nil || !strings.Contains(err.Error(), CreatedTrafficLimitExceededMessage) {
		t.Fatalf("expected created traffic exceeded, got %v", err)
	}

	admin = standardAdmin()
	admin.UseServiceTrafficLimits = true
	admin.ServiceLimits = []adminapp.AdminServiceLimit{{
		ServiceID:        7,
		TrafficLimitMode: adminapp.TrafficLimitUsedTraffic,
		DataLimit:        i64(100),
		UsedTraffic:      100,
		UsersLimit:       i64(1),
	}}
	if err := EnsureAdminServiceScopeAvailable(admin, 0, "create users"); err == nil || !strings.Contains(err.Error(), "inside an assigned service") {
		t.Fatalf("expected service required, got %v", err)
	}
	if err := EnsureAdminServiceScopeAvailable(admin, 7, "create users"); err == nil || !strings.Contains(err.Error(), "traffic limit") {
		t.Fatalf("expected used limit denied, got %v", err)
	}
	admin.ServiceLimits[0].UsedTraffic = 0
	if err := EnsureUsersLimit(admin, i64(7), MutationContext{ServiceActiveUsers: map[int64]int64{7: 1}}); err == nil || !strings.Contains(err.Error(), "Users limit") {
		t.Fatalf("expected per-service users limit denied, got %v", err)
	}
}

func TestServiceVisibilityAndDeleteUsageCap(t *testing.T) {
	admin := standardAdmin()
	service := ServiceInfo{ID: 3, AdminIDs: []int64{99}, HasActiveHosts: true}
	if err := EnsureServiceVisible(admin, service); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("expected service visibility denied, got %v", err)
	}
	service.AdminIDs = []int64{admin.ID}
	if err := EnsureServiceVisible(admin, service); err != nil {
		t.Fatalf("unexpected service visibility error: %v", err)
	}

	admin.TrafficLimitMode = adminapp.TrafficLimitCreatedTraffic
	admin.DataLimit = i64(1000)
	admin.CreatedTraffic = 1000
	if err := EnsureUserDeleteAllowed(admin, UserSnapshot{UsedTraffic: 10}); err == nil || !strings.Contains(err.Error(), DeleteCapExceededMessage) {
		t.Fatalf("expected delete cap denied, got %v", err)
	}
	admin.DeleteUserUsageLimitEnabled = true
	admin.DeleteUserUsageLimit = i64(5)
	if err := EnsureUserDeleteAllowed(admin, UserSnapshot{UsedTraffic: 10}); err == nil || !strings.Contains(err.Error(), DeleteCapExceededMessage) {
		t.Fatalf("expected delete usage cap denied, got %v", err)
	}
	admin.DeleteUserUsageLimit = i64(20)
	if err := EnsureUserDeleteAllowed(admin, UserSnapshot{UsedTraffic: 10}); err != nil {
		t.Fatalf("unexpected delete usage cap error: %v", err)
	}
}

func standardAdmin() adminapp.Admin {
	perms := adminapp.RoleDefaultPermissions(adminapp.RoleStandard)
	return adminapp.Admin{
		ID:          2,
		Username:    "seller",
		Role:        adminapp.RoleStandard,
		Status:      adminapp.StatusActive,
		Permissions: perms,
	}
}

func strPtr(value string) *string { return &value }
func i64(value int64) *int64      { return &value }
