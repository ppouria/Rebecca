package user

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const UsernameValidationMessage = "Username only can be 3 to 32 characters and contain a-z, 0-9, underscores, hyphens, dots, or @."
const ManualInboundSelectionRemovedMessage = "Manual inbound selection was removed in v0.2.0. Assign a service to the user, or use the service inbound tag setservice-<id> for legacy clients."
const NextPlanRemovedMessage = "next_plan was removed in v0.2.0; use next_plans instead."

var (
	usernameRegexp    = regexp.MustCompile(`^[a-zA-Z0-9._@-]+$`)
	telegramRegexp    = regexp.MustCompile(`^[\w.@+\- ]+$`)
	contactRegexp     = regexp.MustCompile(`^[0-9+\-() ]+$`)
	autoServiceRegexp = regexp.MustCompile(`(?i)^setservice-(\d+)$`)
)

type ValidationError struct {
	Detail string
}

func (e ValidationError) Error() string {
	return e.Detail
}

func ValidateUserCreate(payload *UserCreate, catalog MutationContext) error {
	if payload == nil {
		return ValidationError{Detail: "payload is required"}
	}
	if err := validateUsername(payload.Username); err != nil {
		return err
	}
	if payload.Status != "" && payload.Status != UserStatusCreateActive && payload.Status != UserStatusCreateOnHold {
		return ValidationError{Detail: "invalid user status"}
	}
	if hasManualInboundSelection(payload.Inbounds) {
		return ValidationError{Detail: ManualInboundSelectionRemovedMessage}
	}
	if err := validateUserBase(&payload.UserPayloadBase, catalog); err != nil {
		return err
	}
	return validateOnHoldCreate(payload.Status, payload.OnHoldExpireDuration, payload.Expire)
}

func ValidateUserServiceCreate(payload *UserServiceCreate, catalog MutationContext) error {
	if payload == nil {
		return ValidationError{Detail: "payload is required"}
	}
	if err := validateUsername(payload.Username); err != nil {
		return err
	}
	if payload.ServiceID <= 0 {
		return ValidationError{Detail: "service_id must be a positive integer"}
	}
	if payload.Status != "" && payload.Status != UserStatusCreateActive && payload.Status != UserStatusCreateOnHold {
		return ValidationError{Detail: "invalid user status"}
	}
	base := UserPayloadBase{
		CredentialKey:          payload.CredentialKey,
		Flow:                   payload.Flow,
		Expire:                 payload.Expire,
		DataLimit:              payload.DataLimit,
		DataLimitResetStrategy: payload.DataLimitResetStrategy,
		Note:                   payload.Note,
		TelegramID:             nil,
		ContactNumber:          nil,
		OnHoldExpireDuration:   payload.OnHoldExpireDuration,
		OnHoldTimeout:          payload.OnHoldTimeout,
		IPLimit:                payload.IPLimit,
		AutoDeleteInDays:       payload.AutoDeleteInDays,
		NextPlans:              payload.NextPlans,
	}
	if err := validateUserBase(&base, catalog); err != nil {
		return err
	}
	return validateOnHoldCreate(payload.Status, payload.OnHoldExpireDuration, payload.Expire)
}

func ValidateUserModify(payload *UserModify, catalog MutationContext) error {
	if payload == nil {
		return ValidationError{Detail: "payload is required"}
	}
	if payload.Status != "" && payload.Status != UserStatusModifyActive && payload.Status != UserStatusModifyDisabled && payload.Status != UserStatusModifyOnHold {
		return ValidationError{Detail: "invalid user status"}
	}
	if payload.ServiceID != nil && *payload.ServiceID <= 0 {
		return ValidationError{Detail: "service_id must be a positive integer"}
	}
	if hasManualInboundSelection(payload.Inbounds) {
		return ValidationError{Detail: ManualInboundSelectionRemovedMessage}
	}
	if err := validateUserBase(&payload.UserPayloadBase, catalog); err != nil {
		return err
	}
	return validateOnHoldModify(payload.Status, payload.OnHoldExpireDuration, payload.Expire)
}

func ValidateBulkUsersAction(payload *BulkUsersActionRequest) error {
	if payload == nil {
		return ValidationError{Detail: "payload is required"}
	}
	allowedActions := map[AdvancedUserAction]struct{}{
		AdvancedUserActionExtendExpire:    {},
		AdvancedUserActionReduceExpire:    {},
		AdvancedUserActionIncreaseTraffic: {},
		AdvancedUserActionDecreaseTraffic: {},
		AdvancedUserActionCleanupStatus:   {},
		AdvancedUserActionActivateUsers:   {},
		AdvancedUserActionDisableUsers:    {},
		AdvancedUserActionChangeService:   {},
		AdvancedUserActionDeleteUsers:     {},
		AdvancedUserActionMultiplyExpire:  {},
		AdvancedUserActionDivideExpire:    {},
		AdvancedUserActionMultiplyTraffic: {},
		AdvancedUserActionDivideTraffic:   {},
	}
	if _, ok := allowedActions[payload.Action]; !ok {
		return ValidationError{Detail: "unsupported bulk action"}
	}
	needsDays := map[AdvancedUserAction]struct{}{
		AdvancedUserActionExtendExpire:  {},
		AdvancedUserActionReduceExpire:  {},
		AdvancedUserActionCleanupStatus: {},
	}
	if _, ok := needsDays[payload.Action]; ok {
		if payload.Days == nil || *payload.Days <= 0 {
			return ValidationError{Detail: "days must be a positive integer"}
		}
	}
	needsFactor := map[AdvancedUserAction]struct{}{
		AdvancedUserActionMultiplyExpire:  {},
		AdvancedUserActionDivideExpire:    {},
		AdvancedUserActionMultiplyTraffic: {},
		AdvancedUserActionDivideTraffic:   {},
	}
	if _, ok := needsFactor[payload.Action]; ok {
		if payload.Factor == nil || *payload.Factor <= 0 {
			return ValidationError{Detail: "factor must be a positive number"}
		}
	}
	if payload.Action == AdvancedUserActionIncreaseTraffic || payload.Action == AdvancedUserActionDecreaseTraffic {
		if payload.Gigabytes == nil || *payload.Gigabytes <= 0 {
			return ValidationError{Detail: "gigabytes must be a positive number"}
		}
	}
	if payload.Action == AdvancedUserActionCleanupStatus {
		allowed := map[UserStatus]struct{}{UserStatusExpired: {}, UserStatusLimited: {}}
		statuses := payload.Statuses
		if len(statuses) == 0 {
			statuses = []UserStatus{UserStatusExpired, UserStatusLimited}
		}
		for _, status := range statuses {
			if _, ok := allowed[status]; !ok {
				return ValidationError{Detail: "cleanup_status only accepts expired or limited"}
			}
		}
		payload.Statuses = statuses
	}
	if len(payload.Scope) > 0 {
		cleaned := make([]UserStatus, 0, len(payload.Scope))
		seen := map[UserStatus]struct{}{}
		for _, status := range payload.Scope {
			if status == UserStatusDeleted {
				continue
			}
			if _, ok := seen[status]; ok {
				continue
			}
			seen[status] = struct{}{}
			cleaned = append(cleaned, status)
		}
		if len(cleaned) == 0 {
			return ValidationError{Detail: "scope cannot be empty or include deleted"}
		}
		payload.Scope = cleaned
	}
	if payload.ServiceID != nil && *payload.ServiceID <= 0 {
		return ValidationError{Detail: "service_id must be a positive integer"}
	}
	if payload.Action == AdvancedUserActionChangeService {
		if payload.TargetServiceID == nil {
			return ValidationError{Detail: "target_service_id is required. Users must be assigned to a service."}
		}
		if *payload.TargetServiceID <= 0 {
			return ValidationError{Detail: "target_service_id must be a positive integer when provided for change_service"}
		}
	}
	if payload.ServiceIDIsNull != nil && *payload.ServiceIDIsNull && payload.ServiceID != nil {
		return ValidationError{Detail: "service_id and service_id_is_null cannot both be set"}
	}
	if len(payload.Usernames) > 500 {
		return ValidationError{Detail: "at most 500 usernames can be targeted per bulk action"}
	}
	if len(payload.Usernames) > 0 {
		seen := map[string]struct{}{}
		usernames := make([]string, 0, len(payload.Usernames))
		for _, value := range payload.Usernames {
			username := strings.TrimSpace(value)
			if err := validateUsername(username); err != nil {
				return err
			}
			key := strings.ToLower(username)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			usernames = append(usernames, username)
		}
		payload.Usernames = usernames
	}
	for _, item := range []struct {
		name  string
		value *int64
	}{
		{name: "last_online_days", value: payload.LastOnlineDays},
		{name: "status_age_days", value: payload.StatusAgeDays},
		{name: "created_before_days", value: payload.CreatedBeforeDays},
	} {
		if item.value != nil && *item.value <= 0 {
			return ValidationError{Detail: item.name + " must be a positive integer"}
		}
	}
	if payload.StatusAgeDays != nil && len(payload.Scope) == 0 {
		return ValidationError{Detail: "status_age_days requires at least one status in scope"}
	}
	if payload.DryRun && payload.Action != AdvancedUserActionDeleteUsers {
		return ValidationError{Detail: "dry_run is only supported for delete_users"}
	}
	if payload.Action == AdvancedUserActionDeleteUsers {
		hasTarget := len(payload.Usernames) > 0 || payload.LastOnlineDays != nil || payload.StatusAgeDays != nil || payload.CreatedBeforeDays != nil
		if !hasTarget {
			return ValidationError{Detail: "delete_users requires usernames or at least one time-based condition"}
		}
	}
	return nil
}

func validateUserBase(payload *UserPayloadBase, catalog MutationContext) error {
	if payload == nil {
		return nil
	}
	if payload.DataLimit != nil && *payload.DataLimit < 0 {
		return ValidationError{Detail: "data_limit must be greater than or equal to 0"}
	}
	if payload.DataLimitResetStrategy == "" {
		payload.DataLimitResetStrategy = UserDataLimitResetNoReset
	}
	if !validResetStrategy(payload.DataLimitResetStrategy) {
		return ValidationError{Detail: "invalid data_limit_reset_strategy"}
	}
	if payload.Note != nil {
		note := strings.TrimSpace(*payload.Note)
		if len(note) > 500 {
			return ValidationError{Detail: "User's note can be a maximum of 500 character"}
		}
		*payload.Note = note
	}
	if payload.CredentialKey != nil {
		value := strings.TrimSpace(*payload.CredentialKey)
		if value == "" {
			payload.CredentialKey = nil
		} else {
			normalized, err := NormalizeCredentialKeyInput(value)
			if err != nil {
				return ValidationError{Detail: err.Error()}
			}
			*payload.CredentialKey = normalized
		}
	}
	if payload.TelegramID != nil {
		value := strings.TrimSpace(*payload.TelegramID)
		if value == "" {
			payload.TelegramID = nil
		} else if !telegramRegexp.MatchString(value) {
			return ValidationError{Detail: "Invalid telegram_id format"}
		} else {
			*payload.TelegramID = value
		}
	}
	if payload.ContactNumber != nil {
		value := strings.TrimSpace(*payload.ContactNumber)
		if value == "" {
			payload.ContactNumber = nil
		} else if !contactRegexp.MatchString(value) {
			return ValidationError{Detail: "Invalid contact_number format"}
		} else {
			*payload.ContactNumber = value
		}
	}
	if payload.Flow != nil {
		normalized, ok := NormalizeFlow(*payload.Flow)
		if !ok {
			return ValidationError{Detail: "Unsupported flow value"}
		}
		if normalized == "" {
			payload.Flow = nil
		} else {
			*payload.Flow = normalized
		}
	}
	if payload.IPLimit != nil && *payload.IPLimit < 0 {
		zero := int64(0)
		payload.IPLimit = &zero
	}
	if payload.OnHoldExpireDuration != nil && *payload.OnHoldExpireDuration <= 0 {
		payload.OnHoldExpireDuration = nil
	}
	if payload.OnHoldTimeout != nil && strings.TrimSpace(*payload.OnHoldTimeout) == "" {
		payload.OnHoldTimeout = nil
	}
	if err := validateNextPlans(payload.NextPlans); err != nil {
		return err
	}
	if err := validateProxies(payload.Proxies); err != nil {
		return err
	}
	return nil
}

func validateUsername(value string) error {
	if len(value) < 3 || len(value) > 32 || !usernameRegexp.MatchString(value) {
		return ValidationError{Detail: UsernameValidationMessage}
	}
	return nil
}

func NormalizeFlow(value string) (string, bool) {
	normalized := strings.ToLower(strings.TrimSpace(value))
	if normalized == "" {
		return "", true
	}
	switch normalized {
	case "xtls-rprx-vision", "xtls-rprx-vision-udp443":
		return normalized, true
	default:
		return "", false
	}
}

func validateOnHoldCreate(status UserStatusCreate, duration *int64, expire *int64) error {
	if status != UserStatusCreateOnHold {
		return nil
	}
	return validateOnHold(duration, expire)
}

func validateOnHoldModify(status UserStatusModify, duration *int64, expire *int64) error {
	if status != UserStatusModifyOnHold {
		return nil
	}
	return validateOnHold(duration, expire)
}

func validateOnHold(duration *int64, expire *int64) error {
	if duration == nil || *duration <= 0 {
		return ValidationError{Detail: "User cannot be on hold without a valid on_hold_expire_duration."}
	}
	if expire != nil && *expire > 0 {
		return ValidationError{Detail: "User cannot be on hold with specified expire."}
	}
	return nil
}

func validateNextPlans(nextPlans []NextPlanPayload) error {
	for i := range nextPlans {
		if err := validateNextPlan(&nextPlans[i]); err != nil {
			return err
		}
	}
	return nil
}

func validateNextPlan(plan *NextPlanPayload) error {
	if plan == nil {
		return nil
	}
	if plan.DataLimit != nil && *plan.DataLimit < 0 {
		return ValidationError{Detail: "next plan data_limit must be greater than or equal to 0"}
	}
	if plan.TriggerOn == "" {
		plan.TriggerOn = "either"
	}
	return nil
}

func validateProxies(proxies ProxyPayload) error {
	// Legacy clients may still send proxies. New users do not persist proxy rows,
	// but vmess/vless IDs are accepted as credential_key compatibility input.
	return nil
}

func validResetStrategy(value UserDataLimitResetStrategy) bool {
	switch value {
	case UserDataLimitResetNoReset, UserDataLimitResetDay, UserDataLimitResetWeek, UserDataLimitResetMonth, UserDataLimitResetYear:
		return true
	default:
		return false
	}
}

func validProxyProtocol(protocol string) bool {
	switch normalizeProtocol(protocol) {
	case "vmess", "vless", "trojan", "shadowsocks":
		return true
	default:
		return false
	}
}

func normalizeProtocol(protocol string) string {
	return strings.ToLower(strings.TrimSpace(protocol))
}

type AutoServiceDetection struct {
	ServiceID int64
	Tag       string
	Detected  bool
}

func DetectAutoServiceFromInbounds(inbounds map[string][]string) (AutoServiceDetection, error) {
	if len(inbounds) == 0 {
		return AutoServiceDetection{}, nil
	}
	tags := map[string]struct{}{}
	for _, values := range inbounds {
		for _, tag := range values {
			tag = strings.TrimSpace(tag)
			if tag != "" {
				tags[tag] = struct{}{}
			}
		}
	}
	if len(tags) == 0 {
		return AutoServiceDetection{}, nil
	}
	autoTags := make([]string, 0)
	for tag := range tags {
		if autoServiceRegexp.MatchString(tag) {
			autoTags = append(autoTags, tag)
		}
	}
	sort.Strings(autoTags)
	if len(autoTags) == 0 {
		return AutoServiceDetection{}, nil
	}
	if len(autoTags) > 1 {
		return AutoServiceDetection{}, ValidationError{Detail: "Only one service inbound can be selected at a time."}
	}
	if len(tags) != 1 {
		if hasManualInboundSelection(inbounds) {
			return AutoServiceDetection{}, ValidationError{Detail: ManualInboundSelectionRemovedMessage}
		}
		return AutoServiceDetection{}, ValidationError{Detail: "Service inbound must be selected alone without any additional inbounds."}
	}
	match := autoServiceRegexp.FindStringSubmatch(autoTags[0])
	if len(match) != 2 {
		return AutoServiceDetection{}, nil
	}
	serviceID, err := parsePositiveInt64(match[1])
	if err != nil {
		return AutoServiceDetection{}, ValidationError{Detail: fmt.Sprintf(`Invalid service inbound tag "%s".`, autoTags[0])}
	}
	return AutoServiceDetection{ServiceID: serviceID, Tag: autoTags[0], Detected: true}, nil
}

func hasManualInboundSelection(inbounds map[string][]string) bool {
	for _, values := range inbounds {
		for _, tag := range values {
			tag = strings.TrimSpace(tag)
			if tag != "" && !autoServiceRegexp.MatchString(tag) {
				return true
			}
		}
	}
	return false
}

func parsePositiveInt64(value string) (int64, error) {
	var parsed int64
	for _, ch := range value {
		if ch < '0' || ch > '9' {
			return 0, fmt.Errorf("invalid integer")
		}
		parsed = parsed*10 + int64(ch-'0')
	}
	if parsed <= 0 {
		return 0, fmt.Errorf("invalid integer")
	}
	return parsed, nil
}
