package user

import adminapp "github.com/rebeccapanel/rebecca/internal/app/admin"

type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusDisabled UserStatus = "disabled"
	UserStatusLimited  UserStatus = "limited"
	UserStatusExpired  UserStatus = "expired"
	UserStatusOnHold   UserStatus = "on_hold"
	UserStatusDeleted  UserStatus = "deleted"
)

type UserStatusCreate string

const (
	UserStatusCreateActive UserStatusCreate = "active"
	UserStatusCreateOnHold UserStatusCreate = "on_hold"
)

type UserStatusModify string

const (
	UserStatusModifyActive   UserStatusModify = "active"
	UserStatusModifyDisabled UserStatusModify = "disabled"
	UserStatusModifyOnHold   UserStatusModify = "on_hold"
)

type UserDataLimitResetStrategy string

const (
	UserDataLimitResetNoReset UserDataLimitResetStrategy = "no_reset"
	UserDataLimitResetDay     UserDataLimitResetStrategy = "day"
	UserDataLimitResetWeek    UserDataLimitResetStrategy = "week"
	UserDataLimitResetMonth   UserDataLimitResetStrategy = "month"
	UserDataLimitResetYear    UserDataLimitResetStrategy = "year"
)

type AdvancedUserAction string

const (
	AdvancedUserActionExtendExpire    AdvancedUserAction = "extend_expire"
	AdvancedUserActionReduceExpire    AdvancedUserAction = "reduce_expire"
	AdvancedUserActionIncreaseTraffic AdvancedUserAction = "increase_traffic"
	AdvancedUserActionDecreaseTraffic AdvancedUserAction = "decrease_traffic"
	AdvancedUserActionCleanupStatus   AdvancedUserAction = "cleanup_status"
	AdvancedUserActionActivateUsers   AdvancedUserAction = "activate_users"
	AdvancedUserActionDisableUsers    AdvancedUserAction = "disable_users"
	AdvancedUserActionChangeService   AdvancedUserAction = "change_service"
	AdvancedUserActionDeleteUsers     AdvancedUserAction = "delete_users"
	AdvancedUserActionMultiplyExpire  AdvancedUserAction = "multiply_expire"
	AdvancedUserActionDivideExpire    AdvancedUserAction = "divide_expire"
	AdvancedUserActionMultiplyTraffic AdvancedUserAction = "multiply_traffic"
	AdvancedUserActionDivideTraffic   AdvancedUserAction = "divide_traffic"
)

type ProxyPayload map[string]map[string]any

type NextPlanPayload struct {
	DataLimit           *int64 `json:"data_limit,omitempty"`
	Expire              *int64 `json:"expire,omitempty"`
	AddRemainingTraffic bool   `json:"add_remaining_traffic"`
	FireOnEither        bool   `json:"fire_on_either"`
	IncreaseDataLimit   bool   `json:"increase_data_limit"`
	StartOnFirstConnect bool   `json:"start_on_first_connect"`
	TriggerOn           string `json:"trigger_on"`
	Position            int64  `json:"position"`
}

type UserPayloadBase struct {
	CredentialKey          *string                    `json:"credential_key,omitempty"`
	Proxies                ProxyPayload               `json:"proxies,omitempty"`
	Flow                   *string                    `json:"flow,omitempty"`
	Expire                 *int64                     `json:"expire,omitempty"`
	DataLimit              *int64                     `json:"data_limit,omitempty"`
	DataLimitResetStrategy UserDataLimitResetStrategy `json:"data_limit_reset_strategy,omitempty"`
	Inbounds               map[string][]string        `json:"inbounds,omitempty"`
	Note                   *string                    `json:"note,omitempty"`
	TelegramID             *string                    `json:"telegram_id,omitempty"`
	ContactNumber          *string                    `json:"contact_number,omitempty"`
	OnHoldExpireDuration   *int64                     `json:"on_hold_expire_duration,omitempty"`
	OnHoldTimeout          *string                    `json:"on_hold_timeout,omitempty"`
	IPLimit                *int64                     `json:"ip_limit,omitempty"`
	AutoDeleteInDays       *int64                     `json:"auto_delete_in_days,omitempty"`
	NextPlans              []NextPlanPayload          `json:"next_plans,omitempty"`
}

type UserCreate struct {
	UserPayloadBase
	Username string           `json:"username"`
	Status   UserStatusCreate `json:"status,omitempty"`
}

type UserServiceCreate struct {
	Username               string                     `json:"username"`
	ServiceID              int64                      `json:"service_id"`
	Status                 UserStatusCreate           `json:"status,omitempty"`
	Expire                 *int64                     `json:"expire,omitempty"`
	DataLimit              *int64                     `json:"data_limit,omitempty"`
	DataLimitResetStrategy UserDataLimitResetStrategy `json:"data_limit_reset_strategy,omitempty"`
	Note                   *string                    `json:"note,omitempty"`
	OnHoldTimeout          *string                    `json:"on_hold_timeout,omitempty"`
	OnHoldExpireDuration   *int64                     `json:"on_hold_expire_duration,omitempty"`
	AutoDeleteInDays       *int64                     `json:"auto_delete_in_days,omitempty"`
	NextPlans              []NextPlanPayload          `json:"next_plans,omitempty"`
	IPLimit                *int64                     `json:"ip_limit,omitempty"`
	Flow                   *string                    `json:"flow,omitempty"`
	CredentialKey          *string                    `json:"credential_key,omitempty"`
}

type UserModify struct {
	UserPayloadBase
	Status    UserStatusModify `json:"status,omitempty"`
	ServiceID *int64           `json:"service_id,omitempty"`
}

type BulkUsersActionRequest struct {
	Action            AdvancedUserAction `json:"action"`
	Days              *int64             `json:"days,omitempty"`
	Factor            *float64           `json:"factor,omitempty"`
	Gigabytes         *float64           `json:"gigabytes,omitempty"`
	Statuses          []UserStatus       `json:"statuses,omitempty"`
	Scope             []UserStatus       `json:"scope,omitempty"`
	AdminUsername     *string            `json:"admin_username,omitempty"`
	ServiceID         *int64             `json:"service_id,omitempty"`
	TargetServiceID   *int64             `json:"target_service_id,omitempty"`
	ServiceIDIsNull   *bool              `json:"service_id_is_null,omitempty"`
	Usernames         []string           `json:"usernames,omitempty"`
	LastOnlineDays    *int64             `json:"last_online_days,omitempty"`
	StatusAgeDays     *int64             `json:"status_age_days,omitempty"`
	CreatedBeforeDays *int64             `json:"created_before_days,omitempty"`
	DryRun            bool               `json:"dry_run,omitempty"`
}

type BulkUsersActionResult struct {
	Detail  string  `json:"detail"`
	Count   int64   `json:"count"`
	UserIDs []int64 `json:"-"`
}

type BulkUsersActionOptions struct {
	TargetAdmin    *adminapp.Admin
	ServiceRouteID *int64
}

type InboundInfo struct {
	Tag             string
	Protocol        string
	HasEnabledHosts bool
	ServiceIDs      []int64
}

type ServiceInfo struct {
	ID              int64
	Name            string
	AdminIDs        []int64
	HasActiveHosts  bool
	AllowedInbounds map[string][]string
}

type UserSnapshot struct {
	ID          int64
	Username    string
	Status      UserStatus
	UsedTraffic int64
	DataLimit   *int64
	ServiceID   *int64
	AdminID     *int64
}

type MutationContext struct {
	ActiveUsers        int64
	ServiceActiveUsers map[int64]int64
	Services           map[int64]ServiceInfo
	Inbounds           map[string]InboundInfo
	ExistingUser       *UserSnapshot
}

func (p UserServiceCreate) ToUserCreate(service ServiceInfo) UserCreate {
	_ = service
	return UserCreate{
		UserPayloadBase: UserPayloadBase{
			CredentialKey:          p.CredentialKey,
			Proxies:                ProxyPayload{},
			Flow:                   p.Flow,
			Expire:                 p.Expire,
			DataLimit:              p.DataLimit,
			DataLimitResetStrategy: p.DataLimitResetStrategy,
			Inbounds:               map[string][]string{},
			Note:                   p.Note,
			OnHoldExpireDuration:   p.OnHoldExpireDuration,
			OnHoldTimeout:          p.OnHoldTimeout,
			IPLimit:                p.IPLimit,
			AutoDeleteInDays:       p.AutoDeleteInDays,
			NextPlans:              p.NextPlans,
		},
		Username: p.Username,
		Status:   p.Status,
	}
}
