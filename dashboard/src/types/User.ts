import type {
	AdminPermissions,
	AdminRole,
	AdminStatus,
	AdminTrafficLimitMode,
} from "./Admin";

export type Status =
	| "active"
	| "disabled"
	| "limited"
	| "expired"
	| "on_hold"
	| "error"
	| "connecting"
	| "connected";
export type ProxyKeys = ("vmess" | "vless" | "trojan" | "shadowsocks")[];
export type ProxyType = {
	vmess?: {
		id?: string;
	};
	vless?: {
		id?: string;
	};
	trojan?: {
		password?: string;
	};
	shadowsocks?: {
		password?: string;
		method?: string;
	};
};

export type DataLimitResetStrategy =
	| "no_reset"
	| "day"
	| "week"
	| "month"
	| "year";

export type UserInbounds = {
	[key: string]: string[];
};
export type NextPlan = {
	data_limit: number | null;
	expire: number | null;
	add_remaining_traffic: boolean;
	fire_on_either: boolean;
};

export type UserLinkData = {
	uuid?: string;
	password?: string;
	password_b64?: string;
	protocol: string;
};

export type User = {
	credential_key?: string | null;
	key_subscription_url?: string | null;
	proxies: ProxyType;
	flow?: string | null;
	expire: number | null;
	data_limit: number | null;
	ip_limit: number | null;
	data_limit_reset_strategy: DataLimitResetStrategy;
	on_hold_expire_duration: number | null;
	lifetime_used_traffic: number;
	username: string;
	used_traffic: number;
	status: Status;
	links: string[]; // Deprecated, use link_data with link_templates instead
	link_data?: UserLinkData[]; // UUID/password for each inbound
	subscription_url: string;
	subscription_urls?: Record<string, string>;
	inbounds: UserInbounds;
	note: string;
	telegram_id?: string | null;
	contact_number?: string | null;
	online_at: string;
	service_id: number | null;
	service_name: string | null;
	admin_username?: string | null;
	service_host_orders: Record<number, number>;
	auto_delete_in_days: number | null;
	next_plans: NextPlan[];
};

export type UserListItem = {
	username: string;
	status: Status;
	used_traffic: number;
	lifetime_used_traffic: number;
	created_at: string;
	expire: number | null;
	data_limit: number | null;
	data_limit_reset_strategy: DataLimitResetStrategy | null;
	online_at?: string | null;
	is_online: boolean;
	upload_speed?: number;
	download_speed?: number;
	service_id: number | null;
	service_name: string | null;
	admin_id?: number | null;
	admin_username?: string | null;
	links?: string[];
	subscription_url: string;
	subscription_urls: Record<string, string>;
};

export type UserCreate = Pick<
	User,
	| "expire"
	| "data_limit"
	| "ip_limit"
	| "data_limit_reset_strategy"
	| "on_hold_expire_duration"
	| "username"
	| "status"
	| "note"
	| "telegram_id"
	| "contact_number"
	| "flow"
	| "credential_key"
	| "service_id"
	| "auto_delete_in_days"
> & {
	next_plans?: NextPlan[];
};

export type UserCreateWithService = Pick<
	User,
	| "username"
	| "status"
	| "expire"
	| "data_limit"
	| "ip_limit"
	| "data_limit_reset_strategy"
	| "on_hold_expire_duration"
	| "note"
	| "telegram_id"
	| "contact_number"
	| "flow"
> & {
	service_id: number;
	auto_delete_in_days?: number | null;
	next_plans?: NextPlan[];
	credential_key?: string;
};

export type UserApi = {
	role: AdminRole;
	permissions: AdminPermissions;
	telegram_id: number | string;
	username: string;
	users_usage?: number | null;
	created_traffic?: number | null;
	deleted_users_usage?: number | null;
	data_limit?: number | null;
	traffic_limit_mode?: AdminTrafficLimitMode;
	use_service_traffic_limits?: boolean;
	show_user_traffic?: boolean;
	delete_user_usage_limit_enabled?: boolean;
	delete_user_usage_limit?: number | null;
	service_limits?: import("./Admin").AdminServiceTrafficLimit[];
	status?: AdminStatus;
	disabled_reason?: string | null;
	require_2fa?: boolean;
	totp_enabled?: boolean;
};

export type UseGetUserReturn = {
	userData: UserApi;
	getUserIsPending: boolean;
	getUserIsSuccess: boolean;
	getUserIsError: boolean;
	getUserError: Error | null;
};

export type UsersListResponse = {
	users: UserListItem[];
	link_templates?: Record<string, string[]>; // Link templates by protocol
	total: number;
	active_total?: number | null;
	users_limit?: number | null;
	status_breakdown?: Record<string, number>;
	usage_total?: number | null;
	online_total?: number | null;
};

export type AdvancedUserActionStatus = "expired" | "limited";

export type AdvancedUserActionScopeStatus =
	| "active"
	| "on_hold"
	| "expired"
	| "limited"
	| "disabled";

export type AdvancedUserActionType =
	| "extend_expire"
	| "reduce_expire"
	| "increase_traffic"
	| "decrease_traffic"
	| "cleanup_status"
	| "activate_users"
	| "disable_users"
	| "change_service"
	| "delete_users"
	| "multiply_expire"
    | "divide_expire"
    | "multiply_traffic"
    | "divide_traffic";

export type AdvancedUserActionPayload = {
	action: AdvancedUserActionType;
	days?: number;
	gigabytes?: number;
	statuses?: AdvancedUserActionStatus[];
	scope?: AdvancedUserActionScopeStatus[];
	admin_username?: string | null;
	service_id?: number;
	service_id_is_null?: boolean;
	target_service_id?: number | null;
	usernames?: string[];
	last_online_days?: number;
	status_age_days?: number;
	created_before_days?: number;
	dry_run?: boolean;
};

export type AdvancedUserActionResponse = {
	detail: string;
	count: number;
};
