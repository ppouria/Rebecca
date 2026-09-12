import {
	Alert,
	AlertIcon,
	Box,
	Button,
	Checkbox,
	chakra,
	FormControl,
	FormHelperText,
	FormLabel,
	HStack,
	IconButton,
	SimpleGrid,
	Stack,
	Text,
	Textarea,
	Tooltip,
	useBreakpointValue,
	useDisclosure,
	useToast,
	VStack,
} from "@chakra-ui/react";
import { SparklesIcon } from "@heroicons/react/24/outline";
import { PanelSelect as Select } from "components/common/PanelSelect";
import { AppDialog } from "components/dialogs/AppDialog";
import { useAdminsStore } from "contexts/AdminsContext";
import { useDashboard } from "contexts/DashboardContext";
import { useServicesStore } from "contexts/ServicesContext";
import useGetUser from "hooks/useGetUser";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { AdminRole, AdminTrafficLimitMode } from "types/Admin";
import type {
	AdvancedUserActionPayload,
	AdvancedUserActionScopeStatus,
	AdvancedUserActionStatus,
	AdvancedUserActionType,
} from "types/User";
import { isUserManagementLocked } from "utils/adminTraffic";
import { NumericInput } from "./common/NumericInput";

// `className="w-4 h-4"` (Tailwind) is a no-op in this project - there is no
// Tailwind build step - so the raw 24x24 heroicon rendered ~2.4x oversized
// next to the neighboring 16px icons. Size it the same way every other
// toolbar icon in this codebase is sized, via Chakra's style props.
const AdvancedActionsIcon = chakra(SparklesIcon, {
	baseStyle: { w: 4, h: 4 },
});

const cleanupOptions: AdvancedUserActionStatus[] = ["expired", "limited"];
const scopeStatusOptions: AdvancedUserActionScopeStatus[] = [
	"active",
	"on_hold",
	"limited",
	"expired",
	"disabled",
];
type ServiceScopePayload = Partial<
	Pick<AdvancedUserActionPayload, "service_id">
>;

type OwnerSelection = "my_users" | "all_users" | `admin:${string}`;

const parseTargetUsernames = (value: string) =>
	Array.from(
		new Set(
			value
				.split(/[\n,]+/)
				.map((item) => item.trim())
				.filter(Boolean),
		),
	).slice(0, 500);

type AdvancedUserActionsProps = {
	/** Render the trigger as a round icon button for tight toolbars. */
	compact?: boolean;
	/** Render the controls directly inside the Bulk Actions page. */
	embedded?: boolean;
};

const AdvancedUserActions = ({
	compact = false,
	embedded = false,
}: AdvancedUserActionsProps) => {
	const { t } = useTranslation();
	const toast = useToast();
	const performBulkUserAction = useDashboard(
		(state) => state.performBulkUserAction,
	);
	const { userData } = useGetUser();
	const userManagementLocked = isUserManagementLocked(userData);
	const { isOpen, onOpen, onClose } = useDisclosure();
	const [expireDays, setExpireDays] = useState("");
	const [expireFactor, setExpireFactor] = useState("");
	const [trafficGb, setTrafficGb] = useState("");
	const [trafficFactor, setTrafficFactor] = useState("");
	const [cleanupDays, setCleanupDays] = useState("");
	const [selectedStatuses, setSelectedStatuses] = useState<
		AdvancedUserActionStatus[]
	>(["expired", "limited"]);
	const [selectedScopeStatuses, setSelectedScopeStatuses] = useState<
		AdvancedUserActionScopeStatus[]
	>(["active"]);
	const [isExtending, setIsExtending] = useState(false);
	const [isReducing, setIsReducing] = useState(false);
	const [isMultiplyingExpire, setIsMultiplyingExpire] = useState(false);
	const [isDividingExpire, setIsDividingExpire] = useState(false);
	const [isMultiplyingTraffic, setIsMultiplyingTraffic] = useState(false);
	const [isDividingTraffic, setIsDividingTraffic] = useState(false);
	const [isIncreasingTraffic, setIsIncreasingTraffic] = useState(false);
	const [isDecreasingTraffic, setIsDecreasingTraffic] = useState(false);
	const [isCleaning, setIsCleaning] = useState(false);
	const [ownerSelection, setOwnerSelection] =
		useState<OwnerSelection>("my_users");
	const [selectedServiceValue, setSelectedServiceValue] = useState("");
	const [targetServiceValue, setTargetServiceValue] = useState("");
	const [targetUsernames, setTargetUsernames] = useState("");
	const [lastOnlineDays, setLastOnlineDays] = useState("");
	const [statusAgeDays, setStatusAgeDays] = useState("");
	const [createdBeforeDays, setCreatedBeforeDays] = useState("");
	const [isChangingService, setIsChangingService] = useState(false);
	const adminList = useAdminsStore((store) => store.adminOptions);
	const adminOptionsLoading = useAdminsStore(
		(store) => store.adminOptionsLoading,
	);
	const fetchAdminOptions = useAdminsStore(
		(store) => store.fetchAdminOptions,
	);
	const serviceOptions = useServicesStore((store) => store.serviceOptions);
	const serviceOptionsLoading = useServicesStore(
		(store) => store.isOptionsLoading,
	);
	const fetchServiceOptions = useServicesStore(
		(store) => store.fetchServiceOptions,
	);

	const hasScopeSelect =
		userData.role === AdminRole.Sudo || userData.role === AdminRole.FullAccess;
	const canSeeServiceControls = hasScopeSelect;
	const canUseAdvanced = Boolean(
		userData.permissions?.users?.advanced_actions ?? true,
	);
	const serviceTransferDisabled = Boolean(
		userData.use_service_traffic_limits ||
			userData.traffic_limit_mode === AdminTrafficLimitMode.CreatedTraffic,
	);

	useEffect(() => {
		if (!isOpen && !embedded) return;
		if (hasScopeSelect && !adminList.length && !adminOptionsLoading) {
			void fetchAdminOptions({ limit: 1000, offset: 0, sort: "username" });
		}
		if (!serviceOptions.length && !serviceOptionsLoading) {
			void fetchServiceOptions({ limit: 1000, offset: 0 });
		}
	}, [
		adminList.length,
		adminOptionsLoading,
		embedded,
		fetchAdminOptions,
		fetchServiceOptions,
		hasScopeSelect,
		isOpen,
		serviceOptions.length,
		serviceOptionsLoading,
	]);

	const resolveTargetAdminUsername = () => {
		if (!hasScopeSelect) {
			return userData.username;
		}
		if (ownerSelection === "all_users") {
			return null;
		}
		if (ownerSelection === "my_users") {
			return userData.username;
		}
		if (ownerSelection.startsWith("admin:")) {
			return ownerSelection.replace(/^admin:/, "");
		}
		return userData.username;
	};

	const showToast = (
		description: string,
		status: "success" | "error" | "warning",
	) => {
		toast({
			title: t("filters.advancedActions.modalTitle"),
			description,
			status,
			isClosable: true,
		});
	};

	const resolveErrorMessage = (error?: unknown, fallback?: string) => {
		if (error && typeof error === "object") {
			const maybe = error as { data?: { detail?: string }; message?: string };
			return maybe.data?.detail || maybe.message || fallback;
		}
		return fallback;
	};

	const handleError = (message?: string) => {
		showToast(
			message ??
				t("filters.advancedActions.error.general"),
			"error",
		);
	};

	const buildServiceScopePayload = (): ServiceScopePayload => {
		if (!selectedServiceValue) {
			return {};
		}
		return { service_id: Number(selectedServiceValue) };
	};

	const buildTargetingPayload = (
		includeStatusAge = true,
	): Partial<AdvancedUserActionPayload> | null => {
		const parseDays = (value: string) => Math.floor(Number(value));
		const payload: Partial<AdvancedUserActionPayload> = {};
		const usernames = parseTargetUsernames(targetUsernames);
		if (targetUsernames.trim() && !usernames.length) {
			handleError(t("filters.advancedActions.error.invalidUsernames"));
			return null;
		}
		if (usernames.length) payload.usernames = usernames;
		for (const item of [
			{ value: lastOnlineDays, key: "last_online_days" as const },
			{ value: createdBeforeDays, key: "created_before_days" as const },
			...(includeStatusAge
				? [{ value: statusAgeDays, key: "status_age_days" as const }]
				: []),
		]) {
			if (!item.value.trim()) continue;
			const days = parseDays(item.value);
			if (!Number.isFinite(days) || days <= 0) {
				handleError(t("filters.advancedActions.error.invalidDays"));
				return null;
			}
			payload[item.key] = days;
		}
		return payload;
	};

	const handleExpireAction = async (action: AdvancedUserActionType) => {
		const days = Number(expireDays);
		if (!Number.isFinite(days) || days <= 0) {
			showToast(
				t("filters.advancedActions.error.invalidDays"),
				"warning",
			);
			return;
		}
		if (!selectedScopeStatuses.length) {
			showToast(
				t("filters.advancedActions.error.noScope"),
				"warning",
			);
			return;
		}
		const targeting = buildTargetingPayload();
		if (!targeting) return;
		const setLoading =
			action === "extend_expire" ? setIsExtending : setIsReducing;
		setLoading(true);
		try {
			const targetAdminUsername = resolveTargetAdminUsername();
			const payload: AdvancedUserActionPayload = {
				action,
				days: Math.floor(days),
				scope: selectedScopeStatuses,
				admin_username: targetAdminUsername,
				...buildServiceScopePayload(),
				...targeting,
			};
			const result = await performBulkUserAction(payload);
			showToast(
				t("filters.advancedActions.success.expire", {
					count: result.count ?? 0,
				}),
				"success",
			);
			setExpireDays("");
		} catch (error) {
			handleError(resolveErrorMessage(error));
		} finally {
			setLoading(false);
		}
	};

	const handleExpireFactorAction = async (action: AdvancedUserActionType) => {
		const factor = Number(expireFactor);
		if (!Number.isFinite(factor) || factor <= 0) {
			showToast(
				t("filters.advancedActions.error.invalidFactor"),
				"warning",
			);
			return;
		}
		if (!selectedScopeStatuses.length) {
			showToast(
				t("filters.advancedActions.error.noScope"),
				"warning",
			);
			return;
		}
		const targeting = buildTargetingPayload();
		if (!targeting) return;
		
		const setLoading = action === "multiply_expire" ? setIsMultiplyingExpire : setIsDividingExpire;
		setLoading(true);
		
		try {
			const targetAdminUsername = resolveTargetAdminUsername();
			const payload: AdvancedUserActionPayload = {
				action,
				factor,
				scope: selectedScopeStatuses,
				admin_username: targetAdminUsername,
				...buildServiceScopePayload(),
				...targeting,
			} as AdvancedUserActionPayload;
			
			const result = await performBulkUserAction(payload);
			showToast(
				t("filters.advancedActions.success.expire", {
					count: result.count ?? 0,
				}),
				"success",
			);
			setExpireFactor("");
		} catch (error) {
			handleError(resolveErrorMessage(error));
		} finally {
			setLoading(false);
		}
	};

	const handleTrafficAction = async (action: AdvancedUserActionType) => {
		const value = Number(trafficGb);
		if (!Number.isFinite(value) || value <= 0) {
			showToast(
				t("filters.advancedActions.error.invalidGigabytes"),
				"warning",
			);
			return;
		}
		if (!selectedScopeStatuses.length) {
			showToast(
				t("filters.advancedActions.error.noScope"),
				"warning",
			);
			return;
		}
		const targeting = buildTargetingPayload();
		if (!targeting) return;
		const setLoading =
			action === "increase_traffic"
				? setIsIncreasingTraffic
				: setIsDecreasingTraffic;
		setLoading(true);
		try {
			const targetAdminUsername = resolveTargetAdminUsername();
			const payload: AdvancedUserActionPayload = {
				action,
				gigabytes: value,
				scope: selectedScopeStatuses,
				admin_username: targetAdminUsername,
				...buildServiceScopePayload(),
				...targeting,
			};
			const result = await performBulkUserAction(payload);
			showToast(
				t("filters.advancedActions.success.traffic", {
					count: result.count ?? 0,
					value,
				}),
				"success",
			);
			setTrafficGb("");
		} catch (error) {
			handleError(resolveErrorMessage(error));
		} finally {
			setLoading(false);
		}
	};

	const handleTrafficFactorAction = async (action: AdvancedUserActionType) => {
		const factor = Number(trafficFactor);
		if (!Number.isFinite(factor) || factor <= 0) {
			showToast(
				t("filters.advancedActions.error.invalidFactor"),
				"warning",
			);
			return;
		}
		if (!selectedScopeStatuses.length) {
			showToast(
				t("filters.advancedActions.error.noScope"),
				"warning",
			);
			return;
		}
		const targeting = buildTargetingPayload();
		if (!targeting) return;
		
		const setLoading = action === "multiply_traffic" ? setIsMultiplyingTraffic : setIsDividingTraffic;
		setLoading(true);
		
		try {
			const targetAdminUsername = resolveTargetAdminUsername();
			const payload: AdvancedUserActionPayload = {
				action,
				factor,
				scope: selectedScopeStatuses,
				admin_username: targetAdminUsername,
				...buildServiceScopePayload(),
				...targeting,
			} as AdvancedUserActionPayload;
			
			const result = await performBulkUserAction(payload);
			showToast(
				t("filters.advancedActions.success.traffic", {
					count: result.count ?? 0,
					value: factor,
				}),
				"success",
			);
			setTrafficFactor("");
		} catch (error) {
			handleError(resolveErrorMessage(error));
		} finally {
			setLoading(false);
		}
	};

	const handleCleanup = async () => {
		const days = Number(cleanupDays);
		if (!Number.isFinite(days) || days <= 0) {
			showToast(
				t("filters.advancedActions.error.invalidDays"),
				"warning",
			);
			return;
		}
		if (!selectedStatuses.length) {
			showToast(
				t("filters.advancedActions.error.noStatuses"),
				"warning",
			);
			return;
		}
		const targeting = buildTargetingPayload(false);
		if (!targeting) return;
		setIsCleaning(true);
		try {
			const targetAdminUsername = resolveTargetAdminUsername();
			const payload: AdvancedUserActionPayload = {
				action: "cleanup_status",
				days: Math.floor(days),
				statuses: selectedStatuses,
				scope: selectedStatuses,
				admin_username: targetAdminUsername,
				...buildServiceScopePayload(),
				...targeting,
			};
			const result = await performBulkUserAction(payload);
			showToast(
				t("filters.advancedActions.success.cleanup", {
					count: result.count ?? 0,
				}),
				"success",
			);
			setCleanupDays("");
		} catch (error) {
			handleError(resolveErrorMessage(error));
		} finally {
			setIsCleaning(false);
		}
	};

	const handleChangeService = async () => {
		if (!targetServiceValue) {
			showToast(
				t("filters.advancedActions.error.targetServiceRequired"),
				"warning",
			);
			return;
		}
		const targeting = buildTargetingPayload();
		if (!targeting) return;
		const resolvedTargetServiceId = Number(targetServiceValue);
		if (
			!Number.isFinite(resolvedTargetServiceId) ||
			resolvedTargetServiceId <= 0
		) {
			showToast(
				t("filters.advancedActions.error.targetServiceRequired"),
				"warning",
			);
			return;
		}
		setIsChangingService(true);
		try {
			const payload: AdvancedUserActionPayload = {
				action: "change_service",
				admin_username: resolveTargetAdminUsername(),
				...buildServiceScopePayload(),
				target_service_id: resolvedTargetServiceId,
				...(targeting.status_age_days
					? { scope: selectedScopeStatuses }
					: {}),
				...targeting,
			};
			const result = await performBulkUserAction(payload);
			showToast(
				t("filters.advancedActions.success.changeService", {
					count: result.count ?? 0,
				}),
				"success",
			);
		} catch (error) {
			handleError(resolveErrorMessage(error));
		} finally {
			setIsChangingService(false);
		}
	};

	const toggleStatus = (status: AdvancedUserActionStatus) => {
		setSelectedStatuses((prev) =>
			prev.includes(status)
				? prev.filter((item) => item !== status)
				: [...prev, status],
		);
	};

	const toggleScopeStatus = (status: AdvancedUserActionScopeStatus) => {
		setSelectedScopeStatuses((prev) =>
			prev.includes(status)
				? prev.filter((item) => item !== status)
				: [...prev, status],
		);
	};

	const isMobile = useBreakpointValue({ base: true, sm: false }) ?? false;

	if (!canUseAdvanced || userManagementLocked) {
		return null;
	}

	const content = (
		<VStack spacing={6} align="stretch">
			<Alert status="warning" borderRadius="md">
				<AlertIcon />
				<Text>
					{t("filters.advancedActions.modalDescription")}
				</Text>
			</Alert>

			{hasScopeSelect && (
				<FormControl>
					<FormLabel fontWeight="semibold">
						{t("filters.advancedActions.scope.label")}
					</FormLabel>
					<Select
						value={ownerSelection}
						onChange={(event) => {
							const nextValue = event.target.value;
							if (
								nextValue === "my_users" ||
								nextValue === "all_users" ||
								nextValue.startsWith("admin:")
							) {
								setOwnerSelection(nextValue as OwnerSelection);
							}
						}}
						size="sm"
					>
						<option value="my_users">
							{t("filters.advancedActions.scope.myUsers")}
						</option>
						<option value="all_users">
							{t("filters.advancedActions.scope.allUsers")}
						</option>
						{adminList
							.filter((record) => record.username !== userData.username)
							.map((record) => (
								<option
									key={record.username}
									value={`admin:${record.username}`}
								>
									{record.username}
								</option>
							))}
					</Select>
					<FormHelperText fontSize="sm">
						{t("filters.advancedActions.scope.helper")}
					</FormHelperText>
				</FormControl>
			)}

			{canSeeServiceControls && (
				<>
					<FormControl>
						<FormLabel fontWeight="semibold">
							{t("filters.advancedActions.service.label")}
						</FormLabel>
						<Select
							value={selectedServiceValue}
							onChange={(event) => {
								setSelectedServiceValue(event.target.value);
							}}
							size="sm"
						>
							<option value="">
								{t("filters.advancedActions.service.all")}
							</option>
							{serviceOptions.map((service) => (
								<option key={service.id} value={String(service.id)}>
									{service.name}
								</option>
							))}
						</Select>
						<FormHelperText fontSize="sm">
							{t("filters.advancedActions.service.helper")}
						</FormHelperText>
					</FormControl>

					{!serviceTransferDisabled && (
						<Box borderWidth="1px" borderRadius="md" px={4} py={4}>
							<Stack spacing={3}>
								<Text fontWeight="semibold">
									{t("filters.advancedActions.serviceChange.title")}
								</Text>
								<Text fontSize="sm" color="gray.500">
									{t("filters.advancedActions.serviceChange.helper")}
								</Text>
								<Select
									placeholder={t("filters.advancedActions.serviceChange.placeholder")}
									value={targetServiceValue}
									onChange={(event) =>
										setTargetServiceValue(event.target.value)
									}
									size="sm"
								>
									{serviceOptions.map((service) => (
										<option key={service.id} value={String(service.id)}>
											{service.name}
										</option>
									))}
								</Select>
								<Button
									colorScheme="primary"
									size="sm"
									alignSelf="flex-start"
									isLoading={isChangingService}
									onClick={handleChangeService}
								>
									{t("filters.advancedActions.serviceChange.button")}
								</Button>
							</Stack>
						</Box>
					)}
				</>
			)}

			<Box borderWidth="1px" borderRadius="md" px={4} py={4}>
				<Stack spacing={3}>
					<Box>
						<Text fontWeight="semibold">
							{t("filters.advancedActions.conditions.title")}
						</Text>
						<Text fontSize="sm" color="gray.500">
							{t("filters.advancedActions.conditions.help")}
						</Text>
					</Box>
					<FormControl>
						<FormLabel fontSize="sm">
							{t("filters.advancedActions.conditions.usernames")}
						</FormLabel>
						<Textarea
							value={targetUsernames}
							onChange={(event) => setTargetUsernames(event.target.value)}
							rows={3}
							fontFamily="mono"
							placeholder={t("filters.advancedActions.conditions.usernamesPlaceholder")}
						/>
						<FormHelperText>
							{t("filters.advancedActions.conditions.usernamesHelp")}
						</FormHelperText>
					</FormControl>
					<SimpleGrid columns={{ base: 1, md: 3 }} spacing={3}>
						<FormControl>
							<FormLabel fontSize="sm">
								{t("filters.advancedActions.conditions.lastOnline")}
							</FormLabel>
							<NumericInput
								value={lastOnlineDays}
								onChange={(value) => setLastOnlineDays(value)}
								min={1}
								step={1}
								w="full"
							/>
						</FormControl>
						<FormControl>
							<FormLabel fontSize="sm">
								{t("filters.advancedActions.conditions.statusAge")}
							</FormLabel>
							<NumericInput
								value={statusAgeDays}
								onChange={(value) => setStatusAgeDays(value)}
								min={1}
								step={1}
								w="full"
							/>
						</FormControl>
						<FormControl>
							<FormLabel fontSize="sm">
								{t("filters.advancedActions.conditions.createdBefore")}
							</FormLabel>
							<NumericInput
								value={createdBeforeDays}
								onChange={(value) => setCreatedBeforeDays(value)}
								min={1}
								step={1}
								w="full"
							/>
						</FormControl>
					</SimpleGrid>
				</Stack>
			</Box>

			<Box borderWidth="1px" borderRadius="md" px={4} py={4}>
				<Stack spacing={2}>
					<Text fontWeight="semibold">
						{t("filters.advancedActions.scopeStatuses.title")}
					</Text>
					<Text fontSize="sm" color="gray.500">
						{t("filters.advancedActions.scopeStatuses.helper")}
					</Text>
					<HStack spacing={3} flexWrap="wrap">
						{scopeStatusOptions.map((status) => (
							<Checkbox
								key={status}
								isChecked={selectedScopeStatuses.includes(status)}
								onChange={() => toggleScopeStatus(status)}
							>
								{t(
									`filters.advancedActions.scopeStatuses.${status}`,
									status.replace("_", " "),
								)}
							</Checkbox>
						))}
					</HStack>
				</Stack>
			</Box>

			<Stack spacing={4}>
				<Box borderWidth="1px" borderRadius="md" px={4} py={4}>
					<Stack spacing={2}>
						<Text fontWeight="semibold">
							{t("filters.advancedActions.expireSection.title")}
						</Text>
						<Text fontSize="sm" color="gray.500">
							{t("filters.advancedActions.expireSection.description")}
						</Text>
						<FormControl>
							<FormLabel>
								{t("filters.advancedActions.expireSection.inputLabel")}
							</FormLabel>
							<NumericInput
								value={expireDays}
								onChange={(value) => setExpireDays(value)}
								min={1}
								step={1}
								w="full"
							/>
							<FormHelperText>
								{t("filters.advancedActions.expireSection.helper")}
							</FormHelperText>
						</FormControl>
						<HStack spacing={2} flexWrap="wrap">
							<Button
								colorScheme="primary"
								isLoading={isExtending}
								flex="1"
								minW="150px"
								onClick={() => handleExpireAction("extend_expire")}
							>
								{t("filters.advancedActions.expireSection.addButton")}
							</Button>
							<Button
								colorScheme="gray"
								variant="outline"
								isLoading={isReducing}
								flex="1"
								minW="150px"
								onClick={() => handleExpireAction("reduce_expire")}
							>
								{t("filters.advancedActions.expireSection.removeButton")}
							</Button>
						</HStack>
						
						<FormControl mt={4}>
							<FormLabel>
								{t("filters.advancedActions.expireSection.factorLabel")}
							</FormLabel>
							<NumericInput
								value={expireFactor}
								onChange={(value) => setExpireFactor(value)}
								min={0.01}
								step={0.1}
								w="full"
							/>
						</FormControl>
						<HStack spacing={2} flexWrap="wrap" mt={2}>
							<Button
								colorScheme="primary"
								isLoading={isMultiplyingExpire}
								flex="1"
								minW="150px"
								onClick={() => handleExpireFactorAction("multiply_expire")}
							>
								{t("filters.advancedActions.expireSection.multiplyButton")}
							</Button>
							<Button
								colorScheme="gray"
								variant="outline"
								isLoading={isDividingExpire}
								flex="1"
								minW="150px"
								onClick={() => handleExpireFactorAction("divide_expire")}
							>
								{t("filters.advancedActions.expireSection.divideButton")}
							</Button>
						</HStack>

					</Stack>
				</Box>

				<Box borderWidth="1px" borderRadius="md" px={4} py={4}>
					<Stack spacing={2}>
						<Text fontWeight="semibold">
							{t("filters.advancedActions.trafficSection.title")}
						</Text>
						<Text fontSize="sm" color="gray.500">
							{t("filters.advancedActions.trafficSection.description")}
						</Text>
						<FormControl>
							<FormLabel>
								{t("filters.advancedActions.trafficSection.inputLabel")}
							</FormLabel>
							<NumericInput
								value={trafficGb}
								onChange={(value) => setTrafficGb(value)}
								min={0.01}
								step={0.1}
								w="full"
							/>
						</FormControl>
						<HStack spacing={2} flexWrap="wrap">
							<Button
								colorScheme="primary"
								isLoading={isIncreasingTraffic}
								flex="1"
								minW="150px"
								onClick={() => handleTrafficAction("increase_traffic")}
							>
								{t("filters.advancedActions.trafficSection.addButton")}
							</Button>
							<Button
								colorScheme="gray"
								variant="outline"
								isLoading={isDecreasingTraffic}
								flex="1"
								minW="150px"
								onClick={() => handleTrafficAction("decrease_traffic")}
							>
								{t("filters.advancedActions.trafficSection.removeButton")}
							</Button>
						</HStack>

						<FormControl mt={4}>
							<FormLabel>
								{t("filters.advancedActions.trafficSection.factorLabel")}
							</FormLabel>
							<NumericInput
								value={trafficFactor}
								onChange={(value) => setTrafficFactor(value)}
								min={0.01}
								step={0.1}
								w="full"
							/>
						</FormControl>
						<HStack spacing={2} flexWrap="wrap" mt={2}>
							<Button
								colorScheme="primary"
								isLoading={isMultiplyingTraffic}
								flex="1"
								minW="150px"
								onClick={() => handleTrafficFactorAction("multiply_traffic")}
							>
								{t("filters.advancedActions.trafficSection.multiplyButton")}
							</Button>
							<Button
								colorScheme="gray"
								variant="outline"
								isLoading={isDividingTraffic}
								flex="1"
								minW="150px"
								onClick={() => handleTrafficFactorAction("divide_traffic")}
							>
								{t("filters.advancedActions.trafficSection.divideButton")}
							</Button>
						</HStack>

					</Stack>
				</Box>

				<Box borderWidth="1px" borderRadius="md" px={4} py={4}>
					<Stack spacing={2}>
						<Text fontWeight="semibold">
							{t("filters.advancedActions.cleanupSection.title")}
						</Text>
						<Text fontSize="sm" color="gray.500">
							{t("filters.advancedActions.cleanupSection.description")}
						</Text>
						<FormControl>
							<FormLabel>
								{t("filters.advancedActions.cleanupSection.daysLabel")}
							</FormLabel>
							<NumericInput
								value={cleanupDays}
								onChange={(value) => setCleanupDays(value)}
								min={1}
								step={1}
								w="full"
							/>
						</FormControl>
						<HStack spacing={3}>
							{cleanupOptions.map((status) => (
								<Checkbox
									key={status}
									isChecked={selectedStatuses.includes(status)}
									onChange={() => toggleStatus(status)}
								>
									{t(
										`filters.advancedActions.cleanupSection.statuses.${status}`,
										status.charAt(0).toUpperCase() + status.slice(1),
									)}
								</Checkbox>
							))}
						</HStack>
						<Button
							colorScheme="primary"
							isLoading={isCleaning}
							w="full"
							onClick={handleCleanup}
						>
							{t("filters.advancedActions.cleanupSection.button")}
						</Button>
					</Stack>
				</Box>
			</Stack>
		</VStack>
	);

	if (embedded) {
		return content;
	}

	return (
		<>
			{compact ? (
				<Tooltip
					label={t("filters.advancedActions.button")}
				>
					<IconButton
						aria-label={t("filters.advancedActions.button")}
						icon={<AdvancedActionsIcon />}
						onClick={onOpen}
						variant="outline"
						borderRadius="full"
						w="40px"
						h="40px"
						flexShrink={0}
					/>
				</Tooltip>
			) : (
				<Button
					leftIcon={<AdvancedActionsIcon />}
					onClick={onOpen}
					size={isMobile ? "sm" : "md"}
					variant="outline"
					h={isMobile ? "36px" : undefined}
					minW={isMobile ? "auto" : "8.5rem"}
					fontSize={isMobile ? "xs" : "sm"}
					fontWeight="semibold"
					whiteSpace="nowrap"
				>
					{t("filters.advancedActions.button")}
				</Button>
			)}

			<AppDialog
				isOpen={isOpen}
				onClose={onClose}
				size="lg"
				title={t("filters.advancedActions.modalTitle")}
				footer={
					<Button variant="ghost" onClick={onClose}>
						{t("close")}
					</Button>
				}
			>
				{content}
			</AppDialog>
		</>
	);
};

export default AdvancedUserActions;
