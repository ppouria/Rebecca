import {
	Alert,
	AlertIcon,
	Box,
	Button,
	FormControl,
	FormLabel,
	HStack,
	Modal,
	ModalBody,
	ModalCloseButton,
	ModalContent,
	ModalFooter,
	ModalHeader,
	ModalOverlay,
	Popover,
	PopoverBody,
	PopoverContent,
	PopoverHeader,
	PopoverTrigger,
	Progress,
	Stack,
	Text,
	useToast,
} from "@chakra-ui/react";
import {
	ArchiveBoxIcon,
	ArrowDownTrayIcon,
	ArrowUpTrayIcon,
} from "@heroicons/react/24/outline";
import { PanelSelect as Select } from "components/common/PanelSelect";
import { useState } from "react";
import { useTranslation } from "react-i18next";
import { useMutation } from "react-query";
import {
	exportRebeccaBackup,
	importRebeccaBackup,
	type RebeccaBackupScope,
} from "service/settings";
import {
	generateErrorMessage,
	generateSuccessMessage,
} from "utils/toastHandler";
import { FileDropzone } from "./common/FileDropzone";

const buildBackupFilename = (scope: RebeccaBackupScope) => {
	const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
	return `rebecca-${scope}-${timestamp}.rbbackup`;
};

type BackupDialog = "import" | "export" | null;

export const DashboardBackupControls = ({
	isBinaryRuntime,
	runtimeLoading,
}: {
	isBinaryRuntime: boolean;
	runtimeLoading: boolean;
}) => {
	const { t } = useTranslation();
	const toast = useToast();
	const [isMenuOpen, setMenuOpen] = useState(false);
	const [dialog, setDialog] = useState<BackupDialog>(null);
	const [exportScope, setExportScope] =
		useState<RebeccaBackupScope>("database");
	const [selectedFile, setSelectedFile] = useState<File | null>(null);
	const [uploadProgress, setUploadProgress] = useState<number | null>(null);
	const backupActionsAvailable = isBinaryRuntime && !runtimeLoading;

	const exportMutation = useMutation(exportRebeccaBackup, {
		onSuccess: (blob, scope) => {
			const url = URL.createObjectURL(blob);
			const anchor = document.createElement("a");
			anchor.href = url;
			anchor.download = buildBackupFilename(scope);
			document.body.appendChild(anchor);
			anchor.click();
			anchor.remove();
			URL.revokeObjectURL(url);
			setDialog(null);
			generateSuccessMessage(t("dashboard.backup.exportReady"), toast);
		},
		onError: (error) => {
			generateErrorMessage(error, toast);
		},
	});

	const importMutation = useMutation(
		(file: File) => importRebeccaBackup(file, setUploadProgress),
		{
			onMutate: () => setUploadProgress(0),
			onSuccess: (result) => {
				generateSuccessMessage(
					t("dashboard.backup.importDone", {
						tables: result.tables_restored,
						rows: result.rows_restored,
					}),
					toast,
				);
				if (result.warnings.length) {
					toast({
						status: "warning",
						title: t("dashboard.backup.importWarnings"),
						description: result.warnings.join("\n"),
						duration: 8000,
						isClosable: true,
					});
				}
				setSelectedFile(null);
				setDialog(null);
			},
			onError: (error) => {
				generateErrorMessage(error, toast);
			},
			onSettled: () => setUploadProgress(null),
		},
	);

	const openDialog = (nextDialog: Exclude<BackupDialog, null>) => {
		setMenuOpen(false);
		setDialog(nextDialog);
	};

	const handleImport = () => {
		if (!selectedFile) {
			toast({ status: "warning", title: t("dashboard.backup.fileRequired") });
			return;
		}
		importMutation.mutate(selectedFile);
	};

	return (
		<>
			<Popover
				isOpen={isMenuOpen}
				onOpen={() => setMenuOpen(true)}
				onClose={() => setMenuOpen(false)}
				placement="bottom-end"
				closeOnBlur={true}
				isLazy
			>
				<PopoverTrigger>
					<Button
						size="xs"
						h="32px"
						w={{ base: "full", sm: "auto" }}
						px={3.5}
						variant="outline"
						borderRadius="full"
						isDisabled={!backupActionsAvailable || runtimeLoading}
						borderColor="panel.border"
						color="panel.text"
						_hover={{ bg: "panel.elevated", borderColor: "panel.borderStrong" }}
						transition="border-color 0.25s ease, background-color 0.25s ease"
						whiteSpace="nowrap"
					>
						<HStack spacing={1.5} align="center" justify="center" w="full">
							<Box as="span" display="inline-flex" alignItems="center" justifyContent="center" flexShrink={0}>
								<ArchiveBoxIcon width={15} height={15} />
							</Box>
							<Text as="span" fontSize="12px" fontWeight="600" lineHeight="none">
								{t("dashboard.backup.tabTitle")}
							</Text>
						</HStack>
					</Button>
				</PopoverTrigger>
				<PopoverContent
					w="min(280px, calc(100vw - 24px))"
					borderRadius="2xl"
					boxShadow="0 24px 60px rgba(0,0,0,0.5)"
					bg="panel.surface"
					borderColor="panel.border"
					borderWidth="1px"
				>
					<PopoverHeader fontWeight="700" fontSize="13px" py={3} px={4} borderColor="panel.border">
						{t("dashboard.backup.title")}
					</PopoverHeader>
					<PopoverBody p={2}>
						<Stack spacing={1}>
							<Button
								variant="ghost"
								justifyContent="flex-start"
								fontSize="13px"
								borderRadius="xl"
								h="36px"
								leftIcon={<ArrowUpTrayIcon width={16} height={16} />}
								onClick={() => openDialog("import")}
								_hover={{ bg: "panel.elevated" }}
								transition="background-color 0.2s ease"
							>
								{t("dashboard.backup.import")}
							</Button>
							<Button
								variant="ghost"
								justifyContent="flex-start"
								fontSize="13px"
								borderRadius="xl"
								h="36px"
								leftIcon={<ArrowDownTrayIcon width={16} height={16} />}
								onClick={() => openDialog("export")}
								_hover={{ bg: "panel.elevated" }}
								transition="background-color 0.2s ease"
							>
								{t("dashboard.backup.exportTitle")}
							</Button>
						</Stack>
					</PopoverBody>
				</PopoverContent>
			</Popover>

			<Modal
				isOpen={dialog === "import"}
				onClose={() => setDialog(null)}
				isCentered
				size="xl"
				closeOnOverlayClick={!importMutation.isLoading}
			>
				<ModalOverlay bg="blackAlpha.700" backdropFilter="blur(8px)" />
				<ModalContent
					borderWidth="1px"
					borderColor="panel.border"
					borderRadius="2xl"
					boxShadow="0 32px 80px rgba(0,0,0,0.5)"
					bg="panel.surface"
					mx={{ base: 4, sm: 0 }}
				>
					<ModalHeader fontSize="md" fontWeight="700" color="panel.text">{t("dashboard.backup.import")}</ModalHeader>
					<ModalCloseButton isDisabled={importMutation.isLoading} />
					<ModalBody py={4}>
						<Stack spacing={4}>
							<Text fontSize="13px" color="panel.textMuted">
								{t("dashboard.backup.importHint")}
							</Text>
							<Alert status="warning" borderRadius="xl" fontSize="13px">
								<AlertIcon />
								<Text fontSize="12px">
									{t("dashboard.backup.autoDetectImportWarning")}
								</Text>
							</Alert>
							<FormControl isRequired>
								<FormLabel fontSize="13px" fontWeight="600" color="panel.textSecondary">{t("dashboard.backup.file")}</FormLabel>
								<FileDropzone
									accept=".rbbackup,.tar.gz,.tgz,.zip,application/vnd.rebecca.backup,application/gzip,application/x-gzip,application/zip,application/x-tar,application/octet-stream"
									isDisabled={
										!backupActionsAvailable || importMutation.isLoading
									}
									selectedFile={selectedFile}
									title={t("dashboard.backup.dropTitle")}
									description={t("dashboard.backup.dropHint")}
									emptyText={t("dashboard.backup.selectFile")}
									onFileSelect={setSelectedFile}
								/>
							</FormControl>
							{importMutation.isLoading && uploadProgress !== null && (
								<Stack spacing={2} aria-live="polite">
									<Text fontSize="12px" fontWeight="600">
										{uploadProgress < 100
											? t("dashboard.backup.uploadProgress", {
													percent: uploadProgress,
												})
											: t("dashboard.backup.processing")}
									</Text>
									<Progress
										value={uploadProgress}
										isIndeterminate={uploadProgress >= 100}
										colorScheme="primary"
										borderRadius="full"
										size="xs"
										h="4px"
									/>
								</Stack>
							)}
						</Stack>
					</ModalBody>
					<ModalFooter gap={2} borderTopWidth="1px" borderColor="panel.border">
						<Button
							variant="ghost"
							size="sm"
							borderRadius="full"
							onClick={() => setDialog(null)}
							isDisabled={importMutation.isLoading}
						>
							{t("cancel")}
						</Button>
						<Button
							colorScheme="red"
							size="sm"
							borderRadius="full"
							px={5}
							leftIcon={<ArrowUpTrayIcon width={15} height={15} />}
							onClick={handleImport}
							isLoading={importMutation.isLoading}
						>
							{t("dashboard.backup.import")}
						</Button>
					</ModalFooter>
				</ModalContent>
			</Modal>

			<Modal
				isOpen={dialog === "export"}
				onClose={() => setDialog(null)}
				isCentered
				size="md"
				closeOnOverlayClick={!exportMutation.isLoading}
			>
				<ModalOverlay bg="blackAlpha.700" backdropFilter="blur(8px)" />
				<ModalContent
					borderWidth="1px"
					borderColor="panel.border"
					borderRadius="2xl"
					boxShadow="0 32px 80px rgba(0,0,0,0.5)"
					bg="panel.surface"
					mx={{ base: 4, sm: 0 }}
				>
					<ModalHeader fontSize="md" fontWeight="700" color="panel.text">{t("dashboard.backup.exportTitle")}</ModalHeader>
					<ModalCloseButton isDisabled={exportMutation.isLoading} />
					<ModalBody py={4}>
						<Stack spacing={4}>
							<Text fontSize="13px" color="panel.textMuted">
								{t("dashboard.backup.exportHint")}
							</Text>
							<FormControl>
								<FormLabel fontSize="13px" fontWeight="600" color="panel.textSecondary">{t("dashboard.backup.scope")}</FormLabel>
								<Select
									value={exportScope}
									showSearch={false}
									onChange={(event) =>
										setExportScope(event.target.value as RebeccaBackupScope)
									}
								>
									<option value="database">
										{t("dashboard.backup.databaseOnly")}
									</option>
									<option value="full">{t("dashboard.backup.full")}</option>
								</Select>
							</FormControl>
						</Stack>
					</ModalBody>
					<ModalFooter gap={2} borderTopWidth="1px" borderColor="panel.border">
						<Button
							variant="ghost"
							size="sm"
							borderRadius="full"
							onClick={() => setDialog(null)}
							isDisabled={exportMutation.isLoading}
						>
							{t("cancel")}
						</Button>
						<Button
							colorScheme="primary"
							size="sm"
							borderRadius="full"
							px={5}
							leftIcon={<ArrowDownTrayIcon width={15} height={15} />}
							onClick={() => exportMutation.mutate(exportScope)}
							isLoading={exportMutation.isLoading}
						>
							{t("dashboard.backup.download")}
						</Button>
					</ModalFooter>
				</ModalContent>
			</Modal>
		</>
	);
};
