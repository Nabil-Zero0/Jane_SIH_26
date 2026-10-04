import { HugeiconsIcon } from "@hugeicons/react";
import {
  DashboardSquare01Icon as RawDashboardSquare01Icon,
  Search01Icon as RawSearch01Icon,
  Activity01Icon as RawActivity01Icon,
  UserGroupIcon as RawUserGroupIcon,
  TestTube01Icon as RawTestTube01Icon,
  ShoppingBag01Icon as RawShoppingBag01Icon,
  HierarchyCircle01Icon as RawHierarchyCircle01Icon,
  Key01Icon as RawKey01Icon,
  GlobalIcon as RawGlobalIcon,
  Archive01Icon as RawArchive01Icon,
  ShieldAlertIcon as RawShieldAlertIcon,
  ShieldCheckIcon as RawShieldCheckIcon,
  File01Icon as RawFile01Icon,
  Settings01Icon as RawSettings01Icon,
  UserIcon as RawUserIcon,
  CreditCardIcon as RawCreditCardIcon,
  Logout01Icon as RawLogout01Icon,
  HelpCircleIcon as RawHelpCircleIcon,
  Notification01Icon as RawNotification01Icon,
  PlusSignIcon as RawPlusSignIcon,
  Copy01Icon as RawCopy01Icon,
  Database01Icon as RawDatabase01Icon,
  Wallet01Icon as RawWallet01Icon,
  Alert01Icon as RawAlert01Icon,
  Clock01Icon as RawClock01Icon,
  BarChartIcon as RawBarChartIcon,
  ArrowRight01Icon as RawArrowRight01Icon,
  ArrowLeft01Icon as RawArrowLeft01Icon,
  ArrowUp01Icon as RawArrowUp01Icon,
  ArrowDown01Icon as RawArrowDown01Icon,
  TrendingUpIcon as RawTrendingUpIcon,
  TrendingDownIcon as RawTrendingDownIcon,
  MinusIcon as RawMinusIcon,
  ChevronRightIcon as RawChevronRightIcon,
  ChevronDownIcon as RawChevronDownIcon,
  ChevronUpIcon as RawChevronUpIcon,
  MoreHorizontalIcon as RawMoreHorizontalIcon,
  CheckIcon as RawCheckIcon,
  CheckmarkCircle01Icon as RawCheckmarkCircle01Icon,
  CircleIcon as RawCircleIcon,
  AlertCircleIcon as RawAlertCircleIcon,
  CancelCircleIcon as RawCancelCircleIcon,
  Cancel01Icon as RawCancel01Icon,
  SidebarLeftIcon as RawSidebarLeftIcon,
} from "@hugeicons/core-free-icons";
import type { ComponentProps } from "react";

export type IconProps = Omit<ComponentProps<typeof HugeiconsIcon>, "icon" | "strokeWidth"> & {
  size?: number | string;
  strokeWidth?: number | string;
  className?: string;
  [key: string]: any;
};

function createIcon(iconSvg: any) {
  return function HugeIconComponent({
    size = 18,
    strokeWidth = 1.5,
    className,
    ...props
  }: IconProps) {
    const sw =
      typeof strokeWidth === "string"
        ? parseFloat(strokeWidth) || 1.5
        : typeof strokeWidth === "number"
        ? strokeWidth
        : 1.5;

    return (
      <HugeiconsIcon
        icon={iconSvg}
        size={size}
        strokeWidth={sw}
        className={className}
        {...props}
      />
    );
  };
}

// Navigation & Cockpit
export const LayoutDashboardIcon = createIcon(RawDashboardSquare01Icon);
export const SearchIcon = createIcon(RawSearch01Icon);
export const ActivityIcon = createIcon(RawActivity01Icon);
export const UsersIcon = createIcon(RawUserGroupIcon);
export const FlaskConicalIcon = createIcon(RawTestTube01Icon);
export const ShoppingBagIcon = createIcon(RawShoppingBag01Icon);
export const NetworkIcon = createIcon(RawHierarchyCircle01Icon);
export const KeyIcon = createIcon(RawKey01Icon);
export const GlobeIcon = createIcon(RawGlobalIcon);
export const ArchiveIcon = createIcon(RawArchive01Icon);
export const ShieldAlertIcon = createIcon(RawShieldAlertIcon);
export const ShieldCheckIcon = createIcon(RawShieldCheckIcon);
export const ScrollIcon = createIcon(RawFile01Icon);

// App controls & User
export const SettingsIcon = createIcon(RawSettings01Icon);
export const UserIcon = createIcon(RawUserIcon);
export const CreditCardIcon = createIcon(RawCreditCardIcon);
export const LogOutIcon = createIcon(RawLogout01Icon);
export const HelpCircleIcon = createIcon(RawHelpCircleIcon);
export const BellIcon = createIcon(RawNotification01Icon);
export const PlusIcon = createIcon(RawPlusSignIcon);
export const CopyIcon = createIcon(RawCopy01Icon);
export const DatabaseIcon = createIcon(RawDatabase01Icon);
export const WalletIcon = createIcon(RawWallet01Icon);
export const ServerCrashIcon = createIcon(RawAlert01Icon);
export const ClockIcon = createIcon(RawClock01Icon);
export const BarChart3Icon = createIcon(RawBarChartIcon);

// Directional & Metric arrows
export const ArrowRightIcon = createIcon(RawArrowRight01Icon);
export const ArrowLeftIcon = createIcon(RawArrowLeft01Icon);
export const ArrowUpIcon = createIcon(RawArrowUp01Icon);
export const ArrowDownIcon = createIcon(RawArrowDown01Icon);
export const TrendingUpIcon = createIcon(RawTrendingUpIcon);
export const TrendingDownIcon = createIcon(RawTrendingDownIcon);
export const MinusIcon = createIcon(RawMinusIcon);
export const ChevronRightIcon = createIcon(RawChevronRightIcon);
export const ChevronDownIcon = createIcon(RawChevronDownIcon);
export const ChevronUpIcon = createIcon(RawChevronUpIcon);
export const MoreHorizontalIcon = createIcon(RawMoreHorizontalIcon);

// Status & Indicators
export const CheckIcon = createIcon(RawCheckIcon);
export const CheckCircle2Icon = createIcon(RawCheckmarkCircle01Icon);
export const CircleIcon = createIcon(RawCircleIcon);
export const CircleDotIcon = createIcon(RawCheckmarkCircle01Icon);
export const AlertCircleIcon = createIcon(RawAlertCircleIcon);
export const XCircleIcon = createIcon(RawCancelCircleIcon);
export const XIcon = createIcon(RawCancel01Icon);
export const PanelLeftIcon = createIcon(RawSidebarLeftIcon);
