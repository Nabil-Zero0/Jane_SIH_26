import type { ReactNode } from "react";
import {
  LayoutDashboardIcon,
  SearchIcon,
  ActivityIcon,
  UsersIcon,
  FlaskConicalIcon,
  ShoppingBagIcon,
  NetworkIcon,
  KeyIcon,
  GlobeIcon,
  ArchiveIcon,
  ShieldAlertIcon,
  ShieldCheckIcon,
  ScrollIcon,
  ClockIcon,
  BarChart3Icon,
  DatabaseIcon,
} from "@/components/icons";

export type SidebarNavItem = {
	title: string;
	path?: string;
	icon?: ReactNode;
	isActive?: boolean;
	subItems?: SidebarNavItem[];
};

export type SidebarNavGroup = {
	label: string;
	items: SidebarNavItem[];
};

export const navGroups: SidebarNavGroup[] = [
	{
		label: "Cockpit",
		items: [
			{
				title: "Dashboard",
				path: "/dashboard",
				icon: <LayoutDashboardIcon />,
			},
			{
				title: "Investigations",
				path: "/investigations",
				icon: <SearchIcon />,
			},
			{
				title: "Live Feed",
				path: "/logs",
				icon: <ActivityIcon />,
			},
		],
	},
	{
		label: "Forensic Profiling",
		items: [
			{
				title: "Threat Actors",
				path: "/actors",
				icon: <UsersIcon />,
			},
			{
				title: "Stylometry Lab",
				path: "/stylometry",
				icon: <FlaskConicalIcon />,
			},
			{
				title: "Cross-Compare",
				path: "/compare",
				icon: <BarChart3Icon />,
			},
			{
				title: "Commodities",
				path: "/commodities",
				icon: <ShoppingBagIcon />,
			},
		],
	},
	{
		label: "Infrastructure & Graph",
		items: [
			{
				title: "MultiDiGraph",
				path: "/graph",
				icon: <NetworkIcon />,
			},
			{
				title: "Locksmith",
				path: "/locksmith",
				icon: <KeyIcon />,
			},
			{
				title: "Timeline & Churn",
				path: "/timeline",
				icon: <ClockIcon />,
			},
			{
				title: "Onion Explorer",
				path: "/onions",
				icon: <GlobeIcon />,
			},
		],
	},
	{
		label: "Data Vault",
		items: [
			{
				title: "Query Dashboard",
				path: "/query",
				icon: <SearchIcon />,
			},
			{
				title: "SQL Studio",
				path: "/sql",
				icon: <DatabaseIcon />,
			},
			{
				title: "Warehouse",
				path: "/warehouse",
				icon: <ArchiveIcon />,
			},
			{
				title: "Evidentiary Audit",
				path: "/evidence",
				icon: <ShieldCheckIcon />,
			},
			{
				title: "Sanctions",
				path: "/sanctions",
				icon: <ShieldAlertIcon />,
			},
			{
				title: "Audit Logs",
				path: "/logs",
				icon: <ScrollIcon />,
			},
			{
				title: "Rules of Engagement",
				path: "/policy",
				icon: <ShieldAlertIcon />,
			},
		],
	},
];

export const navLinks: SidebarNavItem[] = [
	...navGroups.flatMap((group) =>
		group.items.flatMap((item) =>
			item.subItems?.length ? [item, ...item.subItems] : [item]
		)
	),
];
