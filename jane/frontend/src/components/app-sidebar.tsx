"use client";

import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import { LogoIcon } from "@/components/logo";
import { Button } from "@/components/ui/button";
import {
	Sidebar,
	SidebarContent,
	SidebarFooter,
	SidebarGroup,
	SidebarGroupLabel,
	SidebarHeader,
	SidebarMenu,
	SidebarMenuButton,
	SidebarMenuItem,
	SidebarRail,
} from "@/components/ui/sidebar";
import { AppSearch } from "@/components/app-search";
import { navGroups } from "@/components/app-shared";
import { CustomTrigger } from "@/components/custom-trigger";
import { ThemeSwitcher } from "@/components/theme-switcher";
import { SettingsIcon } from "@/components/icons";

import Link from "next/link";
import { ShieldAlertIcon } from "@/components/icons";

export function AppSidebar() {
	const pathname = usePathname();

	const isItemActive = (path?: string) => {
		if (!path) return false;
		if (path === "/dashboard") return pathname === "/dashboard";
		return pathname === path || pathname.startsWith(path + "/");
	};

	return (
		<Sidebar
			className={cn(
				"*:data-[slot=sidebar-inner]:bg-background",
				"transition-[left,right,top,width] group-data-[collapsible=offcanvas]:top-[calc(var(--app-header-height)*0.5)]"
			)}
			collapsible="offcanvas"
			variant="sidebar"
		>
			<SidebarHeader className="h-(--app-header-height,3rem) flex-row items-center justify-between">
				<Button variant="ghost" render={<a href="/dashboard" />} nativeButton={false}>
					<LogoIcon />
					<span className="font-medium">JANE</span>
				</Button>
				<CustomTrigger place="sidebar" />
			</SidebarHeader>
			<SidebarContent>
				<SidebarGroup>
					<AppSearch />
				</SidebarGroup>
				{navGroups.map((group) => (
					<SidebarGroup key={group.label}>
						<SidebarGroupLabel className="group-data-[collapsible=icon]:pointer-events-none">
							{group.label}
						</SidebarGroupLabel>
						<SidebarMenu>
							{group.items.map((item) => {
								const active = isItemActive(item.path);
								return (
									<SidebarMenuItem key={item.title}>
										<SidebarMenuButton
											isActive={active}
											tooltip={item.title}
											render={<a href={item.path} />}
										>
											{item.icon}
											<span>{item.title}</span>
										</SidebarMenuButton>
									</SidebarMenuItem>
								);
							})}
						</SidebarMenu>
					</SidebarGroup>
				))}
			</SidebarContent>
			<SidebarFooter className="px-3 pb-3 pt-1 space-y-2">
				<Link
					href="/policy"
					className={cn(
						"flex items-center gap-2.5 rounded-xl border border-white/[0.06] bg-zinc-950/70 px-3 py-2 text-xs transition-all duration-200 hover:border-amber-400/30 hover:bg-zinc-900 group",
						pathname === "/policy" && "border-amber-400/40 bg-amber-400/[0.04] text-zinc-100"
					)}
				>
					<ShieldAlertIcon className="h-4 w-4 shrink-0 text-amber-300/80 group-hover:text-amber-200 transition-colors" />
					<div className="flex flex-col text-left truncate leading-tight">
						<span className="font-medium text-[11px] text-zinc-200 flex items-center gap-1.5 group-hover:text-zinc-100">
							Rules of Engagement
							<span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-amber-400/[0.08] text-amber-200/90 border border-amber-400/20">RoE</span>
						</span>
						<span className="text-[10px] text-zinc-500 truncate">Policy & Compliance</span>
					</div>
				</Link>

				<div className="flex items-center justify-between pt-1">
					<ThemeSwitcher />
					<Button
						className="text-muted-foreground"
						size="icon-sm"
						variant="ghost"
						render={<a aria-label="Settings" href="#" />}
						nativeButton={false}
					>
						<SettingsIcon />
					</Button>
				</div>
			</SidebarFooter>
			<SidebarRail />
		</Sidebar>
	);
}
