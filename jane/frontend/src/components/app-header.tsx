"use client";

import { usePathname } from "next/navigation";
import {
	Breadcrumb,
	BreadcrumbItem,
	BreadcrumbLink,
	BreadcrumbList,
	BreadcrumbPage,
	BreadcrumbSeparator,
} from "@/components/ui/breadcrumb";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { navGroups } from "@/components/app-shared";
import { CustomTrigger } from "@/components/custom-trigger";
import { NavUser } from "@/components/nav-user";
import { HelpCircleIcon, BellIcon } from "@/components/icons";

export function AppHeader() {
	const pathname = usePathname();

	let currentGroup = "";
	let currentItemTitle = "Dashboard";
	let currentItemPath = "/dashboard";
	let detailId = "";

	for (const group of navGroups) {
		for (const item of group.items) {
			if (item.path) {
				if (item.path === "/dashboard" && pathname === "/dashboard") {
					currentGroup = group.label;
					currentItemTitle = item.title;
					currentItemPath = item.path;
					break;
				} else if (
					item.path !== "/dashboard" &&
					(pathname === item.path || pathname.startsWith(item.path + "/"))
				) {
					currentGroup = group.label;
					currentItemTitle = item.title;
					currentItemPath = item.path;
					if (pathname.startsWith(item.path + "/")) {
						detailId = pathname.slice(item.path.length + 1);
					}
					break;
				}
			}
		}
	}

	return (
		<header className="sticky top-0 z-50 flex h-(--app-header-height) w-full shrink-0 items-center justify-between gap-2 border-b bg-background px-4 md:px-6">
			<div className="flex items-center gap-3">
				<CustomTrigger place="navbar" />
				<Separator
					className="h-4 data-[orientation=vertical]:self-center hidden sm:block"
					orientation="vertical"
				/>
				<Breadcrumb>
					<BreadcrumbList>
						<BreadcrumbItem>
							<BreadcrumbLink render={<a href="/dashboard" />}>JANE</BreadcrumbLink>
						</BreadcrumbItem>
						{currentGroup && (
							<>
								<BreadcrumbSeparator />
								<BreadcrumbItem className="hidden md:inline-flex">
									<span className="text-muted-foreground">{currentGroup}</span>
								</BreadcrumbItem>
							</>
						)}
						<BreadcrumbSeparator />
						<BreadcrumbItem>
							{detailId ? (
								<BreadcrumbLink render={<a href={currentItemPath} />}>
									{currentItemTitle}
								</BreadcrumbLink>
							) : (
								<BreadcrumbPage>{currentItemTitle}</BreadcrumbPage>
							)}
						</BreadcrumbItem>
						{detailId && (
							<>
								<BreadcrumbSeparator />
								<BreadcrumbItem>
									<BreadcrumbPage className="font-mono text-xs max-w-[180px] truncate">
										{detailId}
									</BreadcrumbPage>
								</BreadcrumbItem>
							</>
						)}
					</BreadcrumbList>
				</Breadcrumb>
			</div>

			<div className="flex items-center gap-3">
				<Button size="icon-sm" variant="outline">
					<HelpCircleIcon />
				</Button>
				<Button aria-label="Notifications" size="icon-sm" variant="outline">
					<BellIcon />
				</Button>
				<Separator
					className="h-4 data-[orientation=vertical]:self-center"
					orientation="vertical"
				/>
				<NavUser />
			</div>
		</header>
	);
}
