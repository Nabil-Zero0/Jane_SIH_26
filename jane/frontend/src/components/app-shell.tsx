import { cn } from "@/lib/utils";
import { SidebarInset, SidebarProvider } from "@/components/ui/sidebar";
import { AppHeader } from "@/components/app-header";
import { AppSidebar } from "@/components/app-sidebar";

export function AppShell({ children }: { children: React.ReactNode }) {
	return (
		<SidebarProvider
			className={cn(
				"[--app-wrapper-max-width:80rem]",
				"[--app-header-height:3rem]"
			)}
		>
			<AppSidebar />
			<SidebarInset className="bg-muted dark:bg-background min-w-0 max-w-full overflow-x-hidden">
				<AppHeader />
				<div
					className={cn(
						"flex flex-1 flex-col p-4 md:p-6 min-w-0 max-w-full overflow-x-hidden",
						"mx-auto w-full max-w-[1600px]"
					)}
				>
					{children}
				</div>
			</SidebarInset>
		</SidebarProvider>
	);
}
