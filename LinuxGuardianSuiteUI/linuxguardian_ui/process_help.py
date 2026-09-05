"""Plain-language process guidance, independent of the GTK interface."""
KEEP_RUNNING = {
    "close_app": "The application and its helpers stay available. Open tasks, downloads, or editing can continue.",
    "feature_stops": "The associated feature stays available, including any background work or synchronization.",
    "desktop_affected": "Desktop integration and background helpers continue supporting your session.",
    "session_critical": "Essential session or system functions continue. Leave these processes running.",
    "unknown": "The process continues its current work. Its purpose and the consequences of stopping it are not fully known.",
}
CLOSE_EFFECT = {
    "close_app": "The app or one of its helpers stops. Unsaved work and active tasks may be interrupted. Save your work and use the app’s Quit command first.",
    "feature_stops": "The associated feature may stop working until restarted. This can interrupt sync, printing, containers, or a remote session.",
    "desktop_affected": "Parts of the desktop may stop working, including file access, account integration, or input services.",
    "session_critical": "You may lose your graphical session, network access, or essential system functionality. Unsaved work can be lost.",
    "unknown": "There is not enough information to predict the consequences. Inspect the command, executable, and parent in Advanced details before taking action.",
}
END_HELP = "End requests termination (SIGTERM). The app may clean up, but a save prompt is not guaranteed. Use its own Quit command first."
FORCE_HELP = "Force Kill stops the process immediately (SIGKILL), without cleanup. Unsaved data may be lost. Reserve this for an unresponsive app."
GUIDE = (
    ("One app, many processes", "Browsers and editors use helpers for tabs, extensions, and other work. Ending one helper can break a feature; ending a group can close the whole app."),
    ("Keep running or close?", "Keep apps you are using and desktop services running. Close recognizable apps you have finished using through their own Quit command. A process at 0% CPU is idle at that moment, but can still occupy memory. Closing it may free resources; it may also restart automatically."),
    ("Read the impact label", "Close app: affects an application. Feature stops: interrupts a capability. Desktop affected: can break desktop helpers. Don’t kill: essential session or system functionality. Unknown: consequences are not established. These labels describe impact, not whether software is malicious."),
    ("End", END_HELP),
    ("Force Kill", FORCE_HELP),
    ("Common examples", "Firefox: tabs and downloads can stop. Cursor: editing and development tasks can stop. ChatGPT, Codex, or Grok: active agent work may stop. Terminal and shells: attached commands may stop; inspect the parent first. GNOME Shell and Xorg: your graphical session may end. File helpers: transfers or mounted-file access may fail. Calendar services: sync and reminders may stop. Remote desktop: remote connections may disconnect."),
    ("Understand the numbers", "CPU and memory are snapshots, not safety ratings. Combined CPU can exceed 100% on a multicore machine. Process memory percentages can include shared memory, so summed values are approximate. The summary reflects the groups currently shown by your filters."),
)
