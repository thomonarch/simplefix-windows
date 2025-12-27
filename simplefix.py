import os
import sys
import subprocess
import threading
import platform
from datetime import datetime

import customtkinter


# ------------- Utility / helpers ------------- #

def is_admin():
    """
    Try to detect if the process is running with admin privileges.
    Used to hint about actions that may require elevation.
    """
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run_powershell_command(command: str):
    """
    Run a PowerShell command hidden and return (success, output).
    """
    try:
        result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-WindowStyle", "Hidden",
                "-Command", command
            ],
            capture_output=True,
            text=True
        )
        success = (result.returncode == 0)
        output = result.stdout.strip() + ("\n" + result.stderr.strip() if result.stderr.strip() else "")
        return success, output
    except Exception as e:
        return False, str(e)



def ensure_backup_dir():
    """
    Create a backup directory under Documents if it doesn't exist.
    """
    documents = os.path.join(os.path.expanduser("~"), "Documents")
    backup_root = os.path.join(documents, "SimpleFix_Backups")
    os.makedirs(backup_root, exist_ok=True)
    return backup_root


# ------------- Debloat logic ------------- #

def safe_debloat(callback=None):
    """
    Run a curated set of safe debloat actions.
    Runs in a thread from the UI.
    """
    actions = []

    # Appx-based removals (UWP stuff)
    appx_patterns = [
        "*Microsoft.3DViewer*",
        "*Microsoft.Microsoft3DViewer*",
        "*Microsoft.MixedReality.Portal*",
        "*Microsoft.People*",
        "*Microsoft.MicrosoftSolitaireCollection*",
        "*Microsoft.WindowsFeedbackHub*",
        "*Microsoft.WindowsMaps*",
        "*Microsoft.WindowsAlarms*",
        "*Microsoft.ZuneMusic*",
        "*Microsoft.ZuneVideo*",
        "*Microsoft.OneConnect*",
        "*Microsoft.FreshPaint*",
        "*Microsoft.BingWeather*",
        "*Microsoft.BingNews*",
        "*Microsoft.MSPaint*",
        "*Clipchamp.Clipchamp*",
        "*Microsoft.OfficeHub*",
        "*Microsoft.GetHelp*",
        "*Microsoft.Getstarted*",
    ]

    for pattern in appx_patterns:
        ps = f'Get-AppxPackage -AllUsers {pattern} | Remove-AppxPackage -ErrorAction SilentlyContinue'
        actions.append(("Appx remove", ps))

    log = []

    for label, cmd in actions:
        success, output = run_powershell_command(cmd)
        log.append(f"[{label}] -> {'OK' if success else 'FAILED'}")
        if output:
            log.append(output)

    final_log = "\n".join(log)
    if callback:
        callback(final_log)


def apply_optional_debloat(options: dict, callback=None):
    """
    Apply optional app removals based on checkboxes.
    options: dict of flags, e.g. {'onedrive': True, 'xbox_game_bar': False, ...}
    """
    log = []

    # OneDrive
    if options.get("onedrive"):
        success, output = run_winget_uninstall("Microsoft.OneDrive")
        log.append(f"[OneDrive] winget -> {'OK' if success else 'FAILED'}")
        if output:
            log.append(output)

        ps = r"""
        $oneDriveSetup = "$env:SystemRoot\SysWOW64\OneDriveSetup.exe"
        if (Test-Path $oneDriveSetup) { & $oneDriveSetup /uninstall }
        """
        success, output = run_powershell_command(ps)
        log.append(f"[OneDrive legacy] -> {'OK' if success else 'FAILED'}")
        if output:
            log.append(output)

    # Xbox Game Bar
    if options.get("xbox_game_bar"):
        ps = 'Get-AppxPackage -AllUsers *Microsoft.XboxGamingOverlay* | Remove-AppxPackage -ErrorAction SilentlyContinue'
        success, output = run_powershell_command(ps)
        log.append(f"[Xbox Game Bar] -> {'OK' if success else 'FAILED'}")
        if output:
            log.append(output)

    # Teams (consumer)
    if options.get("teams"):
        success, output = run_winget_uninstall("Microsoft.Teams")
        log.append(f"[Teams] -> {'OK' if success else 'FAILED'}")
        if output:
            log.append(output)

    # Clipchamp
    if options.get("clipchamp"):
        ps = 'Get-AppxPackage -AllUsers *Clipchamp.Clipchamp* | Remove-AppxPackage -ErrorAction SilentlyContinue'
        success, output = run_powershell_command(ps)
        log.append(f"[Clipchamp] -> {'OK' if success else 'FAILED'}")
        if output:
            log.append(output)

    # Weather
    if options.get("weather"):
        ps = 'Get-AppxPackage -AllUsers *Microsoft.BingWeather* | Remove-AppxPackage -ErrorAction SilentlyContinue'
        success, output = run_powershell_command(ps)
        log.append(f"[Weather] -> {'OK' if success else 'FAILED'}")
        if output:
            log.append(output)

    # News
    if options.get("news"):
        ps = 'Get-AppxPackage -AllUsers *Microsoft.BingNews* | Remove-AppxPackage -ErrorAction SilentlyContinue'
        success, output = run_powershell_command(ps)
        log.append(f"[News] -> {'OK' if success else 'FAILED'}")
        if output:
            log.append(output)

    # Mixed Reality
    if options.get("mixed_reality"):
        ps = 'Get-AppxPackage -AllUsers *Microsoft.MixedReality.Portal* | Remove-AppxPackage -ErrorAction SilentlyContinue'
        success, output = run_powershell_command(ps)
        log.append(f"[Mixed Reality] -> {'OK' if success else 'FAILED'}")
        if output:
            log.append(output)

    # Office Hub
    if options.get("office_hub"):
        ps = 'Get-AppxPackage -AllUsers *Microsoft.OfficeHub* | Remove-AppxPackage -ErrorAction SilentlyContinue'
        success, output = run_powershell_command(ps)
        log.append(f"[Office Hub] -> {'OK' if success else 'FAILED'}")
        if output:
            log.append(output)

    # Cortana remnants
    if options.get("cortana"):
        ps = 'Get-AppxPackage -AllUsers *Microsoft.549981C3F5F10* | Remove-AppxPackage -ErrorAction SilentlyContinue'
        success, output = run_powershell_command(ps)
        log.append(f"[Cortana] -> {'OK' if success else 'FAILED'}")
        if output:
            log.append(output)

    final_log = "\n".join(log)
    if callback:
        callback(final_log)


def apply_safe_tweaks(tweaks: dict, callback=None):
    """
    Apply non-destructive, reversible registry / policy tweaks.
    tweaks: dict of flags, e.g. {'telemetry': True, 'widgets': False, ...}
    """
    log = []
    cmds = []

    # Disable telemetry
    if tweaks.get("telemetry"):
        cmds.append((
            "Telemetry",
            r"""
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
"""
        ))

    # Disable Widgets
    if tweaks.get("widgets"):
        cmds.append((
            "Widgets",
            r"""
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Dsh" -Name "AllowNewsAndInterests" -Type DWord -Value 0
"""
        ))

    # Disable Bing in Start
    if tweaks.get("bing_search"):
        cmds.append((
            "Bing search",
            r"""
New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer" -Name "DisableSearchBoxSuggestions" -Type DWord -Value 1
"""
        ))

    # Disable background apps
    if tweaks.get("background_apps"):
        cmds.append((
            "Background apps",
            r"""
New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Type DWord -Value 1
"""
        ))

    # Edge auto-launch (placeholder – softer approach)
    if tweaks.get("edge_autolaunch"):
        cmds.append((
            "Edge auto-launch (soft)",
            r"""
# Placeholder: in future, target specific scheduled tasks / run keys.
Write-Output "Edge auto-launch tweak applied (soft placeholder)."
"""
        ))

    # Disable Consumer Experience
    if tweaks.get("consumer_experience"):
        cmds.append((
            "Consumer Experience",
            r"""
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableConsumerFeatures" -Type DWord -Value 1
"""
        ))

    # Disable Tips & Suggestions
    if tweaks.get("tips"):
        cmds.append((
            "Tips & suggestions",
            r"""
New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-310093Enabled" -Type DWord -Value 0
"""
        ))

    # Disable Lock Screen Spotlight
    if tweaks.get("lockscreen_spotlight"):
        cmds.append((
            "Lock screen Spotlight",
            r"""
New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Force | Out-Null
Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name "LockScreenOverlayDisabled" -Type DWord -Value 1
"""
        ))

    for label, ps in cmds:
        success, output = run_powershell_command(ps)
        log.append(f"[{label}] -> {'OK' if success else 'FAILED'}")
        if output:
            log.append(output)

    final_log = "\n".join(log)
    if callback:
        callback(final_log)


# ------------- Main app ------------- #

class SimpleFixApp(customtkinter.CTk):

    def __init__(self):
        super().__init__()

        self.title("SimpleFix Suite (Windows)")
        self.geometry("950x650")
        customtkinter.set_appearance_mode("system")
        customtkinter.set_default_color_theme("blue")

        self._build_ui()

    # ----- Logging helpers ----- #

    def append_log(self, text: str):
        self.log_textbox.configure(state="normal")
        self.log_textbox.insert("end", text + "\n")
        self.log_textbox.see("end")
        self.log_textbox.configure(state="disabled")

    def log_status(self, text: str):
        self.status_label.configure(text=text)
        self.append_log(text)

    # ----- UI construction ----- #

    def _build_ui(self):
        # Top-level layout: tabview + log area
        main_frame = customtkinter.CTkFrame(self)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.tabview = customtkinter.CTkTabview(main_frame)
        self.tabview.pack(fill="both", expand=True, padx=5, pady=5)

        repair_tab = self.tabview.add("Repair")
        backup_tab = self.tabview.add("Backup")
        clean_tab = self.tabview.add("Clean")
        info_tab = self.tabview.add("Info")

        self._build_repair_tab(repair_tab)
        self._build_backup_tab(backup_tab)
        self._build_clean_tab(clean_tab)
        self._build_info_tab(info_tab)

        # Log area
        log_frame = customtkinter.CTkFrame(main_frame)
        log_frame.pack(fill="both", expand=False, padx=5, pady=(5, 0))

        self.status_label = customtkinter.CTkLabel(
            log_frame,
            text="Ready",
            anchor="w"
        )
        self.status_label.pack(fill="x", padx=5, pady=(5, 2))

        self.log_textbox = customtkinter.CTkTextbox(
            log_frame,
            height=140
        )
        self.log_textbox.pack(fill="both", expand=True, padx=5, pady=(0, 5))
        self.log_textbox.configure(state="disabled")

        if not is_admin():
            self.append_log("[Warning] SimpleFix is not running as administrator. Some actions may fail or do nothing.")

    # ----- Repair tab ----- #

    def _build_repair_tab(self, tab):
        frame = customtkinter.CTkFrame(tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        title = customtkinter.CTkLabel(
            frame,
            text="Repair tools",
            font=("Segoe UI", 18, "bold")
        )
        title.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

        # SFC
        sfc_button = customtkinter.CTkButton(
            frame,
            text="Run SFC (System File Checker)",
            command=lambda: self._threaded_action(self.run_sfc)
        )
        sfc_button.grid(row=1, column=0, sticky="w", pady=4)

        # DISM
        dism_button = customtkinter.CTkButton(
            frame,
            text="Run DISM /RestoreHealth",
            command=lambda: self._threaded_action(self.run_dism)
        )
        dism_button.grid(row=2, column=0, sticky="w", pady=4)

        # Network reset (placeholder)
        net_button = customtkinter.CTkButton(
            frame,
            text="Open Network Reset (Settings)",
            command=lambda: self._threaded_action(self.open_network_reset)
        )
        net_button.grid(row=3, column=0, sticky="w", pady=4)

        # Windows Update troubleshooter (Settings link)
        wu_button = customtkinter.CTkButton(
            frame,
            text="Open Windows Update Troubleshooters",
            command=lambda: self._threaded_action(self.open_update_troubleshoot)
        )
        wu_button.grid(row=4, column=0, sticky="w", pady=4)

    def run_sfc(self):
        self.log_status("[Repair] Running SFC /scannow (may take some time)...")
        cmd = ["cmd.exe", "/c", "sfc /scannow"]
        success, output = run_command_for_log(cmd, shell=False)
        self.append_log(output or "(no output)")
        self.log_status(f"[Repair] SFC completed -> {'OK' if success else 'FAILED'}")

    def run_dism(self):
        self.log_status("[Repair] Running DISM /Online /Cleanup-Image /RestoreHealth...")
        cmd = ["cmd.exe", "/c", "DISM /Online /Cleanup-Image /RestoreHealth"]
        success, output = run_command_for_log(cmd, shell=False)
        self.append_log(output or "(no output)")
        self.log_status(f"[Repair] DISM completed -> {'OK' if success else 'FAILED'}")

    def open_network_reset(self):
        self.log_status("[Repair] Opening Network Reset settings...")
        cmd = ["start", "ms-settings:network-status"]
        success, output = run_command_for_log(" ".join(cmd), shell=True)
        self.append_log(output or "(no output)")
        self.log_status("[Repair] Network settings opened.")

    def open_update_troubleshoot(self):
        self.log_status("[Repair] Opening Windows Update troubleshooters...")
        cmd = ["start", "ms-settings:troubleshoot"]
        success, output = run_command_for_log(" ".join(cmd), shell=True)
        self.append_log(output or "(no output)")
        self.log_status("[Repair] Troubleshooters opened.")

    # ----- Backup tab ----- #

    def _build_backup_tab(self, tab):
        frame = customtkinter.CTkFrame(tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        title = customtkinter.CTkLabel(
            frame,
            text="Backup tools",
            font=("Segoe UI", 18, "bold")
        )
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        apps_button = customtkinter.CTkButton(
            frame,
            text="Backup installed apps list (winget)",
            command=lambda: self._threaded_action(self.backup_installed_apps)
        )
        apps_button.grid(row=1, column=0, sticky="w", pady=4)

        note_label = customtkinter.CTkLabel(
            frame,
            text="Backups are saved to Documents\\SimpleFix_Backups",
            font=("Segoe UI", 11)
        )
        note_label.grid(row=2, column=0, sticky="w", pady=(10, 0))

    def backup_installed_apps(self):
        backup_dir = ensure_backup_dir()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        out_file = os.path.join(backup_dir, f"installed_apps_{timestamp}.txt")

        self.log_status(f"[Backup] Exporting installed apps list to:\n{out_file}")
        cmd = ["winget", "list"]
        success, output = run_command_for_log(cmd, shell=False)

        if success:
            try:
                with open(out_file, "w", encoding="utf-8", errors="replace") as f:
                    f.write(output)
                self.log_status("[Backup] Installed apps list saved successfully.")
            except Exception as e:
                self.append_log(str(e))
                self.log_status("[Backup] Failed to save apps list.")
        else:
            self.append_log(output or "(no output)")
            self.log_status("[Backup] winget list failed. Is winget installed?")

    # ----- Clean tab (includes Debloat Windows) ----- #

    def _build_clean_tab(self, tab):
        frame = customtkinter.CTkFrame(tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        title = customtkinter.CTkLabel(
            frame,
            text="Clean & debloat",
            font=("Segoe UI", 18, "bold")
        )
        title.grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 10))

        # Basic clean actions
        basic_frame = customtkinter.CTkFrame(frame)
        basic_frame.grid(row=1, column=0, columnspan=2, sticky="nwe", pady=(0, 15))

        basic_title = customtkinter.CTkLabel(
            basic_frame, text="Basic cleaning", font=("Segoe UI", 14, "bold")
        )
        basic_title.grid(row=0, column=0, sticky="w", pady=(5, 5))

        disk_cleanup_button = customtkinter.CTkButton(
            basic_frame,
            text="Open Disk Cleanup",
            command=lambda: self._threaded_action(self.open_disk_cleanup)
        )
        disk_cleanup_button.grid(row=1, column=0, sticky="w", pady=3)

        temp_cleanup_button = customtkinter.CTkButton(
            basic_frame,
            text="Clean temp files (user temp)",
            command=lambda: self._threaded_action(self.clean_temp_files)
        )
        temp_cleanup_button.grid(row=2, column=0, sticky="w", pady=3)

        storage_sense_button = customtkinter.CTkButton(
            basic_frame,
            text="Open Storage Settings",
            command=lambda: self._threaded_action(self.open_storage_settings)
        )
        storage_sense_button.grid(row=3, column=0, sticky="w", pady=3)

        # Debloat Windows section
        debloat_frame = customtkinter.CTkFrame(frame)
        debloat_frame.grid(row=2, column=0, columnspan=2, sticky="nwe", pady=(0, 5))

        debloat_title = customtkinter.CTkLabel(
            debloat_frame, text="Debloat Windows (Balanced)", font=("Segoe UI", 16, "bold")
        )
        debloat_title.grid(row=0, column=0, columnspan=2, sticky="w", pady=(5, 8))

        safe_debloat_button = customtkinter.CTkButton(
            debloat_frame,
            text="Run Safe Debloat",
            fg_color="#c0392b",
            hover_color="#e74c3c",
            command=lambda: self._threaded_action(self._run_safe_debloat)
        )
        safe_debloat_button.grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 10))

        # Optional debloat
        optional_label = customtkinter.CTkLabel(
            debloat_frame, text="Optional app removals:", font=("Segoe UI", 13, "bold")
        )
        optional_label.grid(row=2, column=0, columnspan=2, sticky="w", pady=(5, 2))

        self.opt_onedrive_var = customtkinter.BooleanVar()
        self.opt_xbox_var = customtkinter.BooleanVar()
        self.opt_teams_var = customtkinter.BooleanVar()
        self.opt_clipchamp_var = customtkinter.BooleanVar()
        self.opt_weather_var = customtkinter.BooleanVar()
        self.opt_news_var = customtkinter.BooleanVar()
        self.opt_mixed_var = customtkinter.BooleanVar()
        self.opt_officehub_var = customtkinter.BooleanVar()
        self.opt_cortana_var = customtkinter.BooleanVar()

        optional_checks = [
            (self.opt_onedrive_var, "Remove OneDrive"),
            (self.opt_xbox_var, "Remove Xbox Game Bar"),
            (self.opt_teams_var, "Remove Microsoft Teams"),
            (self.opt_clipchamp_var, "Remove Clipchamp"),
            (self.opt_weather_var, "Remove Weather"),
            (self.opt_news_var, "Remove News"),
            (self.opt_mixed_var, "Remove Mixed Reality Portal"),
            (self.opt_officehub_var, "Remove Office Hub"),
            (self.opt_cortana_var, "Remove Cortana remnants"),
        ]

        row = 3
        col = 0
        for var, label in optional_checks:
            cb = customtkinter.CTkCheckBox(debloat_frame, text=label, variable=var)
            cb.grid(row=row, column=col, sticky="w", padx=(0, 20), pady=2)
            if col == 0:
                col = 1
            else:
                col = 0
                row += 1

        optional_button = customtkinter.CTkButton(
            debloat_frame,
            text="Apply selected optional debloat",
            command=lambda: self._threaded_action(self._run_optional_debloat)
        )
        optional_button.grid(row=row + 1, column=0, columnspan=2, sticky="w", pady=(8, 10))

        # Safe tweaks
        tweaks_label = customtkinter.CTkLabel(
            debloat_frame, text="Safe tweaks:", font=("Segoe UI", 13, "bold")
        )
        tweaks_label.grid(row=row + 2, column=0, columnspan=2, sticky="w", pady=(5, 2))

        self.tw_telemetry_var = customtkinter.BooleanVar()
        self.tw_widgets_var = customtkinter.BooleanVar()
        self.tw_bing_var = customtkinter.BooleanVar()
        self.tw_background_var = customtkinter.BooleanVar()
        self.tw_edge_var = customtkinter.BooleanVar()
        self.tw_consumer_var = customtkinter.BooleanVar()
        self.tw_tips_var = customtkinter.BooleanVar()
        self.tw_lockscreen_var = customtkinter.BooleanVar()

        tweaks_checks = [
            (self.tw_telemetry_var, "Disable telemetry"),
            (self.tw_widgets_var, "Disable widgets"),
            (self.tw_bing_var, "Disable Bing in Start"),
            (self.tw_background_var, "Disable background apps"),
            (self.tw_edge_var, "Edge auto-launch (soft tweak)"),
            (self.tw_consumer_var, "Disable consumer experience"),
            (self.tw_tips_var, "Disable tips & suggestions"),
            (self.tw_lockscreen_var, "Disable lock screen Spotlight"),
        ]

        row2 = row + 3
        col = 0
        for var, label in tweaks_checks:
            cb = customtkinter.CTkCheckBox(debloat_frame, text=label, variable=var)
            cb.grid(row=row2, column=col, sticky="w", padx=(0, 20), pady=2)
            if col == 0:
                col = 1
            else:
                col = 0
                row2 += 1

        tweaks_button = customtkinter.CTkButton(
            debloat_frame,
            text="Apply selected tweaks",
            command=lambda: self._threaded_action(self._run_safe_tweaks)
        )
        tweaks_button.grid(row=row2 + 1, column=0, columnspan=2, sticky="w", pady=(8, 10))

    # Clean tab actions

    def open_disk_cleanup(self):
        self.log_status("[Clean] Opening Disk Cleanup...")
        cmd = ["cmd.exe", "/c", "cleanmgr"]
        success, output = run_command_for_log(cmd, shell=False)
        self.append_log(output or "(no output)")
        self.log_status("[Clean] Disk Cleanup command executed.")

    def clean_temp_files(self):
        self.log_status("[Clean] Cleaning user temp folder...")
        temp_dir = os.path.expanduser("~\\AppData\\Local\\Temp")
        deleted = 0
        errors = 0

        if os.path.isdir(temp_dir):
            for root, dirs, files in os.walk(temp_dir, topdown=False):
                for name in files:
                    path = os.path.join(root, name)
                    try:
                        os.remove(path)
                        deleted += 1
                    except Exception:
                        errors += 1
                for name in dirs:
                    path = os.path.join(root, name)
                    try:
                        os.rmdir(path)
                    except Exception:
                        pass

        self.append_log(f"[Clean] Temp files deleted: {deleted}, errors: {errors}")
        self.log_status("[Clean] Temp cleanup completed.")

    def open_storage_settings(self):
        self.log_status("[Clean] Opening Storage Settings...")
        cmd = ["start", "ms-settings:storage"]
        success, output = run_command_for_log(" ".join(cmd), shell=True)
        self.append_log(output or "(no output)")
        self.log_status("[Clean] Storage Settings opened.")

    def _run_safe_debloat(self):
        self.log_status("[Debloat] Running safe debloat...")
        def cb(log_text):
            self.append_log(log_text)
            self.log_status("[Debloat] Safe debloat finished.")
        safe_debloat(callback=cb)

    def _run_optional_debloat(self):
        options = {
            "onedrive": self.opt_onedrive_var.get(),
            "xbox_game_bar": self.opt_xbox_var.get(),
            "teams": self.opt_teams_var.get(),
            "clipchamp": self.opt_clipchamp_var.get(),
            "weather": self.opt_weather_var.get(),
            "news": self.opt_news_var.get(),
            "mixed_reality": self.opt_mixed_var.get(),
            "office_hub": self.opt_officehub_var.get(),
            "cortana": self.opt_cortana_var.get(),
        }
        self.log_status("[Debloat] Applying optional debloat selections...")

        def cb(log_text):
            self.append_log(log_text)
            self.log_status("[Debloat] Optional debloat finished.")

        apply_optional_debloat(options, callback=cb)

    def _run_safe_tweaks(self):
        tweaks = {
            "telemetry": self.tw_telemetry_var.get(),
            "widgets": self.tw_widgets_var.get(),
            "bing_search": self.tw_bing_var.get(),
            "background_apps": self.tw_background_var.get(),
            "edge_autolaunch": self.tw_edge_var.get(),
            "consumer_experience": self.tw_consumer_var.get(),
            "tips": self.tw_tips_var.get(),
            "lockscreen_spotlight": self.tw_lockscreen_var.get(),
        }
        self.log_status("[Debloat] Applying safe tweaks...")

        def cb(log_text):
            self.append_log(log_text)
            self.log_status("[Debloat] Safe tweaks finished.")

        apply_safe_tweaks(tweaks, callback=cb)

    # ----- Info tab ----- #

    def _build_info_tab(self, tab):
        frame = customtkinter.CTkFrame(tab)
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        title = customtkinter.CTkLabel(
            frame,
            text="System info",
            font=("Segoe UI", 18, "bold")
        )
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        info_text = self._gather_system_info()

        info_box = customtkinter.CTkTextbox(frame)
        info_box.grid(row=1, column=0, sticky="nsew", pady=(0, 5))
        info_box.insert("end", info_text)
        info_box.configure(state="disabled")

        frame.grid_rowconfigure(1, weight=1)
        frame.grid_columnconfigure(0, weight=1)

        refresh_button = customtkinter.CTkButton(
            frame,
            text="Refresh info",
            command=lambda: self._refresh_info(info_box)
        )
        refresh_button.grid(row=2, column=0, sticky="w", pady=(5, 0))

    def _gather_system_info(self):
        lines = []
        lines.append(f"SimpleFix Suite (Windows)")
        lines.append(f"Python version: {sys.version.split()[0]}")
        lines.append(f"Platform: {platform.system()} {platform.release()} ({platform.version()})")
        lines.append(f"Machine: {platform.machine()}")
        lines.append(f"Processor: {platform.processor()}")
        lines.append(f"User: {os.getlogin()}")
        lines.append(f"Admin: {'Yes' if is_admin() else 'No'}")
        lines.append("")
        lines.append("Note: Some actions require administrator privileges to be fully effective.")
        return "\n".join(lines)

    def _refresh_info(self, box):
        box.configure(state="normal")
        box.delete("1.0", "end")
        box.insert("end", self._gather_system_info())
        box.configure(state="disabled")

    # ----- Threading wrapper ----- #

    def _threaded_action(self, func):
        t = threading.Thread(target=func, daemon=True)
        t.start()


if __name__ == "__main__":
    app = SimpleFixApp()
    app.mainloop()
