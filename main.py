import os
import csv
import threading
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from modules.engine import run_detection_engine


class WIDSSOCDashboard:
    def __init__(self, root):
        self.root = root
        # Set clean application title
        self.root.title("WayarJaws — Wireless Intrusion Detection System")
        self.root.geometry("1220x840")
        self.root.minsize(1050, 720)
        self.root.configure(bg="#0B0F19")

        # Core application state
        self.raw_alerts = []
        self.filtered_alerts = []
        self.timeline_data = None
        self.category_counts = {}
        self.is_analyzing = False

        # Apply dark-mode SIEM theme using ttk's clam engine
        self._configure_soc_theme()

        # Build the 4 primary SOC dashboard tiers
        self._build_top_control_bar()
        self._build_kpi_summary_row()
        self._build_visual_analytics_row()
        self._build_bottom_split_row()
        self._build_status_bar()

        # Initialize visual charts in clean standby state
        self.root.update_idletasks()
        self._draw_timeline_chart()
        self._draw_donut_chart()

    # --------------------------------------------------------------------------
    # THEME & STYLES (OBSIDIAN & SLATE DARK SOC PALETTE)
    # --------------------------------------------------------------------------
    def _configure_soc_theme(self):
        self.style = ttk.Style()
        self.style.theme_use("clam")

        # Fonts
        self.font_title = ("Segoe UI", 13, "bold")
        self.font_card_val = ("Segoe UI", 21, "bold")
        self.font_card_title = ("Segoe UI", 9, "bold")
        self.font_card_sub = ("Segoe UI", 8)
        self.font_section_hdr = ("Segoe UI", 10, "bold")
        self.font_body = ("Segoe UI", 9)
        self.font_body_bold = ("Segoe UI", 9, "bold")
        self.font_mono = ("Consolas", 9)
        self.font_mono_bold = ("Consolas", 9, "bold")

        # Treeview styling for dark theme
        self.style.configure(
            "Dark.Treeview",
            background="#111827",
            fieldbackground="#111827",
            foreground="#F9FAFB",
            rowheight=27,
            borderwidth=0,
            font=self.font_body
        )
        self.style.configure(
            "Dark.Treeview.Heading",
            background="#1F2937",
            foreground="#F9FAFB",
            borderwidth=0,
            relief="flat",
            font=self.font_body_bold,
            padding=4
        )
        self.style.map(
            "Dark.Treeview",
            background=[("selected", "#1E3A8A")],
            foreground=[("selected", "#FFFFFF")]
        )
        self.style.map(
            "Dark.Treeview.Heading",
            background=[("active", "#374151")]
        )

        # Combobox dark style
        self.style.configure(
            "Dark.TCombobox",
            fieldbackground="#1F2937",
            background="#1F2937",
            foreground="#F9FAFB",
            darkcolor="#1F2937",
            lightcolor="#1F2937",
            arrowcolor="#9CA3AF",
            bordercolor="#374151",
            padding=3
        )
        self.style.map("Dark.TCombobox", fieldbackground=[("readonly", "#1F2937")])

        # Dark Scrollbar style
        self.style.configure(
            "Dark.Vertical.TScrollbar",
            background="#1F2937",
            troughcolor="#111827",
            bordercolor="#111827",
            arrowcolor="#9CA3AF"
        )
        self.style.map("Dark.Vertical.TScrollbar", background=[("active", "#374151")])

        # Checkbutton dark style
        self.style.configure(
            "Dark.TCheckbutton",
            background="#111827",
            foreground="#D1D5DB",
            font=self.font_body
        )
        self.style.map(
            "Dark.TCheckbutton",
            background=[("active", "#111827")],
            foreground=[("active", "#F9FAFB")]
        )

        # Progressbar
        self.style.configure(
            "Dark.Horizontal.TProgressbar",
            troughcolor="#111827",
            background="#3B82F6",
            bordercolor="#1F2937",
            lightcolor="#3B82F6",
            darkcolor="#3B82F6"
        )

    # --------------------------------------------------------------------------
    # ROW 1: TOP CONTROL BAR
    # --------------------------------------------------------------------------
    def _build_top_control_bar(self):
        panel = tk.Frame(self.root, bg="#111827", highlightbackground="#1F2937", highlightthickness=1)
        panel.pack(fill=tk.X, padx=14, pady=(12, 6))

        # Header Title Line: WayarJaws branding + Live Status Badge
        hdr_row = tk.Frame(panel, bg="#111827")
        hdr_row.pack(fill=tk.X, padx=14, pady=(10, 8))

        title_lbl = tk.Label(
            hdr_row,
            text="WayarJaws",
            font=("Segoe UI", 14, "bold"),
            fg="#F9FAFB",
            bg="#111827"
        )
        title_lbl.pack(side=tk.LEFT)

        # Status badge indicator
        self.status_badge_frame = tk.Frame(hdr_row, bg="#064E3B", padx=8, pady=2, highlightbackground="#059669", highlightthickness=1)
        self.status_badge_frame.pack(side=tk.RIGHT)

        self.status_badge_dot = tk.Label(self.status_badge_frame, text="●", fg="#10B981", bg="#064E3B", font=("Segoe UI", 8, "bold"))
        self.status_badge_dot.pack(side=tk.LEFT, padx=(0, 4))

        self.status_badge_text = tk.Label(
            self.status_badge_frame,
            text="SYSTEM READY",
            fg="#ECFDF5",
            bg="#064E3B",
            font=("Segoe UI", 8, "bold")
        )
        self.status_badge_text.pack(side=tk.LEFT)

        # File selection & action button row
        controls_row = tk.Frame(panel, bg="#111827")
        controls_row.pack(fill=tk.X, padx=14, pady=(0, 8))

        lbl_target = tk.Label(controls_row, text="Target PCAP File:", fg="#9CA3AF", bg="#111827", font=self.font_body_bold)
        lbl_target.pack(side=tk.LEFT, padx=(0, 8))

        self.file_path_var = tk.StringVar(value="")
        self.file_entry = tk.Entry(
            controls_row,
            textvariable=self.file_path_var,
            bg="#0B0F19",
            fg="#F9FAFB",
            insertbackground="#F9FAFB",
            relief="solid",
            bd=1,
            highlightbackground="#1F2937",
            font=self.font_mono
        )
        self.file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8), ipady=4)

        browse_btn = tk.Button(
            controls_row,
            text="Browse PCAP...",
            command=self._browse_pcap,
            bg="#1F2937",
            fg="#F3F4F6",
            activebackground="#374151",
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            padx=12,
            pady=4,
            font=self.font_body_bold,
            cursor="hand2"
        )
        browse_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.run_btn = tk.Button(
            controls_row,
            text="▶  Run Analysis",
            command=self._start_analysis_thread,
            bg="#3B82F6",
            fg="#FFFFFF",
            activebackground="#2563EB",
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            padx=14,
            pady=4,
            font=self.font_body_bold,
            cursor="hand2"
        )
        self.run_btn.pack(side=tk.LEFT, padx=(0, 6))

        reset_btn = tk.Button(
            controls_row,
            text="Reset",
            command=self._reset_dashboard,
            bg="#1F2937",
            fg="#9CA3AF",
            activebackground="#374151",
            activeforeground="#E5E7EB",
            relief="flat",
            bd=0,
            padx=12,
            pady=4,
            font=self.font_body,
            cursor="hand2"
        )
        reset_btn.pack(side=tk.LEFT)

        # Checkbox detector toggles row
        toggle_row = tk.Frame(panel, bg="#111827")
        toggle_row.pack(fill=tk.X, padx=14, pady=(0, 10))

        tk.Label(toggle_row, text="Active Modules:", fg="#6B7280", bg="#111827", font=self.font_card_sub).pack(side=tk.LEFT, padx=(0, 10))

        self.chk_deauth = tk.BooleanVar(value=True)
        self.chk_evil_twin = tk.BooleanVar(value=True)
        self.chk_arp = tk.BooleanVar(value=True)
        self.chk_port_scan = tk.BooleanVar(value=True)

        ttk.Checkbutton(toggle_row, text="Deauth Flood (802.11)", variable=self.chk_deauth, style="Dark.TCheckbutton").pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(toggle_row, text="Evil Twin / Rogue AP", variable=self.chk_evil_twin, style="Dark.TCheckbutton").pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(toggle_row, text="ARP Spoofing / Poisoning", variable=self.chk_arp, style="Dark.TCheckbutton").pack(side=tk.LEFT, padx=10)
        ttk.Checkbutton(toggle_row, text="TCP Port Scanning", variable=self.chk_port_scan, style="Dark.TCheckbutton").pack(side=tk.LEFT, padx=10)

    # --------------------------------------------------------------------------
    # ROW 2: KPI SUMMARY CARDS (4 EQUAL DARK CARDS)
    # --------------------------------------------------------------------------
    def _build_kpi_summary_row(self):
        container = tk.Frame(self.root, bg="#0B0F19")
        container.pack(fill=tk.X, padx=14, pady=(0, 6))

        for c in range(4):
            container.columnconfigure(c, weight=1, uniform="kpi_col")

        def make_kpi_card(parent, col, title, initial_val, sub_text, accent_color):
            card = tk.Frame(parent, bg="#111827", highlightbackground="#1F2937", highlightthickness=1)
            card.grid(row=0, column=col, sticky="nsew", padx=4, pady=2)

            # Accent color bar across the top of the card
            top_bar = tk.Frame(card, bg=accent_color, height=3)
            top_bar.pack(fill=tk.X, side=tk.TOP)

            content = tk.Frame(card, bg="#111827", padx=14, pady=10)
            content.pack(fill=tk.BOTH, expand=True)

            lbl_title = tk.Label(content, text=title.upper(), fg="#9CA3AF", bg="#111827", font=self.font_card_title)
            lbl_title.pack(anchor="w")

            lbl_val = tk.Label(content, text=initial_val, fg="#F9FAFB", bg="#111827", font=self.font_card_val)
            lbl_val.pack(anchor="w", pady=(3, 0))

            lbl_sub = tk.Label(content, text=sub_text, fg="#6B7280", bg="#111827", font=self.font_card_sub)
            lbl_sub.pack(anchor="w")
            return lbl_val

        self.kpi_packets = make_kpi_card(container, 0, "Packets Analyzed", "0", "Raw Capture Base", "#3B82F6")
        self.kpi_alerts = make_kpi_card(container, 1, "Total Threats", "0", "Incident Queue", "#8B5CF6")
        self.kpi_critical = make_kpi_card(container, 2, "Critical Alerts", "0", "Immediate Action", "#EF4444")
        self.kpi_high = make_kpi_card(container, 3, "High / Medium Alerts", "0", "Elevated Risk", "#F59E0B")

    # --------------------------------------------------------------------------
    # ROW 3: VISUAL ANALYTICS ROW (NATIVE TK.CANVAS CHARTS)
    # --------------------------------------------------------------------------
    def _build_visual_analytics_row(self):
        charts_container = tk.Frame(self.root, bg="#0B0F19")
        charts_container.pack(fill=tk.BOTH, expand=False, padx=14, pady=(0, 6))

        charts_container.columnconfigure(0, weight=65, uniform="charts")
        charts_container.columnconfigure(1, weight=35, uniform="charts")

        # ----------------- LEFT: Capture Traffic & Alert Timeline -----------------
        panel_line = tk.Frame(charts_container, bg="#111827", highlightbackground="#1F2937", highlightthickness=1)
        panel_line.grid(row=0, column=0, sticky="nsew", padx=(4, 4), pady=2)

        hdr_line = tk.Frame(panel_line, bg="#111827", padx=12, pady=8)
        hdr_line.pack(fill=tk.X)

        tk.Label(hdr_line, text="CAPTURE TRAFFIC & ALERT TIMELINE", fg="#F9FAFB", bg="#111827", font=self.font_section_hdr).pack(side=tk.LEFT)

        # Legend on top right of the timeline chart
        legend_line = tk.Frame(hdr_line, bg="#111827")
        legend_line.pack(side=tk.RIGHT)

        tk.Label(legend_line, text="―", fg="#3B82F6", bg="#111827", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        tk.Label(legend_line, text="Total Traffic  ", fg="#9CA3AF", bg="#111827", font=self.font_card_sub).pack(side=tk.LEFT)
        tk.Label(legend_line, text="―", fg="#EF4444", bg="#111827", font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        tk.Label(legend_line, text="Attack Spikes", fg="#9CA3AF", bg="#111827", font=self.font_card_sub).pack(side=tk.LEFT)

        self.canvas_timeline = tk.Canvas(panel_line, bg="#111827", width=680, height=160, highlightthickness=0)
        self.canvas_timeline.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        self.canvas_timeline.bind("<Configure>", lambda e: self._draw_timeline_chart())

        # ---------------- RIGHT: Attack Category Breakdown Donut -----------------
        panel_donut = tk.Frame(charts_container, bg="#111827", highlightbackground="#1F2937", highlightthickness=1)
        panel_donut.grid(row=0, column=1, sticky="nsew", padx=(4, 4), pady=2)

        hdr_donut = tk.Frame(panel_donut, bg="#111827", padx=12, pady=8)
        hdr_donut.pack(fill=tk.X)

        tk.Label(hdr_donut, text="ATTACK CATEGORY BREAKDOWN", fg="#F9FAFB", bg="#111827", font=self.font_section_hdr).pack(side=tk.LEFT)

        self.canvas_donut = tk.Canvas(panel_donut, bg="#111827", width=360, height=160, highlightthickness=0)
        self.canvas_donut.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
        self.canvas_donut.bind("<Configure>", lambda e: self._draw_donut_chart())

    # --------------------------------------------------------------------------
    # CANVAS DRAWING ROUTINES: TIMELINE CHART & DONUT CHART
    # --------------------------------------------------------------------------
    def _draw_timeline_chart(self):
        # Draw clean vector line chart on native tk.Canvas
        c = self.canvas_timeline
        c.delete("all")

        w = c.winfo_width() if c.winfo_width() > 100 else (c.winfo_reqwidth() if c.winfo_reqwidth() > 100 else 680)
        h = c.winfo_height() if c.winfo_height() > 60 else (c.winfo_reqheight() if c.winfo_reqheight() > 60 else 160)

        pad_l, pad_r, pad_t, pad_b = 48, 18, 20, 24
        plot_w = w - pad_l - pad_r
        plot_h = h - pad_t - pad_b

        # Draw horizontal gridlines (4 steps)
        for i in range(4):
            y = pad_t + (i / 3.0) * plot_h
            c.create_line(pad_l, y, w - pad_r, y, fill="#1F2937", dash=(3, 3))

        # Check if we have active timeline data
        if not self.timeline_data or not self.timeline_data.get("total_bins"):
            c.create_text(
                w / 2, h / 2,
                text="Awaiting PCAP Capture Analysis...",
                fill="#4B5563",
                font=("Segoe UI", 10, "italic")
            )
            # Draw empty axis labels
            for i in range(4):
                y = pad_t + (i / 3.0) * plot_h
                c.create_text(pad_l - 6, y, text="0", fill="#4B5563", font=("Segoe UI", 7), anchor="e")
            return

        total_bins = self.timeline_data["total_bins"]
        attack_bins = self.timeline_data["attack_bins"]
        duration = self.timeline_data.get("duration", 0.0)
        n = len(total_bins)

        max_val = max(max(total_bins), 1)

        # Draw Y-axis numeric labels
        for i in range(4):
            y = pad_t + (i / 3.0) * plot_h
            val = int(max_val * (1.0 - (i / 3.0)))
            c.create_text(pad_l - 6, y, text=str(val), fill="#6B7280", font=("Segoe UI", 7), anchor="e")

        # Draw X-axis duration intervals
        x_steps = 5
        for s in range(x_steps):
            x = pad_l + (s / float(x_steps - 1)) * plot_w
            sec_offset = (s / float(x_steps - 1)) * duration
            lbl_time = f"{sec_offset:.1f}s" if duration < 60 else f"{int(sec_offset//60):02d}:{int(sec_offset%60):02d}"
            c.create_text(x, h - pad_b + 10, text=lbl_time, fill="#6B7280", font=("Segoe UI", 7), anchor="center")

        # Plot total traffic line (Cobalt Blue #3B82F6)
        pts_total = []
        for i in range(n):
            x = pad_l + (i / float(n - 1)) * plot_w
            y = pad_t + plot_h - (total_bins[i] / float(max_val)) * plot_h
            pts_total.extend([x, y])

        if len(pts_total) >= 4:
            c.create_line(pts_total, fill="#3B82F6", width=2, smooth=True)

        # Plot attack spike line (Crimson #EF4444) with alert glow points
        pts_attack = []
        alert_coords = []
        for i in range(n):
            x = pad_l + (i / float(n - 1)) * plot_w
            y = pad_t + plot_h - (attack_bins[i] / float(max_val)) * plot_h
            pts_attack.extend([x, y])
            if attack_bins[i] > 0:
                alert_coords.append((x, y, attack_bins[i]))

        if len(pts_attack) >= 4:
            c.create_line(pts_attack, fill="#EF4444", width=2.5, smooth=False)

        # Highlight attack spike nodes with distinct red pulse dots
        for ax, ay, count in alert_coords:
            c.create_oval(ax - 4, ay - 4, ax + 4, ay + 4, fill="#EF4444", outline="#FCA5A5", width=1.5)
            # Show peak count if prominent
            if count == max(attack_bins):
                c.create_text(ax, ay - 9, text=f"+{count}", fill="#F87171", font=("Segoe UI", 7, "bold"))

    def _draw_donut_chart(self):
        # Draw clean vector donut chart on native tk.Canvas
        c = self.canvas_donut
        c.delete("all")

        w = c.winfo_width() if c.winfo_width() > 100 else (c.winfo_reqwidth() if c.winfo_reqwidth() > 100 else 360)
        h = c.winfo_height() if c.winfo_height() > 60 else (c.winfo_reqheight() if c.winfo_reqheight() > 60 else 160)

        cx = int(w * 0.32)
        cy = int(h * 0.50)
        r_outer = min(cx - 14, cy - 14, 58)
        r_inner = int(r_outer * 0.60)

        # Color palette for attack categories
        category_palette = {
            "Deauthentication Flood": ("#EF4444", "Deauth Flood"),
            "Evil Twin - Security Downgrade": ("#8B5CF6", "Evil Twin"),
            "Rogue AP - Unauthorized BSSID": ("#8B5CF6", "Rogue AP"),
            "ARP Spoofing / Poisoning": ("#F59E0B", "ARP Poisoning"),
            "TCP Port Scan (SYN Stealth Scan)": ("#10B981", "Port Scan"),
            "TCP Port Scan (Xmas Stealth Scan)": ("#10B981", "Xmas Scan"),
            "TCP Port Scan": ("#10B981", "Port Scan"),
        }

        total_alerts = sum(self.category_counts.values()) if self.category_counts else 0

        # Draw Donut Slices if threats are detected
        if total_alerts > 0:
            cur_angle = 90.0
            for cat, count in self.category_counts.items():
                if count <= 0:
                    continue
                slice_angle = (count / float(total_alerts)) * 360.0
                color = category_palette.get(cat, ("#3B82F6", cat))[0]

                c.create_arc(
                    cx - r_outer, cy - r_outer,
                    cx + r_outer, cy + r_outer,
                    start=cur_angle,
                    extent=slice_angle,
                    fill=color,
                    outline="#111827",
                    width=2
                )
                cur_angle += slice_angle

            # Cut out center hole for donut shape
            c.create_oval(
                cx - r_inner, cy - r_inner,
                cx + r_inner, cy + r_inner,
                fill="#111827",
                outline="#1F2937",
                width=1
            )
            c.create_text(cx, cy - 6, text=str(total_alerts), fill="#F9FAFB", font=("Segoe UI", 16, "bold"))
            c.create_text(cx, cy + 12, text="THREATS", fill="#9CA3AF", font=("Segoe UI", 7, "bold"))
        else:
            # Clean / No Threats Standby Ring
            c.create_oval(
                cx - r_outer, cy - r_outer,
                cx + r_outer, cy + r_outer,
                fill="#111827",
                outline="#1F2937",
                width=10
            )
            c.create_text(cx, cy - 6, text="0", fill="#10B981", font=("Segoe UI", 16, "bold"))
            c.create_text(cx, cy + 12, text="CLEAN", fill="#10B981", font=("Segoe UI", 7, "bold"))

        # Right-side Donut Legend
        leg_x = cx + r_outer + 22
        standard_legend_items = [
            ("Deauth Flood", "#EF4444"),
            ("Evil Twin", "#8B5CF6"),
            ("ARP Poisoning", "#F59E0B"),
            ("Port Scan", "#10B981"),
        ]

        # Calculate counts per standard group
        grouped_counts = {
            "Deauth Flood": sum(v for k, v in self.category_counts.items() if "deauth" in k.lower()),
            "Evil Twin": sum(v for k, v in self.category_counts.items() if "evil" in k.lower() or "rogue" in k.lower()),
            "ARP Poisoning": sum(v for k, v in self.category_counts.items() if "arp" in k.lower()),
            "Port Scan": sum(v for k, v in self.category_counts.items() if "port" in k.lower() or "scan" in k.lower()),
        }

        start_y = cy - 42
        for idx, (display_name, col) in enumerate(standard_legend_items):
            y = start_y + (idx * 22)
            c.create_oval(leg_x, y - 4, leg_x + 8, y + 4, fill=col, outline="")

            c.create_text(leg_x + 14, y - 4, text=display_name, fill="#F9FAFB", font=("Segoe UI", 8, "bold"), anchor="w")

            cnt = grouped_counts.get(display_name, 0)
            pct = (cnt / float(total_alerts) * 100.0) if total_alerts > 0 else 0.0
            c.create_text(leg_x + 14, y + 8, text=f"{cnt} ({pct:.0f}%)", fill="#9CA3AF", font=("Segoe UI", 7), anchor="w")

    # --------------------------------------------------------------------------
    # ROW 4: BOTTOM SPLIT ROW (ALERTS LOG + FORENSIC INSPECTOR)
    # --------------------------------------------------------------------------
    def _build_bottom_split_row(self):
        container = tk.Frame(self.root, bg="#0B0F19")
        container.pack(fill=tk.BOTH, expand=True, padx=14, pady=(0, 6))

        container.columnconfigure(0, weight=62, uniform="bottom_row")
        container.columnconfigure(1, weight=38, uniform="bottom_row")

        # ----------------- LEFT: Security Alerts Log -----------------
        panel_table = tk.Frame(container, bg="#111827", highlightbackground="#1F2937", highlightthickness=1)
        panel_table.grid(row=0, column=0, sticky="nsew", padx=(4, 4), pady=2)

        # Table header with filter controls and export button
        tbl_hdr = tk.Frame(panel_table, bg="#111827", padx=12, pady=8)
        tbl_hdr.pack(fill=tk.X)

        tk.Label(tbl_hdr, text="SECURITY ALERTS LOG", fg="#F9FAFB", bg="#111827", font=self.font_section_hdr).pack(side=tk.LEFT, padx=(0, 12))

        # Filter dropdown: Severity
        self.sev_filter_var = tk.StringVar(value="All Severities")
        sev_cb = ttk.Combobox(
            tbl_hdr,
            textvariable=self.sev_filter_var,
            values=["All Severities", "CRITICAL", "HIGH", "MEDIUM"],
            state="readonly",
            style="Dark.TCombobox",
            width=12
        )
        sev_cb.pack(side=tk.LEFT, padx=(0, 6))
        sev_cb.bind("<<ComboboxSelected>>", lambda e: self._apply_filters())

        # Filter dropdown: Attack Type
        self.type_filter_var = tk.StringVar(value="All Attack Types")
        type_cb = ttk.Combobox(
            tbl_hdr,
            textvariable=self.type_filter_var,
            values=["All Attack Types", "Deauthentication", "Evil Twin", "ARP", "Port Scan"],
            state="readonly",
            style="Dark.TCombobox",
            width=15
        )
        type_cb.pack(side=tk.LEFT, padx=(0, 6))
        type_cb.bind("<<ComboboxSelected>>", lambda e: self._apply_filters())

        # Export incident report button
        export_btn = tk.Button(
            tbl_hdr,
            text="Export CSV",
            command=self._export_report_csv,
            bg="#1F2937",
            fg="#D1D5DB",
            activebackground="#374151",
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            padx=8,
            pady=2,
            font=self.font_body,
            cursor="hand2"
        )
        export_btn.pack(side=tk.RIGHT)

        export_txt = tk.Button(
            tbl_hdr,
            text="Export TXT",
            command=self._export_report_txt,
            bg="#1F2937",
            fg="#D1D5DB",
            activebackground="#374151",
            activeforeground="#FFFFFF",
            relief="flat",
            bd=0,
            padx=8,
            pady=2,
            font=self.font_body,
            cursor="hand2"
        )
        export_txt.pack(side=tk.RIGHT, padx=6)

        # Table Treeview frame
        tree_frame = tk.Frame(panel_table, bg="#111827")
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        cols = ("id", "severity", "attack_type", "timestamp", "source", "target", "packets")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", selectmode="browse", style="Dark.Treeview")

        self.tree.heading("id", text="ID")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("attack_type", text="Attack Type")
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.heading("source", text="Source (Attacker)")
        self.tree.heading("target", text="Target / BSSID")
        self.tree.heading("packets", text="Packets")

        self.tree.column("id", width=42, anchor="center")
        self.tree.column("severity", width=82, anchor="center")
        self.tree.column("attack_type", width=170, anchor="w")
        self.tree.column("timestamp", width=130, anchor="center")
        self.tree.column("source", width=155, anchor="w")
        self.tree.column("target", width=155, anchor="w")
        self.tree.column("packets", width=70, anchor="e")

        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview, style="Dark.Vertical.TScrollbar")
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)

        # Alternating dark rows and severity highlighting
        self.tree.tag_configure("even", background="#111827")
        self.tree.tag_configure("odd", background="#0F172A")
        self.tree.tag_configure("CRITICAL", foreground="#F87171")
        self.tree.tag_configure("HIGH", foreground="#FBBF24")
        self.tree.tag_configure("MEDIUM", foreground="#FCD34D")

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        # ---------------- RIGHT: Forensic Evidence Inspector -----------------
        panel_insp = tk.Frame(container, bg="#111827", highlightbackground="#1F2937", highlightthickness=1)
        panel_insp.grid(row=0, column=1, sticky="nsew", padx=(4, 4), pady=2)

        hdr_insp = tk.Frame(panel_insp, bg="#111827", padx=12, pady=8)
        hdr_insp.pack(fill=tk.X)

        tk.Label(hdr_insp, text="FORENSIC EVIDENCE INSPECTOR", fg="#F9FAFB", bg="#111827", font=self.font_section_hdr).pack(side=tk.LEFT)

        insp_body = tk.Frame(panel_insp, bg="#111827", padx=12, pady=4)
        insp_body.pack(fill=tk.BOTH, expand=True)

        # Top severity badge in inspector
        self.insp_badge_lbl = tk.Label(
            insp_body,
            text="Awaiting Incident Selection",
            fg="#9CA3AF",
            bg="#1F2937",
            font=self.font_card_title,
            padx=8,
            pady=4,
            relief="flat",
            anchor="w"
        )
        self.insp_badge_lbl.pack(fill=tk.X, pady=(0, 8))

        # Metadata grid: Source, Target, BSSID, Extra
        meta_grid = tk.Frame(insp_body, bg="#111827")
        meta_grid.pack(fill=tk.X, pady=(0, 6))

        def make_meta_field(parent, row, col, label):
            f = tk.Frame(parent, bg="#111827")
            f.grid(row=row, column=col, sticky="w", padx=4, pady=2)
            tk.Label(f, text=label, fg="#6B7280", bg="#111827", font=self.font_card_sub).pack(anchor="w")
            v = tk.Label(f, text="--", fg="#F9FAFB", bg="#111827", font=self.font_mono)
            v.pack(anchor="w")
            return v

        self.meta_src = make_meta_field(meta_grid, 0, 0, "Source Attacker")
        self.meta_dst = make_meta_field(meta_grid, 0, 1, "Target Victim")
        self.meta_bssid = make_meta_field(meta_grid, 1, 0, "BSSID / Radio")
        self.meta_aux = make_meta_field(meta_grid, 1, 1, "Auxiliary / Code")

        # Forensic Log Evidence text box
        tk.Label(insp_body, text="GROUND TRUTH FORENSIC EVIDENCE:", fg="#9CA3AF", bg="#111827", font=self.font_card_sub).pack(anchor="w", pady=(4, 2))

        txt_frame = tk.Frame(insp_body, bg="#0B0F19", highlightbackground="#1F2937", highlightthickness=1)
        txt_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 6))

        self.detail_text = tk.Text(
            txt_frame,
            wrap=tk.WORD,
            font=self.font_mono,
            bg="#0B0F19",
            fg="#E5E7EB",
            relief="flat",
            bd=0,
            padx=8,
            pady=8
        )
        self.detail_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        txt_sb = ttk.Scrollbar(txt_frame, orient="vertical", command=self.detail_text.yview, style="Dark.Vertical.TScrollbar")
        self.detail_text.configure(yscrollcommand=txt_sb.set)
        txt_sb.pack(side=tk.RIGHT, fill=tk.Y)

        self.detail_text.insert(tk.END, "Select an alert row from the incident log to inspect full forensic telemetry.")
        self.detail_text.config(state=tk.DISABLED)

    # --------------------------------------------------------------------------
    # STATUS BAR
    # --------------------------------------------------------------------------
    def _build_status_bar(self):
        bar = tk.Frame(self.root, bg="#0B0F19", height=24)
        bar.pack(fill=tk.X, side=tk.BOTTOM, padx=14, pady=(2, 6))

        self.status_var = tk.StringVar(value="Ready. Select a capture file and click 'Run Analysis'.")
        status_lbl = tk.Label(bar, textvariable=self.status_var, bg="#0B0F19", fg="#6B7280", font=self.font_card_sub)
        status_lbl.pack(side=tk.LEFT)

        self.prog_bar = ttk.Progressbar(bar, orient="horizontal", length=180, mode="determinate", style="Dark.Horizontal.TProgressbar")
        self.prog_bar.pack(side=tk.RIGHT)

    # --------------------------------------------------------------------------
    # CONTROLLER & EVENT HANDLERS
    # --------------------------------------------------------------------------
    def _browse_pcap(self):
        datasets_dir = os.path.join(os.path.dirname(__file__), "datasets")
        if not os.path.exists(datasets_dir):
            datasets_dir = os.path.dirname(__file__)

        selected = filedialog.askopenfilename(
            initialdir=datasets_dir,
            title="Select Wireless / Network PCAP File",
            filetypes=[
                ("PCAP Captures", "*.pcap *.pcapng *"),
                ("All Files", "*.*")
            ]
        )
        if selected:
            self.file_path_var.set(selected)
            fname = os.path.basename(selected)
            self.status_var.set(f"Loaded: {fname} | Ready to run analysis.")

    def _start_analysis_thread(self):
        target_path = self.file_path_var.get().strip()
        if not target_path or not os.path.exists(target_path):
            messagebox.showerror("File Error", "Please select a valid, existing PCAP capture file first!")
            return

        if self.is_analyzing:
            messagebox.showwarning("Busy", "Analysis is currently running! Please wait for completion.")
            return

        enabled = {
            "deauth": self.chk_deauth.get(),
            "evil_twin": self.chk_evil_twin.get(),
            "arp": self.chk_arp.get(),
            "port_scan": self.chk_port_scan.get(),
        }

        if not any(enabled.values()):
            messagebox.showwarning("Module Selection", "Please check at least one detection module!")
            return

        # Update UI state to Running
        self.is_analyzing = True
        self.run_btn.config(state=tk.DISABLED, bg="#1E3A8A")
        self.status_badge_frame.config(bg="#1E3A8A", highlightbackground="#3B82F6")
        self.status_badge_dot.config(fg="#60A5FA", bg="#1E3A8A")
        self.status_badge_text.config(text="ANALYZING...", bg="#1E3A8A", fg="#EFF6FF")
        self.prog_bar.config(mode="indeterminate")
        self.prog_bar.start(10)
        self.status_var.set("Streaming packets with Scapy...")

        worker = threading.Thread(
            target=self._run_analysis_worker,
            args=(target_path, enabled),
            daemon=True
        )
        worker.start()

    def _run_analysis_worker(self, pcap_path, enabled_modules):
        try:
            def progress_cb(percent, msg):
                self.root.after(0, self._update_progress_ui, percent, msg)

            alerts, metrics = run_detection_engine(
                pcap_path=pcap_path,
                enabled_modules=enabled_modules,
                progress_callback=progress_cb
            )
            self.root.after(0, self._on_analysis_finished, alerts, metrics)
        except Exception as e:
            self.root.after(0, self._on_analysis_error, str(e))

    def _update_progress_ui(self, percent, msg):
        if msg:
            self.status_var.set(msg)

    def _on_analysis_finished(self, alerts, metrics):
        self.is_analyzing = False
        self.prog_bar.stop()
        self.prog_bar.config(mode="determinate", value=100)
        self.run_btn.config(state=tk.NORMAL, bg="#3B82F6")

        self.status_badge_frame.config(bg="#064E3B", highlightbackground="#059669")
        self.status_badge_dot.config(fg="#10B981", bg="#064E3B")
        self.status_badge_text.config(text="ANALYSIS COMPLETE", bg="#064E3B", fg="#ECFDF5")

        self.raw_alerts = alerts
        self.timeline_data = metrics.get("timeline_data")
        self.category_counts = metrics.get("category_counts", {})

        # Update KPI Cards
        self.kpi_packets.config(text=f"{metrics['total_packets']:,}")
        self.kpi_alerts.config(text=str(metrics['total_alerts']))
        self.kpi_critical.config(text=str(metrics['critical_count']))
        self.kpi_high.config(text=str(metrics['high_count'] + metrics['medium_count']))

        # Redraw charts with actual capture data
        self._draw_timeline_chart()
        self._draw_donut_chart()

        # Populate alerts tree
        self._apply_filters()

        self.status_var.set(
            f"Finished! Scanned {metrics['total_packets']:,} packets — "
            f"Identified {metrics['total_alerts']} security threat(s)."
        )

        messagebox.showinfo(
            "WayarJaws Scan Complete",
            f"Analysis Completed Successfully!\n\n"
            f"• Total Packets Scanned : {metrics['total_packets']:,}\n"
            f"• Threats Flagged       : {metrics['total_alerts']}\n"
            f"• Critical Incidents    : {metrics['critical_count']}\n"
            f"• High / Medium Alerts  : {metrics['high_count'] + metrics['medium_count']}"
        )

    def _on_analysis_error(self, err_msg):
        self.is_analyzing = False
        self.prog_bar.stop()
        self.prog_bar.config(value=0)
        self.run_btn.config(state=tk.NORMAL, bg="#3B82F6")

        self.status_badge_frame.config(bg="#7F1D1D", highlightbackground="#EF4444")
        self.status_badge_dot.config(fg="#F87171", bg="#7F1D1D")
        self.status_badge_text.config(text="ANALYSIS ERROR", bg="#7F1D1D", fg="#FEF2F2")

        self.status_var.set(f"Error during scan: {err_msg}")
        messagebox.showerror("Execution Error", f"Failed to complete PCAP analysis:\n{err_msg}")

    def _apply_filters(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        sev_filter = self.sev_filter_var.get()
        type_filter = self.type_filter_var.get()

        self.filtered_alerts = []
        for idx, alert in enumerate(self.raw_alerts):
            if sev_filter != "All Severities" and alert["severity"] != sev_filter:
                continue
            if type_filter != "All Attack Types" and type_filter.lower() not in alert["attack_type"].lower():
                continue

            self.filtered_alerts.append(alert)

            src_lbl = alert.get("source_ip", "")
            src_disp = f"{src_lbl} ({alert['source_mac']})" if src_lbl else alert["source_mac"]

            dst_lbl = alert.get("target_ip", "")
            dst_disp = f"{dst_lbl} ({alert['target_mac']})" if dst_lbl else alert.get("target_mac", alert.get("bssid", "N/A"))

            stripe_tag = "even" if idx % 2 == 0 else "odd"

            self.tree.insert(
                "",
                tk.END,
                values=(
                    alert["id"],
                    alert["severity"],
                    alert["attack_type"],
                    alert["timestamp"],
                    src_disp,
                    dst_disp,
                    f"{alert['packet_count']:,}"
                ),
                tags=(stripe_tag, alert["severity"])
            )

        if self.filtered_alerts:
            first = self.tree.get_children()[0]
            self.tree.selection_set(first)
            self.tree.focus(first)

    def _on_tree_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return

        item = sel[0]
        vals = self.tree.item(item, "values")
        if not vals:
            return

        alert_id = int(vals[0])
        alert = next((a for a in self.raw_alerts if a["id"] == alert_id), None)
        if not alert:
            return

        # Update Inspector Badge
        badge_color = "#7F1D1D" if alert["severity"] == "CRITICAL" else "#78350F"
        badge_fg = "#FCA5A5" if alert["severity"] == "CRITICAL" else "#FDE68A"
        self.insp_badge_lbl.config(
            text=f"[{alert['severity']}] {alert['attack_type'].upper()} — {alert['packet_count']:,} PACKETS",
            bg=badge_color,
            fg=badge_fg
        )

        # Update metadata grid
        src_disp = f"{alert.get('source_ip', '')} [{alert['source_mac']}]" if alert.get("source_ip") else alert["source_mac"]
        dst_disp = f"{alert.get('target_ip', '')} [{alert['target_mac']}]" if alert.get("target_ip") else alert["target_mac"]
        self.meta_src.config(text=src_disp)
        self.meta_dst.config(text=dst_disp)
        self.meta_bssid.config(text=alert.get("bssid", "N/A"))

        # Auxiliary code or port details
        aux_text = "--"
        if "reason_code" in alert and alert["reason_code"] is not None:
            aux_text = f"Reason Code {alert['reason_code']}"
        elif "ssid" in alert:
            aux_text = f"SSID: '{alert['ssid']}'"
        elif "ports_probed_count" in alert:
            aux_text = f"{alert['ports_probed_count']} Ports Scanned"
        self.meta_aux.config(text=aux_text)

        # Update Evidence Log
        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, f"{alert['evidence']}\n\n")
        self.detail_text.insert(tk.END, f"Timestamp   : {alert['timestamp']}\n")
        self.detail_text.insert(tk.END, f"Attacker MAC: {alert['source_mac']}\n")
        self.detail_text.insert(tk.END, f"Victim / AP : {alert['target_mac']} (BSSID: {alert.get('bssid', 'N/A')})\n")
        if "sample_ports" in alert and alert["sample_ports"]:
            self.detail_text.insert(tk.END, f"Sample Ports: {alert['sample_ports']}\n")
        self.detail_text.config(state=tk.DISABLED)

    def _reset_dashboard(self):
        self.raw_alerts = []
        self.filtered_alerts = []
        self.timeline_data = None
        self.category_counts = {}

        for item in self.tree.get_children():
            self.tree.delete(item)

        self.kpi_packets.config(text="0")
        self.kpi_alerts.config(text="0")
        self.kpi_critical.config(text="0")
        self.kpi_high.config(text="0")

        self.status_badge_frame.config(bg="#064E3B", highlightbackground="#059669")
        self.status_badge_dot.config(fg="#10B981", bg="#064E3B")
        self.status_badge_text.config(text="SYSTEM READY", bg="#064E3B", fg="#ECFDF5")

        self.insp_badge_lbl.config(text="Awaiting Incident Selection", bg="#1F2937", fg="#9CA3AF")
        self.meta_src.config(text="--")
        self.meta_dst.config(text="--")
        self.meta_bssid.config(text="--")
        self.meta_aux.config(text="--")

        self.detail_text.config(state=tk.NORMAL)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, "Select an alert row from the incident log to inspect full forensic telemetry.")
        self.detail_text.config(state=tk.DISABLED)

        self._draw_timeline_chart()
        self._draw_donut_chart()

        self.prog_bar.config(value=0)
        self.status_var.set("Dashboard reset. Ready for next capture file.")

    def _export_report_csv(self):
        if not self.filtered_alerts:
            messagebox.showwarning("Export Warning", "No alert incidents currently available to export!")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Spreadsheet", "*.csv")],
            title="Export WayarJaws Incident Report as CSV"
        )
        if not save_path:
            return

        try:
            with open(save_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ID", "Severity", "Attack Type", "Timestamp", "Source MAC/IP", "Target MAC/IP", "BSSID", "Packet Count", "Evidence"])
                for a in self.filtered_alerts:
                    writer.writerow([
                        a["id"],
                        a["severity"],
                        a["attack_type"],
                        a["timestamp"],
                        a["source_mac"],
                        a["target_mac"],
                        a["bssid"],
                        a["packet_count"],
                        a["evidence"]
                    ])
            messagebox.showinfo("Export Success", f"Incident log exported successfully to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not write CSV report: {e}")

    def _export_report_txt(self):
        if not self.filtered_alerts:
            messagebox.showwarning("Export Warning", "No alert incidents currently available to export!")
            return

        save_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Report", "*.txt")],
            title="Export WayarJaws Incident Report as Text"
        )
        if not save_path:
            return

        try:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write("=" * 80 + "\n")
                f.write("      WAYARJAWS // WIRELESS INTRUSION DETECTION SYSTEM INCIDENT REPORT\n")
                f.write("=" * 80 + "\n")
                f.write(f"Capture Source : {self.file_path_var.get()}\n")
                f.write(f"Generated Time : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Total Incidents: {len(self.filtered_alerts)}\n\n")

                for a in self.filtered_alerts:
                    f.write(f"--- ALERT #{a['id']}: [{a['severity']}] {a['attack_type']} ---\n")
                    f.write(f"  Timestamp    : {a['timestamp']}\n")
                    f.write(f"  Source (Att) : {a['source_mac']}\n")
                    f.write(f"  Target (Vic) : {a['target_mac']}\n")
                    f.write(f"  BSSID / Radio: {a['bssid']}\n")
                    f.write(f"  Packet Count : {a['packet_count']:,} packets\n")
                    f.write(f"  Forensic Log : {a['evidence']}\n\n")

            messagebox.showinfo("Export Success", f"Text incident report exported to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not write text report: {e}")


# Aliases for backward compatibility
WIDSDashboard = WIDSSOCDashboard
WayarJawsDashboard = WIDSSOCDashboard


def main():
    root = tk.Tk()
    app = WIDSSOCDashboard(root)
    root.mainloop()


if __name__ == "__main__":
    main()
