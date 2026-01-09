import flet as ft
import pandas as pd
import threading, io, json, os
from insside_core import load_inputs, process_items, refresh_cdn_ranges

def main(page: ft.Page):
    page.title = "INSSIDE • CDN Radar"
    page.theme_mode = ft.ThemeMode.DARK
    page.window_width = 1200
    page.window_height = 800
    page.padding = 16

    # Header
    logo = ft.Image(src="logo_insside.png", width=56) if os.path.exists("logo_insside.png") else ft.Icon(ft.icons.SHIELD)
    title = ft.Text("INSSIDE • CDN Radar", size=24, weight=ft.FontWeight.W_700)
    subtitle = ft.Text("Detección de CDN y ASN", size=12, color=ft.colors.GREY_400)
    header = ft.Row([logo, ft.Column([title, subtitle], spacing=2)], alignment=ft.MainAxisAlignment.START, spacing=16)

    # Controls
    input_file = ft.TextField(label="Archivo .txt con IPs/Dominios", read_only=True, expand=True)
    browse_btn = ft.ElevatedButton("Seleccionar archivo", icon=ft.icons.UPLOAD_FILE)
    timeout_slider = ft.Slider(min=1, max=15, value=6, label="{value}s", expand=True)
    run_btn = ft.ElevatedButton("Ejecutar", icon=ft.icons.PLAY_ARROW)
    refresh_btn = ft.OutlinedButton("Actualizar rangos CDN", icon=ft.icons.CACHED)
    progress = ft.ProgressBar(width=300, visible=False)

    kpi_total = ft.Text("0", size=20, weight=ft.FontWeight.BOLD)
    kpi_detect = ft.Text("0", size=20, weight=ft.FontWeight.BOLD)
    kpi_top = ft.Text("-", size=20, weight=ft.FontWeight.BOLD)

    kpis = ft.Row([
        ft.Container(ft.Column([ft.Text("Total filas"), kpi_total], spacing=4), padding=12, bgcolor=ft.colors.BLUE_GREY_900, border_radius=10),
        ft.Container(ft.Column([ft.Text("CDNs detectados"), kpi_detect], spacing=4), padding=12, bgcolor=ft.colors.BLUE_GREY_900, border_radius=10),
        ft.Container(ft.Column([ft.Text("Top CDN"), kpi_top], spacing=4), padding=12, bgcolor=ft.colors.BLUE_GREY_900, border_radius=10),
    ], spacing=12)

    columns = ["Entrada","IP","CDN","Evidencia","ASN","Organización (AS)","Prefijo BGP","rDNS","CNAME(s)"]
    table = ft.DataTable(columns=[ft.DataColumn(ft.Text(c)) for c in columns], rows=[], column_spacing=16, data_row_max_height=56)

    download_csv = ft.OutlinedButton("Descargar CSV", icon=ft.icons.DOWNLOAD, disabled=True)
    download_xlsx = ft.OutlinedButton("Descargar Excel", icon=ft.icons.DOWNLOAD, disabled=True)
    download_jsonl = ft.OutlinedButton("Descargar JSONL", icon=ft.icons.DOWNLOAD, disabled=True)

    df_state: pd.DataFrame | None = None
    file_path: str | None = None
    cdn_db = {"Cloudflare":{"ipv4":[]}, "Fastly":{"ipv4":[]}, "CloudFront":{"ipv4":[]}}

    def pick_file(e):
        nonlocal file_path
        def on_result(result: ft.FilePickerResultEvent):
            nonlocal file_path
            if result.files:
                file_path = result.files[0].path
                input_file.value = file_path
                input_file.update()
        fp = ft.FilePicker(on_result=on_result)
        page.overlay.append(fp)
        fp.pick_files(allow_multiple=False)
    browse_btn.on_click = pick_file

    def refresh_ranges(e):
        nonlocal cdn_db
        try:
            progress.visible = True; progress.update()
            cdn_db = refresh_cdn_ranges()
            page.snack_bar = ft.SnackBar(ft.Text("Rangos CDN actualizados."), open=True); page.snack_bar.update()
        except Exception as ex:
            page.snack_bar = ft.SnackBar(ft.Text(f"Error al actualizar: {ex}"), open=True); page.snack_bar.update()
        finally:
            progress.visible = False; progress.update()
    refresh_btn.on_click = refresh_ranges

    def run_processing():
        nonlocal df_state
        try:
            progress.visible = True; progress.update()
            items = load_inputs(file_path)
            df = process_items(items, timeout=timeout_slider.value, cdn_db=cdn_db)
            df_state = df

            # KPIs
            total = len(df)
            detect = int((df["CDN"] != "Desconocido").sum()) if total else 0
            top = "-"
            if total:
                vc = df.loc[df["CDN"] != "Desconocido", "CDN"].value_counts()
                top = vc.index[0] if not vc.empty else "-"
            kpi_total.value = str(total); kpi_total.update()
            kpi_detect.value = str(detect); kpi_detect.update()
            kpi_top.value = top; kpi_top.update()

            # Tabla
            table.rows.clear()
            for _, r in df.iterrows():
                table.rows.append(ft.DataRow(cells=[ft.DataCell(ft.Text(str(r.get(c,"")))) for c in columns]))
            table.update()

            # Habilitar descargas
            for b in [download_csv, download_xlsx, download_jsonl]:
                b.disabled = False; b.update()
        except Exception as ex:
            page.snack_bar = ft.SnackBar(ft.Text(f"Error: {ex}"), open=True); page.snack_bar.update()
        finally:
            progress.visible = False; progress.update()

    def on_run(e):
        if not file_path:
            page.snack_bar = ft.SnackBar(ft.Text("Selecciona un archivo .txt"), open=True); page.snack_bar.update()
            return
        threading.Thread(target=run_processing, daemon=True).start()
    run_btn.on_click = on_run

    def on_download_csv(e):
        if df_state is None: return
        buf = io.StringIO(); df_state.to_csv(buf, index=False)
        def on_save(res: ft.FilePickerResultEvent):
            if res.path:
                with open(res.path, "w", encoding="utf-8") as f:
                    f.write(buf.getvalue())
        fps = ft.FilePicker(on_result=on_save); page.overlay.append(fps); fps.save_file(file_name="cdn_radar.csv")
    download_csv.on_click = on_download_csv

    def on_download_xlsx(e):
        if df_state is None: return
        buf = io.BytesIO()
        with pd.ExcelWriter(buf, engine="xlsxwriter") as writer:
            df_state.to_excel(writer, index=False, sheet_name="Resultados")
        def on_save(res: ft.FilePickerResultEvent):
            if res.path:
                with open(res.path, "wb") as f:
                    f.write(buf.getvalue())
        fps = ft.FilePicker(on_result=on_save); page.overlay.append(fps); fps.save_file(file_name="cdn_radar.xlsx")
    download_xlsx.on_click = on_download_xlsx

    def on_download_jsonl(e):
        if df_state is None: return
        buf = io.StringIO()
        for _, r in df_state.iterrows():
            buf.write(json.dumps({k: ("" if pd.isna(v) else v) for k, v in r.items()}, ensure_ascii=False) + "\n")
        def on_save(res: ft.FilePickerResultEvent):
            if res.path:
                with open(res.path, "w", encoding="utf-8") as f:
                    f.write(buf.getvalue())
        fps = ft.FilePicker(on_result=on_save); page.overlay.append(fps); fps.save_file(file_name="cdn_radar.jsonl")
    download_jsonl.on_click = on_download_jsonl

    page.add(
        header, ft.Divider(),
        ft.Row([input_file, browse_btn], vertical_alignment=ft.CrossAxisAlignment.CENTER),
        ft.Row([ft.Text("Timeout"), timeout_slider, run_btn, refresh_btn, progress], alignment=ft.MainAxisAlignment.SPACE_BETWEEN),
        ft.Divider(), kpis, ft.Container(height=10),
        table, ft.Container(height=10), ft.Row([download_csv, download_xlsx, download_jsonl]),
    )

ft.app(target=main, assets_dir=".")