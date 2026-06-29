// husk-gui — GTK4 frontend for husk
//
// Point it at an executable; it runs the read-only `husk` inspector and shows
// the report in a terminal-styled log pane on the right. The GUI itself never
// executes the target — it only spawns husk, which only reads it.
//
// Build:  make            (needs gtk4)
// Layout: chooser on the left, report log on the right (horizontal).

#include <gtk/gtk.h>

#define APP_ID   "com.github.effjy.husk"
#define ICON_NAME "husk"

typedef struct {
  GtkWindow    *win;
  GtkEntry     *path_entry;
  GtkTextView  *report;
  GtkWidget    *analyze_btn;
  GtkCheckButton *verbose;
  GtkLabel     *status;
  GtkSpinner   *spinner;
} AppCtx;

// ---- locate the husk core binary at runtime --------------------------------
static gchar *find_husk(void) {
  gchar *p = g_find_program_in_path("husk");
  if (p) return p;
  const char *candidates[] = {
    "/usr/local/bin/husk", "/usr/bin/husk", "./husk", "../husk", NULL
  };
  for (int i = 0; candidates[i]; i++)
    if (g_file_test(candidates[i], G_FILE_TEST_IS_EXECUTABLE))
      return g_strdup(candidates[i]);
  return NULL;
}

// ---- write text into the report log ----------------------------------------
static void set_report(AppCtx *ctx, const char *text) {
  GtkTextBuffer *buf = gtk_text_view_get_buffer(ctx->report);
  gtk_text_buffer_set_text(buf, text ? text : "", -1);
}

static void set_busy(AppCtx *ctx, gboolean busy, const char *msg) {
  gtk_widget_set_sensitive(ctx->analyze_btn, !busy);
  if (busy) gtk_spinner_start(ctx->spinner);
  else      gtk_spinner_stop(ctx->spinner);
  gtk_widget_set_visible(GTK_WIDGET(ctx->spinner), busy);
  gtk_label_set_text(ctx->status, msg ? msg : "");
}

// ---- husk finished: collect its output -------------------------------------
static void on_husk_done(GObject *src, GAsyncResult *res, gpointer user_data) {
  AppCtx *ctx = user_data;
  GError *err = NULL;
  gchar *out = NULL, *errout = NULL;
  gboolean ok = g_subprocess_communicate_utf8_finish(
      G_SUBPROCESS(src), res, &out, &errout, &err);

  if (!ok) {
    gchar *m = g_strdup_printf("Failed to run husk: %s",
                               err ? err->message : "unknown error");
    set_report(ctx, m);
    g_free(m);
    if (err) g_error_free(err);
  } else {
    GString *s = g_string_new(out ? out : "");
    if (errout && *errout) { g_string_append(s, "\n"); g_string_append(s, errout); }
    if (s->len == 0) g_string_assign(s, "(husk produced no output)");
    set_report(ctx, s->str);
    g_string_free(s, TRUE);
  }
  set_busy(ctx, FALSE, "Done.");
  g_free(out);
  g_free(errout);
  g_object_unref(src);
}

// ---- run husk on the selected path -----------------------------------------
static void run_analysis(AppCtx *ctx) {
  const char *path = gtk_editable_get_text(GTK_EDITABLE(ctx->path_entry));
  if (!path || !*path) {
    set_report(ctx, "Select a binary first (use “Choose…” on the left).");
    return;
  }
  gchar *husk = find_husk();
  if (!husk) {
    set_report(ctx,
      "Could not find the husk core binary.\n\n"
      "Build and install it first:\n\n"
      "    cd husk && make && sudo make install\n");
    return;
  }

  gboolean verbose = gtk_check_button_get_active(ctx->verbose);
  GPtrArray *argv = g_ptr_array_new();
  g_ptr_array_add(argv, husk);
  g_ptr_array_add(argv, (gpointer)"--no-color");
  if (verbose) g_ptr_array_add(argv, (gpointer)"--all");
  g_ptr_array_add(argv, (gpointer)path);
  g_ptr_array_add(argv, NULL);

  GError *err = NULL;
  GSubprocess *proc = g_subprocess_newv(
      (const gchar * const *)argv->pdata,
      G_SUBPROCESS_FLAGS_STDOUT_PIPE | G_SUBPROCESS_FLAGS_STDERR_PIPE, &err);
  g_ptr_array_free(argv, TRUE);

  if (!proc) {
    gchar *m = g_strdup_printf("Could not launch husk: %s",
                               err ? err->message : "unknown error");
    set_report(ctx, m);
    g_free(m);
    if (err) g_error_free(err);
    g_free(husk);
    return;
  }
  set_busy(ctx, TRUE, "Analyzing…");
  g_subprocess_communicate_utf8_async(proc, NULL, NULL, on_husk_done, ctx);
  g_free(husk);
}

// ---- callbacks -------------------------------------------------------------
static void on_analyze_clicked(GtkButton *btn, gpointer user_data) {
  (void)btn;
  run_analysis(user_data);
}
static void on_entry_activate(GtkEntry *entry, gpointer user_data) {
  (void)entry;
  run_analysis(user_data);
}

static void on_file_chosen(GObject *src, GAsyncResult *res, gpointer user_data) {
  AppCtx *ctx = user_data;
  GError *err = NULL;
  GFile *file = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(src), res, &err);
  if (file) {
    gchar *path = g_file_get_path(file);
    if (path) {
      gtk_editable_set_text(GTK_EDITABLE(ctx->path_entry), path);
      g_free(path);
      run_analysis(ctx);  // analyze immediately on selection
    }
    g_object_unref(file);
  }
  if (err) g_error_free(err);  // cancelled -> just ignore
}

static void on_choose_clicked(GtkButton *btn, gpointer user_data) {
  (void)btn;
  AppCtx *ctx = user_data;
  GtkFileDialog *dialog = gtk_file_dialog_new();
  gtk_file_dialog_set_title(dialog, "Choose a binary to inspect");
  gtk_file_dialog_open(dialog, ctx->win, NULL, on_file_chosen, ctx);
  g_object_unref(dialog);
}

static void on_about(GSimpleAction *a, GVariant *p, gpointer user_data) {
  (void)a; (void)p;
  AppCtx *ctx = user_data;
  const char *authors[] = { "Jean-Francois Lachance-Caumartin", NULL };
  gtk_show_about_dialog(ctx->win,
      "program-name", "husk",
      "version", "1.0.0",
      "logo-icon-name", ICON_NAME,
      "comments", "Read-only ELF / permissions / capability inspector.\n"
                  "Point it at a binary; husk reports its security posture\n"
                  "without ever executing it.",
      "authors", authors,
      "copyright", "© 2026 Jean-Francois Lachance-Caumartin",
      "license-type", GTK_LICENSE_MIT_X11,
      "website", "https://github.com/effjy/husk",
      "website-label", "github.com/effjy/husk",
      NULL);
}

// ---- styling: Tokyo Night log + monospace ----------------------------------
static void install_css(void) {
  static const char *css =
    ".husk-report, .husk-report text {"
    "  font-family: monospace; font-size: 11pt;"
    "  background-color: #1a1b26; color: #c0caf5;"
    "}"
    ".husk-side-title { font-weight: bold; }"
    ".husk-status { font-size: 10pt; }";
  GtkCssProvider *p = gtk_css_provider_new();
  gtk_css_provider_load_from_string(p, css);
  gtk_style_context_add_provider_for_display(
      gdk_display_get_default(), GTK_STYLE_PROVIDER(p),
      GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
  g_object_unref(p);
}

// ---- build the window ------------------------------------------------------
static void on_activate(GtkApplication *app, gpointer user_data) {
  (void)user_data;
  install_css();

  AppCtx *ctx = g_new0(AppCtx, 1);

  GtkWidget *win = gtk_application_window_new(app);
  ctx->win = GTK_WINDOW(win);
  gtk_window_set_title(ctx->win, "husk");
  gtk_window_set_default_size(ctx->win, 1040, 600);
  // Tell the compositor/taskbar which themed icon represents this window.
  gtk_window_set_icon_name(ctx->win, ICON_NAME);

  // header bar with About menu
  GtkWidget *header = gtk_header_bar_new();
  gtk_window_set_titlebar(ctx->win, header);

  GMenu *menu = g_menu_new();
  g_menu_append(menu, "About husk", "win.about");
  GtkWidget *mbtn = gtk_menu_button_new();
  gtk_menu_button_set_icon_name(GTK_MENU_BUTTON(mbtn), "open-menu-symbolic");
  gtk_menu_button_set_menu_model(GTK_MENU_BUTTON(mbtn), G_MENU_MODEL(menu));
  gtk_header_bar_pack_end(GTK_HEADER_BAR(header), mbtn);
  g_object_unref(menu);

  GSimpleAction *about = g_simple_action_new("about", NULL);
  g_signal_connect(about, "activate", G_CALLBACK(on_about), ctx);
  g_action_map_add_action(G_ACTION_MAP(win), G_ACTION(about));
  g_object_unref(about);

  // horizontal split: chooser | report
  GtkWidget *paned = gtk_paned_new(GTK_ORIENTATION_HORIZONTAL);
  gtk_paned_set_position(GTK_PANED(paned), 320);
  gtk_window_set_child(ctx->win, paned);

  // ---- left: chooser panel ----
  GtkWidget *left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 10);
  gtk_widget_set_margin_top(left, 14);
  gtk_widget_set_margin_bottom(left, 14);
  gtk_widget_set_margin_start(left, 14);
  gtk_widget_set_margin_end(left, 14);

  GtkWidget *title = gtk_label_new("Binary");
  gtk_widget_add_css_class(title, "husk-side-title");
  gtk_widget_set_halign(title, GTK_ALIGN_START);
  gtk_box_append(GTK_BOX(left), title);

  GtkWidget *entry = gtk_entry_new();
  ctx->path_entry = GTK_ENTRY(entry);
  gtk_entry_set_placeholder_text(GTK_ENTRY(entry), "/path/to/executable");
  g_signal_connect(entry, "activate", G_CALLBACK(on_entry_activate), ctx);
  gtk_box_append(GTK_BOX(left), entry);

  GtkWidget *choose = gtk_button_new_with_label("Choose…");
  g_signal_connect(choose, "clicked", G_CALLBACK(on_choose_clicked), ctx);
  gtk_box_append(GTK_BOX(left), choose);

  GtkWidget *verbose = gtk_check_button_new_with_label("Verbose (list segments)");
  ctx->verbose = GTK_CHECK_BUTTON(verbose);
  gtk_box_append(GTK_BOX(left), verbose);

  GtkWidget *analyze = gtk_button_new_with_label("Analyze");
  ctx->analyze_btn = analyze;
  gtk_widget_add_css_class(analyze, "suggested-action");
  g_signal_connect(analyze, "clicked", G_CALLBACK(on_analyze_clicked), ctx);
  gtk_box_append(GTK_BOX(left), analyze);

  // spacer pushes status to the bottom
  GtkWidget *spacer = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
  gtk_widget_set_vexpand(spacer, TRUE);
  gtk_box_append(GTK_BOX(left), spacer);

  GtkWidget *statusbox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
  GtkWidget *spinner = gtk_spinner_new();
  ctx->spinner = GTK_SPINNER(spinner);
  gtk_widget_set_visible(spinner, FALSE);
  GtkWidget *status = gtk_label_new("Ready.");
  ctx->status = GTK_LABEL(status);
  gtk_widget_add_css_class(status, "husk-status");
  gtk_widget_set_halign(status, GTK_ALIGN_START);
  gtk_box_append(GTK_BOX(statusbox), spinner);
  gtk_box_append(GTK_BOX(statusbox), status);
  gtk_box_append(GTK_BOX(left), statusbox);

  gtk_paned_set_start_child(GTK_PANED(paned), left);
  gtk_paned_set_resize_start_child(GTK_PANED(paned), FALSE);
  gtk_paned_set_shrink_start_child(GTK_PANED(paned), FALSE);

  // ---- right: report log ----
  GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
  gtk_widget_set_margin_top(right, 14);
  gtk_widget_set_margin_bottom(right, 14);
  gtk_widget_set_margin_start(right, 14);
  gtk_widget_set_margin_end(right, 14);

  GtkWidget *rtitle = gtk_label_new("Report");
  gtk_widget_add_css_class(rtitle, "husk-side-title");
  gtk_widget_set_halign(rtitle, GTK_ALIGN_START);
  gtk_box_append(GTK_BOX(right), rtitle);

  GtkWidget *scroll = gtk_scrolled_window_new();
  gtk_widget_set_hexpand(scroll, TRUE);
  gtk_widget_set_vexpand(scroll, TRUE);

  GtkWidget *report = gtk_text_view_new();
  ctx->report = GTK_TEXT_VIEW(report);
  gtk_text_view_set_editable(GTK_TEXT_VIEW(report), FALSE);
  gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(report), FALSE);
  gtk_text_view_set_monospace(GTK_TEXT_VIEW(report), TRUE);
  gtk_text_view_set_left_margin(GTK_TEXT_VIEW(report), 10);
  gtk_text_view_set_top_margin(GTK_TEXT_VIEW(report), 8);
  gtk_widget_add_css_class(report, "husk-report");
  gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scroll), report);
  gtk_box_append(GTK_BOX(right), scroll);

  gtk_paned_set_end_child(GTK_PANED(paned), right);
  gtk_paned_set_resize_end_child(GTK_PANED(paned), TRUE);

  set_report(ctx, "Choose a binary on the left to inspect it.\n\n"
                  "husk reads the file only — it never runs it.");

  // free ctx with the window
  g_object_set_data_full(G_OBJECT(win), "ctx", ctx, g_free);
  gtk_window_present(ctx->win);
}

int main(int argc, char **argv) {
  // Normalize the program/WM_CLASS name so it matches husk.desktop's
  // StartupWMClass (the binary is husk-gui, which would otherwise mismatch).
  g_set_prgname(ICON_NAME);
  g_set_application_name("husk");
  GtkApplication *app = gtk_application_new(APP_ID, G_APPLICATION_DEFAULT_FLAGS);
  g_signal_connect(app, "activate", G_CALLBACK(on_activate), NULL);
  int rc = g_application_run(G_APPLICATION(app), argc, argv);
  g_object_unref(app);
  return rc;
}
