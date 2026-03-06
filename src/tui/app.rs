use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Table, TableState, Tabs,
};

use crate::cores::engine::task::{
    EventKind, TaskEvent, TaskMeta, TaskStatus, append_task_event, ensure_task_dir, new_task_id,
    now_epoch_secs, write_task_meta,
};
use crate::errors::RustpenError;

#[derive(Clone)]
struct TaskView {
    meta: TaskMeta,
    dir: PathBuf,
}

#[derive(Clone)]
struct ScriptTaskCtx {
    dir: PathBuf,
    meta: TaskMeta,
}

#[derive(Clone)]
struct ScriptRunResult {
    file: PathBuf,
    ok: bool,
    exit_code: Option<i32>,
    stdout: String,
    stderr: String,
}

#[derive(Clone)]
struct ProjectEntry {
    name: String,
    path: PathBuf,
    imported: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum StatusFilter {
    All,
    Running,
    Failed,
    Succeeded,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ResultKindFilter {
    All,
    Host,
    Web,
    Vuln,
    Reverse,
    Script,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ProjectTemplate {
    Minimal,
    Recon,
    Reverse,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum MiniConsoleLayout {
    DockRightBottom,
    DockLeftBottom,
    Floating,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum MiniConsoleTab {
    Output,
    Terminal,
    Problems,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum TaskTab {
    Overview,
    Events,
    Logs,
    Notes,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum MainPane {
    Dashboard,
    Tasks,
    Launcher,
    Scripts,
    Results,
    Projects,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum InputMode {
    Normal,
    NoteInput,
    CommandInput,
    ScriptEdit,
    ScriptNewInput,
    ProjectNewInput,
    ProjectImportInput,
    ProjectCopyInput,
    ProjectRenameInput,
    ResultSearchInput,
}

impl StatusFilter {
    fn next(self) -> Self {
        match self {
            StatusFilter::All => StatusFilter::Running,
            StatusFilter::Running => StatusFilter::Failed,
            StatusFilter::Failed => StatusFilter::Succeeded,
            StatusFilter::Succeeded => StatusFilter::All,
        }
    }

    fn label(self) -> &'static str {
        match self {
            StatusFilter::All => "all",
            StatusFilter::Running => "running",
            StatusFilter::Failed => "failed",
            StatusFilter::Succeeded => "succeeded",
        }
    }
}

impl ResultKindFilter {
    fn next(self) -> Self {
        match self {
            ResultKindFilter::All => ResultKindFilter::Host,
            ResultKindFilter::Host => ResultKindFilter::Web,
            ResultKindFilter::Web => ResultKindFilter::Vuln,
            ResultKindFilter::Vuln => ResultKindFilter::Reverse,
            ResultKindFilter::Reverse => ResultKindFilter::Script,
            ResultKindFilter::Script => ResultKindFilter::All,
        }
    }

    fn label(self) -> &'static str {
        match self {
            ResultKindFilter::All => "all",
            ResultKindFilter::Host => "host",
            ResultKindFilter::Web => "web",
            ResultKindFilter::Vuln => "vuln",
            ResultKindFilter::Reverse => "reverse",
            ResultKindFilter::Script => "script",
        }
    }
}

impl ProjectTemplate {
    fn next(self) -> Self {
        match self {
            ProjectTemplate::Minimal => ProjectTemplate::Recon,
            ProjectTemplate::Recon => ProjectTemplate::Reverse,
            ProjectTemplate::Reverse => ProjectTemplate::Minimal,
        }
    }

    fn label(self) -> &'static str {
        match self {
            ProjectTemplate::Minimal => "minimal",
            ProjectTemplate::Recon => "recon",
            ProjectTemplate::Reverse => "reverse",
        }
    }
}

impl MiniConsoleLayout {
    fn next(self) -> Self {
        match self {
            MiniConsoleLayout::DockRightBottom => MiniConsoleLayout::DockLeftBottom,
            MiniConsoleLayout::DockLeftBottom => MiniConsoleLayout::Floating,
            MiniConsoleLayout::Floating => MiniConsoleLayout::DockRightBottom,
        }
    }

    fn label(self) -> &'static str {
        match self {
            MiniConsoleLayout::DockRightBottom => "dock-right",
            MiniConsoleLayout::DockLeftBottom => "dock-left",
            MiniConsoleLayout::Floating => "floating",
        }
    }
}

impl MiniConsoleTab {
    fn next(self) -> Self {
        match self {
            MiniConsoleTab::Output => MiniConsoleTab::Terminal,
            MiniConsoleTab::Terminal => MiniConsoleTab::Problems,
            MiniConsoleTab::Problems => MiniConsoleTab::Output,
        }
    }

    fn prev(self) -> Self {
        match self {
            MiniConsoleTab::Output => MiniConsoleTab::Problems,
            MiniConsoleTab::Terminal => MiniConsoleTab::Output,
            MiniConsoleTab::Problems => MiniConsoleTab::Terminal,
        }
    }

    fn index(self) -> usize {
        match self {
            MiniConsoleTab::Output => 0,
            MiniConsoleTab::Terminal => 1,
            MiniConsoleTab::Problems => 2,
        }
    }
}

impl MainPane {
    fn label(self) -> &'static str {
        match self {
            MainPane::Dashboard => "dashboard",
            MainPane::Tasks => "tasks",
            MainPane::Launcher => "launcher",
            MainPane::Scripts => "scripts",
            MainPane::Results => "results",
            MainPane::Projects => "projects",
        }
    }
}

pub fn run_tui(workspace: Option<PathBuf>, refresh_ms: Option<u64>) -> Result<(), RustpenError> {
    let root_ws = workspace.unwrap_or(std::env::current_dir()?);
    let tick = Duration::from_millis(refresh_ms.unwrap_or(500).max(100));

    let mut projects = load_projects(&root_ws)?;
    let mut project_selected = 0usize;
    let mut current_project = projects
        .first()
        .map(|p| p.path.clone())
        .unwrap_or_else(|| root_ws.clone());
    ensure_project_layout(&current_project)?;

    let mut filter = StatusFilter::All;
    let mut result_kind_filter = ResultKindFilter::All;
    let mut result_failed_first = false;
    let mut result_query = String::new();
    let mut all_tasks = load_tasks(current_project.join("tasks"))?;
    let mut tasks = apply_filter(&all_tasks, filter);

    let mut pane = MainPane::Dashboard;
    let mut task_selected = 0usize;
    let mut result_selected = 0usize;
    let mut detail_scroll: u16 = 0;
    let mut effect_scroll: u16 = 0;
    let mut task_tab = TaskTab::Overview;

    let mut input_mode = InputMode::Normal;
    let mut note_buffer = String::new();
    let mut cmd_buffer = String::new();
    let mut script_new_buffer = String::new();
    let mut project_new_buffer = String::new();
    let mut project_import_buffer = String::new();
    let mut project_copy_buffer = String::new();
    let mut project_rename_buffer = String::new();
    let mut result_search_buffer = String::new();
    let mut project_template = ProjectTemplate::Minimal;
    let mut mini_console_visible = true;
    let mut mini_console_layout = MiniConsoleLayout::DockRightBottom;
    let mut mini_float_x_pct: u16 = 52;
    let mut mini_float_y_pct: u16 = 58;
    let mut mini_float_w_pct: u16 = 46;
    let mut mini_float_h_pct: u16 = 36;
    let mut mini_console_tab = MiniConsoleTab::Output;
    let mut mini_console_scroll: u16 = 0;
    let mut mini_popup_mode = false;
    let mut mini_popup_saved_geom: Option<(u16, u16, u16, u16)> = None;
    let mut mini_terminal_lines: Vec<String> = vec!["[terminal] mini terminal ready".to_string()];
    let mut last_status_pushed = String::new();
    let mut status_line =
        "提示: zellij Normal 模式会拦截按键，按 Ctrl-g 切到 Locked 模式".to_string();

    let launcher_items = launcher_commands();
    let mut launcher_selected = 0usize;

    let mut scripts_dir = current_project.join("scripts");
    let _ = fs::create_dir_all(&scripts_dir);
    let mut scripts = load_script_files(&scripts_dir)?;
    let mut script_selected = 0usize;
    let mut script_buffer = String::new();
    let mut script_dirty = false;
    let mut script_output: Vec<String> = vec![
        "[script] script pane ready".to_string(),
        "[script] N:new  i:edit  S:save  R:run".to_string(),
    ];
    let mut script_runner_rx: Option<Receiver<ScriptRunResult>> = None;
    let mut script_running = false;
    let mut script_task: Option<ScriptTaskCtx> = None;

    if let Some(p) = scripts.first() {
        script_buffer = read_script_text(p);
    }

    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(RustpenError::Generic(
            "TUI 需要交互式终端(tty)。请直接在 alacritty/zellij pane 中运行。".to_string(),
        ));
    }

    enable_raw_mode().map_err(RustpenError::Io)?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(
        stdout,
        crossterm::terminal::EnterAlternateScreen,
        crossterm::event::EnableMouseCapture
    )
    .map_err(RustpenError::Io)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend).map_err(RustpenError::Io)?;

    let res = loop {
        let result_indices = build_result_indices(
            &all_tasks,
            result_kind_filter,
            result_failed_first,
            &result_query,
        );
        if result_selected >= result_indices.len() {
            result_selected = result_indices.len().saturating_sub(1);
        }

        if !status_line.is_empty() && status_line != last_status_pushed {
            append_mini_terminal_line(
                &mut mini_terminal_lines,
                format!("[{}] {}", now_epoch_secs(), status_line),
            );
            last_status_pushed = status_line.clone();
        }

        if let Some(done) = poll_script_runner(&mut script_runner_rx) {
            script_running = false;
            status_line = format!(
                "script finished: {} ({})",
                done.file.display(),
                if done.ok { "ok" } else { "failed" }
            );
            append_output_block(
                &mut script_output,
                "[script] stdout",
                &done.stdout,
                "[script] stderr",
                &done.stderr,
            );
            let _ = finalize_script_task(&mut script_task, &done);
            all_tasks = load_tasks(current_project.join("tasks"))?;
            tasks = apply_filter(&all_tasks, filter);
            if task_selected >= tasks.len() {
                task_selected = tasks.len().saturating_sub(1);
            }
            if result_selected >= all_tasks.len() {
                result_selected = all_tasks.len().saturating_sub(1);
            }
        }

        terminal
            .draw(|f| {
                let outer = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(1)
                    .constraints(
                        [
                            Constraint::Length(3),
                            Constraint::Min(5),
                            Constraint::Length(1),
                        ]
                        .as_ref(),
                    )
                    .split(f.size());

                let header = Paragraph::new(Line::from(vec![
                    Span::styled(
                        "rscan TUI ",
                        Style::default().add_modifier(Modifier::BOLD),
                    ),
                    Span::raw(
                        "1:Dashboard 2:Tasks 3:Launcher 4:Scripts 5:Results 6:Projects  v:console b:layout z:dock p:popup 0:reset [/]:tab j/k:scroll  q:quit  Ctrl-c:quit  r:refresh",
                    ),
                    Span::raw("  pane="),
                    Span::styled(
                        pane.label(),
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::raw("  filter="),
                    Span::styled(filter.label(), Style::default().fg(Color::Yellow)),
                    Span::raw("  tab="),
                    Span::styled(task_tab_label(task_tab), Style::default().fg(Color::Green)),
                    Span::raw("  rfilter="),
                    Span::styled(
                        result_kind_filter.label(),
                        Style::default().fg(Color::LightMagenta),
                    ),
                    Span::raw("  rsort="),
                    Span::styled(
                        if result_failed_first {
                            "failed-first"
                        } else {
                            "created-desc"
                        },
                        Style::default().fg(Color::LightGreen),
                    ),
                    Span::raw("  project="),
                    Span::styled(
                        project_name_from_path(&current_project),
                        Style::default().fg(Color::LightCyan),
                    ),
                    Span::raw(if script_running { "  [script running]" } else { "" }),
                    Span::raw(match input_mode {
                        InputMode::Normal => "",
                        InputMode::NoteInput => "  [note mode]",
                        InputMode::CommandInput => "  [command mode]",
                        InputMode::ScriptEdit => "  [script edit mode]",
                        InputMode::ScriptNewInput => "  [new script mode]",
                        InputMode::ProjectNewInput => "  [new project mode]",
                        InputMode::ProjectImportInput => "  [import project mode]",
                        InputMode::ProjectCopyInput => "  [copy project mode]",
                        InputMode::ProjectRenameInput => "  [rename project mode]",
                        InputMode::ResultSearchInput => "  [results search mode]",
                    }),
                ]));
                f.render_widget(header, outer[0]);

                match pane {
                    MainPane::Dashboard => {
                        let lines = build_dashboard_lines(&all_tasks);
                        let w = Paragraph::new(lines)
                            .block(Block::default().borders(Borders::ALL).title("Dashboard"));
                        f.render_widget(w, outer[1]);
                    }
                    MainPane::Tasks => {
                        let body = Layout::default()
                            .direction(Direction::Horizontal)
                            .constraints(
                                [Constraint::Percentage(45), Constraint::Percentage(55)].as_ref(),
                            )
                            .split(outer[1]);

                        let table_rows: Vec<Row> = if tasks.is_empty() {
                            vec![Row::new(vec!["无任务，使用 --task-workspace 生成任务"])]
                        } else {
                            tasks
                                .iter()
                                .map(|t| {
                                    let status_style = match t.meta.status {
                                        TaskStatus::Succeeded => {
                                            Style::default().fg(Color::Green)
                                        }
                                        TaskStatus::Failed => Style::default().fg(Color::Red),
                                        TaskStatus::Running => {
                                            Style::default().fg(Color::Yellow)
                                        }
                                        _ => Style::default(),
                                    };
                                    Row::new(vec![
                                        Cell::from(t.meta.id.clone())
                                            .style(Style::default().fg(Color::Cyan)),
                                        Cell::from(t.meta.kind.clone())
                                            .style(Style::default().fg(Color::Magenta)),
                                        Cell::from(t.meta.status.to_string()).style(status_style),
                                        Cell::from(
                                            t.meta
                                                .progress
                                                .map(|v| format!("{:.1}%", v))
                                                .unwrap_or_else(|| "-".into()),
                                        ),
                                        Cell::from(t.meta.created_at.to_string()),
                                        Cell::from(
                                            t.meta.note.as_ref().map(|n| n.as_str()).unwrap_or(""),
                                        ),
                                    ])
                                })
                                .collect()
                        };
                        let mut table_state = TableState::default();
                        table_state.select(if tasks.is_empty() {
                            None
                        } else {
                            Some(task_selected.min(tasks.len().saturating_sub(1)))
                        });
                        let widths = [
                            Constraint::Length(12),
                            Constraint::Length(8),
                            Constraint::Length(10),
                            Constraint::Length(8),
                            Constraint::Length(12),
                            Constraint::Min(10),
                        ];
                        let table = Table::new(table_rows, &widths)
                            .header(
                                Row::new(vec!["ID", "模块", "状态", "进度", "创建", "备注"])
                                    .bottom_margin(0),
                            )
                            .block(Block::default().borders(Borders::ALL).title("Tasks"))
                            .highlight_style(
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD),
                            );
                        f.render_stateful_widget(table, body[0], &mut table_state);

                        let detail_lines: Vec<Line> = tasks
                            .get(task_selected)
                            .map(|cur| match task_tab {
                                TaskTab::Overview => build_overview_lines(cur),
                                TaskTab::Events => build_event_lines(&cur.dir, 120),
                                TaskTab::Logs => build_logs_lines(&cur.dir, 80),
                                TaskTab::Notes => build_notes_lines(cur, &note_buffer, input_mode),
                            })
                            .unwrap_or_else(|| vec![Line::from(Span::raw("无详情"))]);
                        let detail_widget = Paragraph::new(detail_lines)
                            .block(Block::default().borders(Borders::ALL).title("Detail"));
                        f.render_widget(detail_widget.scroll((detail_scroll, 0)), body[1]);
                    }
                    MainPane::Launcher => {
                        let body = Layout::default()
                            .direction(Direction::Horizontal)
                            .constraints(
                                [Constraint::Percentage(45), Constraint::Percentage(55)].as_ref(),
                            )
                            .split(outer[1]);

                        let items = launcher_items
                            .iter()
                            .map(|item| ListItem::new(item.0))
                            .collect::<Vec<_>>();
                        let mut list_state = ListState::default();
                        list_state.select(Some(
                            launcher_selected.min(launcher_items.len().saturating_sub(1)),
                        ));
                        let list = List::new(items)
                            .block(Block::default().borders(Borders::ALL).title("Launcher"))
                            .highlight_style(
                                Style::default()
                                    .fg(Color::Black)
                                    .bg(Color::Cyan)
                                    .add_modifier(Modifier::BOLD),
                            )
                            .highlight_symbol(">> ");
                        f.render_stateful_widget(list, body[0], &mut list_state);

                        let mut desc = vec![
                            Line::from("内置快捷任务（Enter 执行）"),
                            Line::from("命令会以新的 rscan 进程启动，并写入 task/workspace"),
                            Line::from(""),
                        ];
                        if let Some((_, cmd)) = launcher_items.get(launcher_selected) {
                            desc.push(Line::from(Span::styled(
                                "command:",
                                Style::default().fg(Color::Yellow),
                            )));
                            desc.push(Line::from(cmd.to_string()));
                        }
                        desc.push(Line::from(""));
                        desc.push(Line::from("支持模块: host / web / vuln / reverse"));
                        desc.push(Line::from(
                            "按 : 进入命令模式可手动输入 (h.quick|h.tcp|w.dir|w.fuzz|w.dns|v.scan|r.analyze|r.plan)",
                        ));
                        let p = Paragraph::new(desc)
                            .block(Block::default().borders(Borders::ALL).title("Detail"));
                        f.render_widget(p, body[1]);
                    }
                    MainPane::Scripts => {
                        let body = Layout::default()
                            .direction(Direction::Horizontal)
                            .constraints(
                                [Constraint::Percentage(28), Constraint::Percentage(72)].as_ref(),
                            )
                            .split(outer[1]);

                        let file_items = if scripts.is_empty() {
                            vec![ListItem::new("<empty> (N 创建新脚本)")]
                        } else {
                            scripts
                                .iter()
                                .map(|p| {
                                    ListItem::new(
                                        p.file_name()
                                            .map(|s| s.to_string_lossy().to_string())
                                            .unwrap_or_else(|| p.display().to_string()),
                                    )
                                })
                                .collect::<Vec<_>>()
                        };
                        let mut state = ListState::default();
                        state.select(if scripts.is_empty() {
                            None
                        } else {
                            Some(script_selected.min(scripts.len().saturating_sub(1)))
                        });
                        let list = List::new(file_items)
                            .block(Block::default().borders(Borders::ALL).title("Scripts"))
                            .highlight_style(
                                Style::default()
                                    .fg(Color::Black)
                                    .bg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD),
                            )
                            .highlight_symbol(">> ");
                        f.render_stateful_widget(list, body[0], &mut state);

                        let right = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints(
                                [Constraint::Percentage(60), Constraint::Percentage(40)].as_ref(),
                            )
                            .split(body[1]);

                        let mut title = "Editor".to_string();
                        if let Some(path) = scripts.get(script_selected) {
                            title = format!(
                                "Editor: {}{}",
                                path.display(),
                                if script_dirty { " *" } else { "" }
                            );
                        }
                        let editor = Paragraph::new(script_buffer.as_str())
                            .block(Block::default().borders(Borders::ALL).title(title));
                        f.render_widget(editor, right[0]);

                        let out_text = if script_output.is_empty() {
                            "<empty output>".to_string()
                        } else {
                            script_output.join("\n")
                        };
                        let out = Paragraph::new(out_text).block(
                            Block::default().borders(Borders::ALL).title("Output / Logs"),
                        );
                        f.render_widget(out, right[1]);
                    }
                    MainPane::Results => {
                        let body = Layout::default()
                            .direction(Direction::Horizontal)
                            .constraints(
                                [Constraint::Percentage(38), Constraint::Percentage(62)].as_ref(),
                            )
                            .split(outer[1]);

                        let items = if result_indices.is_empty() {
                            vec![ListItem::new("<empty>")]
                        } else {
                            result_indices
                                .iter()
                                .map(|&idx| {
                                    let t = &all_tasks[idx];
                                    ListItem::new(format!(
                                        "[{}] {} {}",
                                        t.meta.status, t.meta.kind, t.meta.id
                                    ))
                                })
                                .collect::<Vec<_>>()
                        };
                        let mut state = ListState::default();
                        state.select(if result_indices.is_empty() {
                            None
                        } else {
                            Some(result_selected.min(result_indices.len().saturating_sub(1)))
                        });
                        let list = List::new(items)
                            .block(Block::default().borders(Borders::ALL).title("Execution Tasks"))
                            .highlight_style(
                                Style::default()
                                    .fg(Color::Black)
                                    .bg(Color::Green)
                                    .add_modifier(Modifier::BOLD),
                            )
                            .highlight_symbol(">> ");
                        f.render_stateful_widget(list, body[0], &mut state);

                        let lines = result_indices
                            .get(result_selected)
                            .and_then(|idx| all_tasks.get(*idx))
                            .map(|cur| {
                                let mut lines = build_effect_lines(cur);
                                lines.push(line_s(""));
                                lines.push(line_s(&format!(
                                    "view: filter={} sort={}",
                                    result_kind_filter.label(),
                                    if result_failed_first {
                                        "failed-first"
                                    } else {
                                        "created-desc"
                                    }
                                )));
                                lines.push(line_s("快捷键: f=模块过滤  o=失败优先排序"));
                                lines.push(line_s(&format!(
                                    "query: {}",
                                    if result_query.is_empty() {
                                        "<none>"
                                    } else {
                                        result_query.as_str()
                                    }
                                )));
                                lines.push(line_s("快捷键: /=搜索  x=清空搜索"));
                                lines
                            })
                            .unwrap_or_else(|| vec![line_s("无执行效果数据")]);
                        let detail = Paragraph::new(lines).block(
                            Block::default()
                                .borders(Borders::ALL)
                                .title("Module Execution Effect"),
                        );
                        f.render_widget(detail.scroll((effect_scroll, 0)), body[1]);
                    }
                    MainPane::Projects => {
                        let body = Layout::default()
                            .direction(Direction::Horizontal)
                            .constraints(
                                [Constraint::Percentage(42), Constraint::Percentage(58)].as_ref(),
                            )
                            .split(outer[1]);

                        let items = if projects.is_empty() {
                            vec![ListItem::new("<empty>")]
                        } else {
                            projects
                                .iter()
                                .map(|p| {
                                    let mark = if p.imported { "import" } else { "local" };
                                    ListItem::new(format!("[{}] {}", mark, p.name))
                                })
                                .collect::<Vec<_>>()
                        };
                        let mut state = ListState::default();
                        state.select(if projects.is_empty() {
                            None
                        } else {
                            Some(project_selected.min(projects.len().saturating_sub(1)))
                        });
                        let list = List::new(items)
                            .block(Block::default().borders(Borders::ALL).title("Projects"))
                            .highlight_style(
                                Style::default()
                                    .fg(Color::Black)
                                    .bg(Color::Magenta)
                                    .add_modifier(Modifier::BOLD),
                            )
                            .highlight_symbol(">> ");
                        f.render_stateful_widget(list, body[0], &mut state);

                        let mut lines = vec![
                            line_s("项目管理"),
                            line_s("Enter: 切换项目"),
                            line_s("N: 新建项目   I: 导入项目   D: 删除/移除项目"),
                            line_s("C: 复制项目   M: 重命名项目   E: 导出项目快照"),
                            line_s("T: 切换新建项目模板"),
                            line_s(""),
                            line_s(&format!("new-template: {}", project_template.label())),
                            line_s(""),
                        ];
                        if let Some(p) = projects.get(project_selected) {
                            lines.push(line_s(&format!("name: {}", p.name)));
                            lines.push(line_s(&format!(
                                "type: {}",
                                if p.imported { "imported" } else { "local" }
                            )));
                            lines.push(line_s(&format!("path: {}", p.path.display())));
                            lines.push(line_s(&format!(
                                "active: {}",
                                if p.path == current_project { "yes" } else { "no" }
                            )));
                        } else {
                            lines.push(line_s("<no project>"));
                        }
                        let detail = Paragraph::new(lines)
                            .block(Block::default().borders(Borders::ALL).title("Project Detail"));
                        f.render_widget(detail, body[1]);
                    }
                }

                let footer_text = match input_mode {
                    InputMode::CommandInput => format!(":{}", cmd_buffer),
                    InputMode::NoteInput => format!("note> {}", note_buffer),
                    InputMode::ScriptNewInput => format!("script.new> {}", script_new_buffer),
                    InputMode::ProjectNewInput => {
                        format!(
                            "project.new[template={}]> {}",
                            project_template.label(),
                            project_new_buffer
                        )
                    }
                    InputMode::ProjectImportInput => {
                        format!("project.import> {}", project_import_buffer)
                    }
                    InputMode::ProjectCopyInput => {
                        format!("project.copy> {}", project_copy_buffer)
                    }
                    InputMode::ProjectRenameInput => {
                        format!("project.rename> {}", project_rename_buffer)
                    }
                    InputMode::ResultSearchInput => {
                        format!("results.search> {}", result_search_buffer)
                    }
                    InputMode::ScriptEdit => {
                        "script edit: Esc退出  Enter换行  Backspace删除  S保存".to_string()
                    }
                    InputMode::Normal => status_line.clone(),
                };
                let footer = Paragraph::new(footer_text);
                f.render_widget(footer, outer[2]);

                if mini_console_visible {
                    let dock = mini_console_rect_for_layout(
                        outer[1],
                        mini_console_layout,
                        mini_float_x_pct,
                        mini_float_y_pct,
                        mini_float_w_pct,
                        mini_float_h_pct,
                    );
                    let mini_lines = build_mini_console_lines(
                        mini_console_tab,
                        pane,
                        &all_tasks,
                        &tasks,
                        task_selected,
                        &result_indices,
                        result_selected,
                        &script_output,
                        &mini_terminal_lines,
                        &status_line,
                    );
                    let title = if mini_console_layout == MiniConsoleLayout::Floating {
                        format!(
                            "Console / Logs [{}{} x={} y={} w={} h={}]",
                            mini_console_layout.label(),
                            if mini_popup_mode { " popup" } else { "" },
                            mini_float_x_pct,
                            mini_float_y_pct,
                            mini_float_w_pct,
                            mini_float_h_pct
                        )
                    } else {
                        format!("Console / Logs [{}]", mini_console_layout.label())
                    };
                    let border_style = if mini_console_layout == MiniConsoleLayout::Floating {
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Gray)
                    };
                    let sections = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([Constraint::Length(3), Constraint::Min(1)].as_ref())
                        .split(dock);
                    let content_inner_h = sections[1].height.saturating_sub(2) as usize;
                    let max_scroll = mini_lines
                        .len()
                        .saturating_sub(content_inner_h.max(1))
                        .min(u16::MAX as usize) as u16;
                    let render_scroll = mini_console_scroll.min(max_scroll);
                    let tabs = Tabs::new(vec!["Output", "Terminal", "Problems"])
                        .select(mini_console_tab.index())
                        .block(
                            Block::default()
                                .borders(Borders::ALL)
                                .border_style(border_style)
                                .title(title),
                        )
                        .highlight_style(
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD),
                        );
                    let widget = Paragraph::new(mini_lines).block(
                        Block::default()
                            .borders(Borders::ALL)
                            .border_style(border_style)
                            .title("Content"),
                    );
                    f.render_widget(Clear, dock);
                    f.render_widget(tabs, sections[0]);
                    f.render_widget(widget.scroll((render_scroll, 0)), sections[1]);
                }
            })
            .ok();

        if event::poll(tick).map_err(RustpenError::Io)? {
            match event::read().map_err(RustpenError::Io)? {
                Event::Key(key) => {
                    if key.kind == KeyEventKind::Release {
                        continue;
                    }
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && matches!(key.code, KeyCode::Char('c') | KeyCode::Char('C'))
                    {
                        break Ok(());
                    }

                    match input_mode {
                        InputMode::Normal => match key.code {
                            KeyCode::Char('q') => break Ok(()),
                            KeyCode::Char('1') => {
                                pane = MainPane::Dashboard;
                                detail_scroll = 0;
                            }
                            KeyCode::Char('2') => {
                                pane = MainPane::Tasks;
                                detail_scroll = 0;
                            }
                            KeyCode::Char('3') => {
                                pane = MainPane::Launcher;
                                detail_scroll = 0;
                            }
                            KeyCode::Char('4') => {
                                pane = MainPane::Scripts;
                                detail_scroll = 0;
                            }
                            KeyCode::Char('5') => {
                                pane = MainPane::Results;
                                effect_scroll = 0;
                            }
                            KeyCode::Char('6') => {
                                pane = MainPane::Projects;
                            }
                            KeyCode::Char('[') if mini_console_visible => {
                                mini_console_tab = mini_console_tab.prev();
                                mini_console_scroll = 0;
                            }
                            KeyCode::Char(']') if mini_console_visible => {
                                mini_console_tab = mini_console_tab.next();
                                mini_console_scroll = 0;
                            }
                            KeyCode::Char('K') | KeyCode::Char('k') if mini_console_visible => {
                                mini_console_scroll = mini_console_scroll.saturating_sub(3);
                            }
                            KeyCode::Char('J') | KeyCode::Char('j') if mini_console_visible => {
                                mini_console_scroll = mini_console_scroll.saturating_add(3);
                            }
                            KeyCode::Char('v') => {
                                mini_console_visible = !mini_console_visible;
                                status_line = if mini_console_visible {
                                    "mini console: on".to_string()
                                } else {
                                    "mini console: off".to_string()
                                };
                            }
                            KeyCode::Char('b') => {
                                mini_console_layout = mini_console_layout.next();
                                if mini_console_layout != MiniConsoleLayout::Floating {
                                    mini_popup_mode = false;
                                    mini_popup_saved_geom = None;
                                }
                                status_line =
                                    format!("mini console layout: {}", mini_console_layout.label());
                            }
                            KeyCode::Char('z') => {
                                mini_console_layout = match mini_console_layout {
                                    MiniConsoleLayout::DockRightBottom => {
                                        MiniConsoleLayout::DockLeftBottom
                                    }
                                    MiniConsoleLayout::DockLeftBottom => {
                                        MiniConsoleLayout::DockRightBottom
                                    }
                                    MiniConsoleLayout::Floating => {
                                        MiniConsoleLayout::DockRightBottom
                                    }
                                };
                                mini_popup_mode = false;
                                mini_popup_saved_geom = None;
                                status_line =
                                    format!("mini console dock: {}", mini_console_layout.label());
                            }
                            KeyCode::Char('p') => {
                                if !mini_console_visible {
                                    mini_console_visible = true;
                                }
                                if mini_console_layout != MiniConsoleLayout::Floating {
                                    mini_console_layout = MiniConsoleLayout::Floating;
                                }
                                if mini_popup_mode {
                                    if let Some((x, y, w, h)) = mini_popup_saved_geom.take() {
                                        mini_float_x_pct = x;
                                        mini_float_y_pct = y;
                                        mini_float_w_pct = w;
                                        mini_float_h_pct = h;
                                    } else {
                                        mini_float_x_pct = 52;
                                        mini_float_y_pct = 58;
                                        mini_float_w_pct = 46;
                                        mini_float_h_pct = 36;
                                    }
                                    mini_popup_mode = false;
                                    status_line = "mini console popup: off".to_string();
                                } else {
                                    mini_popup_saved_geom = Some((
                                        mini_float_x_pct,
                                        mini_float_y_pct,
                                        mini_float_w_pct,
                                        mini_float_h_pct,
                                    ));
                                    mini_float_x_pct = 4;
                                    mini_float_y_pct = 6;
                                    mini_float_w_pct = 92;
                                    mini_float_h_pct = 84;
                                    mini_popup_mode = true;
                                    status_line = "mini console popup: on".to_string();
                                }
                            }
                            KeyCode::Char('0')
                                if mini_console_visible
                                    && mini_console_layout == MiniConsoleLayout::Floating =>
                            {
                                mini_float_x_pct = 52;
                                mini_float_y_pct = 58;
                                mini_float_w_pct = 46;
                                mini_float_h_pct = 36;
                                mini_popup_mode = false;
                                mini_popup_saved_geom = None;
                                status_line = "mini console float geometry reset".to_string();
                            }
                            KeyCode::Left
                                if mini_console_visible
                                    && mini_console_layout == MiniConsoleLayout::Floating
                                    && key.modifiers.contains(KeyModifiers::CONTROL) =>
                            {
                                mini_popup_mode = false;
                                mini_popup_saved_geom = None;
                                mini_float_x_pct = mini_float_x_pct.saturating_sub(5);
                            }
                            KeyCode::Right
                                if mini_console_visible
                                    && mini_console_layout == MiniConsoleLayout::Floating
                                    && key.modifiers.contains(KeyModifiers::CONTROL) =>
                            {
                                mini_popup_mode = false;
                                mini_popup_saved_geom = None;
                                mini_float_x_pct = (mini_float_x_pct + 5).min(100);
                            }
                            KeyCode::Up
                                if mini_console_visible
                                    && mini_console_layout == MiniConsoleLayout::Floating
                                    && key.modifiers.contains(KeyModifiers::CONTROL) =>
                            {
                                mini_popup_mode = false;
                                mini_popup_saved_geom = None;
                                mini_float_y_pct = mini_float_y_pct.saturating_sub(5);
                            }
                            KeyCode::Down
                                if mini_console_visible
                                    && mini_console_layout == MiniConsoleLayout::Floating
                                    && key.modifiers.contains(KeyModifiers::CONTROL) =>
                            {
                                mini_popup_mode = false;
                                mini_popup_saved_geom = None;
                                mini_float_y_pct = (mini_float_y_pct + 5).min(100);
                            }
                            KeyCode::Left
                                if mini_console_visible
                                    && mini_console_layout == MiniConsoleLayout::Floating
                                    && key.modifiers.contains(KeyModifiers::ALT) =>
                            {
                                mini_popup_mode = false;
                                mini_popup_saved_geom = None;
                                mini_float_w_pct = mini_float_w_pct.saturating_sub(5).max(25);
                            }
                            KeyCode::Right
                                if mini_console_visible
                                    && mini_console_layout == MiniConsoleLayout::Floating
                                    && key.modifiers.contains(KeyModifiers::ALT) =>
                            {
                                mini_popup_mode = false;
                                mini_popup_saved_geom = None;
                                mini_float_w_pct = (mini_float_w_pct + 5).min(90);
                            }
                            KeyCode::Up
                                if mini_console_visible
                                    && mini_console_layout == MiniConsoleLayout::Floating
                                    && key.modifiers.contains(KeyModifiers::ALT) =>
                            {
                                mini_popup_mode = false;
                                mini_popup_saved_geom = None;
                                mini_float_h_pct = mini_float_h_pct.saturating_sub(5).max(20);
                            }
                            KeyCode::Down
                                if mini_console_visible
                                    && mini_console_layout == MiniConsoleLayout::Floating
                                    && key.modifiers.contains(KeyModifiers::ALT) =>
                            {
                                mini_popup_mode = false;
                                mini_popup_saved_geom = None;
                                mini_float_h_pct = (mini_float_h_pct + 5).min(90);
                            }
                            KeyCode::Char(':') => {
                                cmd_buffer.clear();
                                input_mode = InputMode::CommandInput;
                            }
                            KeyCode::Char('r') => {
                                projects = load_projects(&root_ws)?;
                                if project_selected >= projects.len() {
                                    project_selected = projects.len().saturating_sub(1);
                                }
                                all_tasks = load_tasks(current_project.join("tasks"))?;
                                tasks = apply_filter(&all_tasks, filter);
                                scripts = load_script_files(&scripts_dir)?;
                                if task_selected >= tasks.len() {
                                    task_selected = tasks.len().saturating_sub(1);
                                }
                                if result_selected >= all_tasks.len() {
                                    result_selected = all_tasks.len().saturating_sub(1);
                                }
                                if script_selected >= scripts.len() {
                                    script_selected = scripts.len().saturating_sub(1);
                                }
                                if let Some(path) = scripts.get(script_selected) {
                                    if !script_dirty {
                                        script_buffer = read_script_text(path);
                                    }
                                }
                            }
                            _ => match pane {
                                MainPane::Dashboard => match key.code {
                                    KeyCode::Char('s') => {
                                        filter = filter.next();
                                        tasks = apply_filter(&all_tasks, filter);
                                    }
                                    _ => {}
                                },
                                MainPane::Tasks => match key.code {
                                    KeyCode::Char('s') => {
                                        filter = filter.next();
                                        tasks = apply_filter(&all_tasks, filter);
                                        if task_selected >= tasks.len() {
                                            task_selected = tasks.len().saturating_sub(1);
                                        }
                                        detail_scroll = 0;
                                    }
                                    KeyCode::Char('t') => {
                                        task_tab = match task_tab {
                                            TaskTab::Overview => TaskTab::Events,
                                            TaskTab::Events => TaskTab::Logs,
                                            TaskTab::Logs => TaskTab::Notes,
                                            TaskTab::Notes => TaskTab::Overview,
                                        };
                                        detail_scroll = 0;
                                    }
                                    KeyCode::Char('n') => {
                                        note_buffer.clear();
                                        input_mode = InputMode::NoteInput;
                                    }
                                    KeyCode::Enter => {
                                        detail_scroll = 0;
                                    }
                                    KeyCode::PageDown => {
                                        detail_scroll = detail_scroll.saturating_add(5);
                                    }
                                    KeyCode::PageUp => {
                                        detail_scroll = detail_scroll.saturating_sub(5);
                                    }
                                    KeyCode::Up => {
                                        if !tasks.is_empty() {
                                            task_selected = task_selected.saturating_sub(1);
                                            detail_scroll = 0;
                                        }
                                    }
                                    KeyCode::Down => {
                                        if !tasks.is_empty() {
                                            task_selected = (task_selected + 1)
                                                .min(tasks.len().saturating_sub(1));
                                            detail_scroll = 0;
                                        }
                                    }
                                    _ => {}
                                },
                                MainPane::Launcher => match key.code {
                                    KeyCode::Up => {
                                        launcher_selected = launcher_selected.saturating_sub(1);
                                    }
                                    KeyCode::Down => {
                                        launcher_selected = (launcher_selected + 1)
                                            .min(launcher_items.len().saturating_sub(1));
                                    }
                                    KeyCode::Enter => {
                                        if let Some((_, cmd)) =
                                            launcher_items.get(launcher_selected)
                                        {
                                            status_line =
                                                execute_short_command(&current_project, cmd);
                                            all_tasks = load_tasks(current_project.join("tasks"))?;
                                            tasks = apply_filter(&all_tasks, filter);
                                            if result_selected >= all_tasks.len() {
                                                result_selected = all_tasks.len().saturating_sub(1);
                                            }
                                        }
                                    }
                                    _ => {}
                                },
                                MainPane::Scripts => match key.code {
                                    KeyCode::Up => {
                                        if !scripts.is_empty() {
                                            let next = script_selected.saturating_sub(1);
                                            switch_script_selection(
                                                next,
                                                &scripts,
                                                &mut script_selected,
                                                &mut script_buffer,
                                                &mut script_dirty,
                                                &mut status_line,
                                            );
                                        }
                                    }
                                    KeyCode::Down => {
                                        if !scripts.is_empty() {
                                            let next = (script_selected + 1)
                                                .min(scripts.len().saturating_sub(1));
                                            switch_script_selection(
                                                next,
                                                &scripts,
                                                &mut script_selected,
                                                &mut script_buffer,
                                                &mut script_dirty,
                                                &mut status_line,
                                            );
                                        }
                                    }
                                    KeyCode::Char('N') => {
                                        script_new_buffer.clear();
                                        input_mode = InputMode::ScriptNewInput;
                                    }
                                    KeyCode::Char('i') => {
                                        if scripts.is_empty() {
                                            status_line = "先按 N 创建脚本".to_string();
                                        } else {
                                            input_mode = InputMode::ScriptEdit;
                                        }
                                    }
                                    KeyCode::Char('S') => {
                                        if scripts.is_empty() {
                                            status_line = "没有可保存的脚本".to_string();
                                        } else {
                                            match save_current_script(
                                                &scripts,
                                                script_selected,
                                                &script_buffer,
                                            ) {
                                                Ok(msg) => {
                                                    script_dirty = false;
                                                    status_line = msg;
                                                }
                                                Err(e) => {
                                                    status_line = format!("save failed: {}", e);
                                                }
                                            }
                                        }
                                    }
                                    KeyCode::Char('R') => {
                                        if script_running {
                                            status_line = "已有脚本正在运行".to_string();
                                        } else if scripts.is_empty() {
                                            status_line = "没有脚本可运行".to_string();
                                        } else {
                                            if script_dirty {
                                                match save_current_script(
                                                    &scripts,
                                                    script_selected,
                                                    &script_buffer,
                                                ) {
                                                    Ok(_) => script_dirty = false,
                                                    Err(e) => {
                                                        status_line = format!(
                                                            "自动保存失败，已取消运行: {}",
                                                            e
                                                        );
                                                        continue;
                                                    }
                                                }
                                            }
                                            if let Some(path) = scripts.get(script_selected) {
                                                script_task =
                                                    start_script_task(&current_project, path).ok();
                                                script_runner_rx =
                                                    Some(start_script_runner(path.clone()));
                                                script_running = true;
                                                status_line =
                                                    format!("running script: {}", path.display());
                                            }
                                        }
                                    }
                                    _ => {}
                                },
                                MainPane::Results => match key.code {
                                    KeyCode::Up => {
                                        if !result_indices.is_empty() {
                                            result_selected = result_selected.saturating_sub(1);
                                            effect_scroll = 0;
                                        }
                                    }
                                    KeyCode::Down => {
                                        if !result_indices.is_empty() {
                                            result_selected = (result_selected + 1)
                                                .min(result_indices.len().saturating_sub(1));
                                            effect_scroll = 0;
                                        }
                                    }
                                    KeyCode::PageDown => {
                                        effect_scroll = effect_scroll.saturating_add(5);
                                    }
                                    KeyCode::PageUp => {
                                        effect_scroll = effect_scroll.saturating_sub(5);
                                    }
                                    KeyCode::Char('f') => {
                                        result_kind_filter = result_kind_filter.next();
                                        result_selected = 0;
                                        effect_scroll = 0;
                                    }
                                    KeyCode::Char('o') => {
                                        result_failed_first = !result_failed_first;
                                        result_selected = 0;
                                        effect_scroll = 0;
                                    }
                                    KeyCode::Char('/') => {
                                        result_search_buffer = result_query.clone();
                                        input_mode = InputMode::ResultSearchInput;
                                    }
                                    KeyCode::Char('x') => {
                                        result_query.clear();
                                        result_selected = 0;
                                        effect_scroll = 0;
                                    }
                                    KeyCode::Enter => {
                                        if let Some(idx) = result_indices.get(result_selected)
                                            && let Some(cur) = all_tasks.get(*idx)
                                        {
                                            if let Some(pos) =
                                                tasks.iter().position(|t| t.meta.id == cur.meta.id)
                                            {
                                                task_selected = pos;
                                                pane = MainPane::Tasks;
                                                task_tab = TaskTab::Logs;
                                                detail_scroll = 0;
                                                status_line =
                                                    format!("已定位到任务: {}", cur.meta.id);
                                            }
                                        }
                                    }
                                    _ => {}
                                },
                                MainPane::Projects => match key.code {
                                    KeyCode::Up => {
                                        if !projects.is_empty() {
                                            project_selected = project_selected.saturating_sub(1);
                                        }
                                    }
                                    KeyCode::Down => {
                                        if !projects.is_empty() {
                                            project_selected = (project_selected + 1)
                                                .min(projects.len().saturating_sub(1));
                                        }
                                    }
                                    KeyCode::Char('N') | KeyCode::Char('n') => {
                                        project_new_buffer.clear();
                                        input_mode = InputMode::ProjectNewInput;
                                    }
                                    KeyCode::Char('I') | KeyCode::Char('i') => {
                                        project_import_buffer.clear();
                                        input_mode = InputMode::ProjectImportInput;
                                    }
                                    KeyCode::Char('C') | KeyCode::Char('c') => {
                                        project_copy_buffer.clear();
                                        input_mode = InputMode::ProjectCopyInput;
                                    }
                                    KeyCode::Char('M') | KeyCode::Char('m') => {
                                        if let Some(sel) = projects.get(project_selected) {
                                            if sel.imported {
                                                status_line =
                                                    "导入项目不能直接重命名，可先复制为本地项目"
                                                        .to_string();
                                            } else {
                                                project_rename_buffer =
                                                    project_name_from_path(&sel.path);
                                                input_mode = InputMode::ProjectRenameInput;
                                            }
                                        }
                                    }
                                    KeyCode::Char('T') | KeyCode::Char('t') => {
                                        project_template = project_template.next();
                                        status_line = format!(
                                            "新建项目模板已切换: {}",
                                            project_template.label()
                                        );
                                    }
                                    KeyCode::Char('E') | KeyCode::Char('e') => {
                                        if let Some(sel) = projects.get(project_selected) {
                                            match export_project_snapshot(&root_ws, &sel.path) {
                                                Ok(out) => {
                                                    status_line = format!(
                                                        "项目已导出快照: {}",
                                                        out.display()
                                                    );
                                                }
                                                Err(e) => {
                                                    status_line = format!("项目导出失败: {}", e);
                                                }
                                            }
                                        }
                                    }
                                    KeyCode::Char('D') | KeyCode::Char('d') => {
                                        if let Some(sel) = projects.get(project_selected).cloned() {
                                            if sel.path == current_project {
                                                status_line =
                                                    "当前激活项目不能删除/移除，请先切换到其他项目"
                                                        .to_string();
                                            } else if sel.imported {
                                                remove_imported_project(&root_ws, &sel.path)?;
                                                projects = load_projects(&root_ws)?;
                                                if project_selected >= projects.len() {
                                                    project_selected =
                                                        projects.len().saturating_sub(1);
                                                }
                                                status_line = format!(
                                                    "已移除导入项目: {}",
                                                    sel.path.display()
                                                );
                                            } else {
                                                delete_local_project(&root_ws, &sel.path)?;
                                                projects = load_projects(&root_ws)?;
                                                if project_selected >= projects.len() {
                                                    project_selected =
                                                        projects.len().saturating_sub(1);
                                                }
                                                status_line =
                                                    format!("已删除项目: {}", sel.path.display());
                                            }
                                        }
                                    }
                                    KeyCode::Enter => {
                                        if script_running {
                                            status_line =
                                                "脚本正在运行，暂不可切换项目".to_string();
                                        } else if let Some(sel) = projects.get(project_selected) {
                                            current_project = sel.path.clone();
                                            ensure_project_layout(&current_project)?;
                                            scripts_dir = current_project.join("scripts");
                                            let _ = fs::create_dir_all(&scripts_dir);
                                            all_tasks = load_tasks(current_project.join("tasks"))?;
                                            tasks = apply_filter(&all_tasks, filter);
                                            scripts = load_script_files(&scripts_dir)?;
                                            task_selected =
                                                task_selected.min(tasks.len().saturating_sub(1));
                                            result_selected = result_selected
                                                .min(all_tasks.len().saturating_sub(1));
                                            script_selected = script_selected
                                                .min(scripts.len().saturating_sub(1));
                                            if !script_dirty {
                                                if let Some(path) = scripts.get(script_selected) {
                                                    script_buffer = read_script_text(path);
                                                } else {
                                                    script_buffer.clear();
                                                }
                                            }
                                            status_line = format!(
                                                "已切换项目: {}",
                                                current_project.display()
                                            );
                                        }
                                    }
                                    _ => {}
                                },
                            },
                        },
                        InputMode::CommandInput => match key.code {
                            KeyCode::Esc => {
                                input_mode = InputMode::Normal;
                                cmd_buffer.clear();
                            }
                            KeyCode::Enter => {
                                let msg = execute_short_command(&current_project, &cmd_buffer);
                                status_line = msg;
                                input_mode = InputMode::Normal;
                                cmd_buffer.clear();
                                all_tasks = load_tasks(current_project.join("tasks"))?;
                                tasks = apply_filter(&all_tasks, filter);
                                if task_selected >= tasks.len() {
                                    task_selected = tasks.len().saturating_sub(1);
                                }
                                if result_selected >= all_tasks.len() {
                                    result_selected = all_tasks.len().saturating_sub(1);
                                }
                            }
                            KeyCode::Backspace => {
                                cmd_buffer.pop();
                            }
                            KeyCode::Char(c) => {
                                cmd_buffer.push(c);
                            }
                            _ => {}
                        },
                        InputMode::NoteInput => match key.code {
                            KeyCode::Esc => {
                                input_mode = InputMode::Normal;
                                note_buffer.clear();
                            }
                            KeyCode::Enter => {
                                if let Some(cur) = tasks.get_mut(task_selected) {
                                    let mut meta = cur.meta.clone();
                                    let existing = meta.note.clone().unwrap_or_default();
                                    let new_note = if existing.is_empty() {
                                        note_buffer.clone()
                                    } else {
                                        format!("{existing}\n{note_buffer}")
                                    };
                                    meta.note = Some(new_note);
                                    let _ = write_task_meta(&cur.dir, &meta);
                                    let ev = TaskEvent {
                                        ts: now_epoch_secs(),
                                        level: "info".to_string(),
                                        kind: EventKind::Control,
                                        message: Some(format!("note: {}", note_buffer)),
                                        data: None,
                                    };
                                    let _ = append_task_event(&cur.dir, &ev);
                                    cur.meta = meta;
                                }
                                input_mode = InputMode::Normal;
                                note_buffer.clear();
                            }
                            KeyCode::Backspace => {
                                note_buffer.pop();
                            }
                            KeyCode::Char(c) => {
                                note_buffer.push(c);
                            }
                            _ => {}
                        },
                        InputMode::ScriptEdit => match key.code {
                            KeyCode::Esc => {
                                input_mode = InputMode::Normal;
                            }
                            KeyCode::Enter => {
                                script_buffer.push('\n');
                                script_dirty = true;
                            }
                            KeyCode::Backspace => {
                                script_buffer.pop();
                                script_dirty = true;
                            }
                            KeyCode::Tab => {
                                script_buffer.push('\t');
                                script_dirty = true;
                            }
                            KeyCode::Char('S') => {
                                if scripts.is_empty() {
                                    status_line = "没有可保存的脚本".to_string();
                                } else {
                                    match save_current_script(
                                        &scripts,
                                        script_selected,
                                        &script_buffer,
                                    ) {
                                        Ok(msg) => {
                                            script_dirty = false;
                                            status_line = msg;
                                        }
                                        Err(e) => {
                                            status_line = format!("save failed: {}", e);
                                        }
                                    }
                                }
                            }
                            KeyCode::Char(c) => {
                                script_buffer.push(c);
                                script_dirty = true;
                            }
                            _ => {}
                        },
                        InputMode::ScriptNewInput => match key.code {
                            KeyCode::Esc => {
                                input_mode = InputMode::Normal;
                                script_new_buffer.clear();
                            }
                            KeyCode::Enter => {
                                let name = script_new_buffer.trim().to_string();
                                if name.is_empty() {
                                    status_line = "文件名不能为空".to_string();
                                } else {
                                    match create_script_file(&scripts_dir, &name) {
                                        Ok(path) => {
                                            scripts = load_script_files(&scripts_dir)?;
                                            if let Some(pos) =
                                                scripts.iter().position(|p| p == &path)
                                            {
                                                script_selected = pos;
                                            } else {
                                                script_selected = scripts.len().saturating_sub(1);
                                            }
                                            script_buffer = read_script_text(&path);
                                            script_dirty = false;
                                            status_line =
                                                format!("created script: {}", path.display());
                                        }
                                        Err(e) => {
                                            status_line = format!("create script failed: {}", e);
                                        }
                                    }
                                }
                                script_new_buffer.clear();
                                input_mode = InputMode::Normal;
                            }
                            KeyCode::Backspace => {
                                script_new_buffer.pop();
                            }
                            KeyCode::Char(c) => {
                                script_new_buffer.push(c);
                            }
                            _ => {}
                        },
                        InputMode::ProjectNewInput => match key.code {
                            KeyCode::Esc => {
                                input_mode = InputMode::Normal;
                                project_new_buffer.clear();
                            }
                            KeyCode::Enter => {
                                let name = project_new_buffer.trim().to_string();
                                if name.is_empty() {
                                    status_line = "项目名不能为空".to_string();
                                } else {
                                    match create_local_project(&root_ws, &name, project_template) {
                                        Ok(path) => {
                                            projects = load_projects(&root_ws)?;
                                            if let Some(pos) =
                                                projects.iter().position(|p| p.path == path)
                                            {
                                                project_selected = pos;
                                            }
                                            status_line = format!("已创建项目: {}", path.display());
                                        }
                                        Err(e) => {
                                            status_line = format!("创建项目失败: {}", e);
                                        }
                                    }
                                }
                                project_new_buffer.clear();
                                input_mode = InputMode::Normal;
                            }
                            KeyCode::Backspace => {
                                project_new_buffer.pop();
                            }
                            KeyCode::Char(c) => {
                                project_new_buffer.push(c);
                            }
                            _ => {}
                        },
                        InputMode::ProjectImportInput => match key.code {
                            KeyCode::Esc => {
                                input_mode = InputMode::Normal;
                                project_import_buffer.clear();
                            }
                            KeyCode::Enter => {
                                let raw = project_import_buffer.trim().to_string();
                                if raw.is_empty() {
                                    status_line = "导入路径不能为空".to_string();
                                } else {
                                    let path = PathBuf::from(raw);
                                    match import_project(&root_ws, &path) {
                                        Ok(imported) => {
                                            projects = load_projects(&root_ws)?;
                                            if let Some(pos) = projects
                                                .iter()
                                                .position(|p| same_path(&p.path, &imported))
                                            {
                                                project_selected = pos;
                                            }
                                            status_line =
                                                format!("导入成功: {}", imported.display());
                                        }
                                        Err(e) => {
                                            status_line = format!("导入项目失败: {}", e);
                                        }
                                    }
                                }
                                project_import_buffer.clear();
                                input_mode = InputMode::Normal;
                            }
                            KeyCode::Backspace => {
                                project_import_buffer.pop();
                            }
                            KeyCode::Char(c) => {
                                project_import_buffer.push(c);
                            }
                            _ => {}
                        },
                        InputMode::ProjectCopyInput => match key.code {
                            KeyCode::Esc => {
                                input_mode = InputMode::Normal;
                                project_copy_buffer.clear();
                            }
                            KeyCode::Enter => {
                                let name = project_copy_buffer.trim().to_string();
                                if name.is_empty() {
                                    status_line = "复制项目名不能为空".to_string();
                                } else if let Some(sel) = projects.get(project_selected).cloned() {
                                    match copy_project_to_local(&root_ws, &sel.path, &name) {
                                        Ok(new_path) => {
                                            projects = load_projects(&root_ws)?;
                                            if let Some(pos) = projects
                                                .iter()
                                                .position(|p| same_path(&p.path, &new_path))
                                            {
                                                project_selected = pos;
                                            }
                                            status_line =
                                                format!("项目复制完成: {}", new_path.display());
                                        }
                                        Err(e) => {
                                            status_line = format!("复制项目失败: {}", e);
                                        }
                                    }
                                }
                                project_copy_buffer.clear();
                                input_mode = InputMode::Normal;
                            }
                            KeyCode::Backspace => {
                                project_copy_buffer.pop();
                            }
                            KeyCode::Char(c) => {
                                project_copy_buffer.push(c);
                            }
                            _ => {}
                        },
                        InputMode::ProjectRenameInput => match key.code {
                            KeyCode::Esc => {
                                input_mode = InputMode::Normal;
                                project_rename_buffer.clear();
                            }
                            KeyCode::Enter => {
                                let name = project_rename_buffer.trim().to_string();
                                if name.is_empty() {
                                    status_line = "重命名项目名不能为空".to_string();
                                } else if let Some(sel) = projects.get(project_selected).cloned() {
                                    if sel.imported {
                                        status_line = "导入项目不能直接重命名，可先复制为本地项目"
                                            .to_string();
                                    } else if script_running && sel.path == current_project {
                                        status_line =
                                            "脚本运行中，暂不可重命名当前项目".to_string();
                                    } else if script_dirty && sel.path == current_project {
                                        status_line =
                                            "当前脚本有未保存内容，先保存再重命名项目".to_string();
                                    } else {
                                        match rename_local_project(&root_ws, &sel.path, &name) {
                                            Ok(new_path) => {
                                                if same_path(&current_project, &sel.path) {
                                                    current_project = new_path.clone();
                                                    scripts_dir = current_project.join("scripts");
                                                    let _ = fs::create_dir_all(&scripts_dir);
                                                    all_tasks =
                                                        load_tasks(current_project.join("tasks"))?;
                                                    tasks = apply_filter(&all_tasks, filter);
                                                    scripts = load_script_files(&scripts_dir)?;
                                                    task_selected = task_selected
                                                        .min(tasks.len().saturating_sub(1));
                                                    script_selected = script_selected
                                                        .min(scripts.len().saturating_sub(1));
                                                    if let Some(path) = scripts.get(script_selected)
                                                    {
                                                        script_buffer = read_script_text(path);
                                                    } else {
                                                        script_buffer.clear();
                                                    }
                                                }
                                                projects = load_projects(&root_ws)?;
                                                if let Some(pos) = projects
                                                    .iter()
                                                    .position(|p| same_path(&p.path, &new_path))
                                                {
                                                    project_selected = pos;
                                                }
                                                status_line = format!(
                                                    "项目重命名完成: {}",
                                                    new_path.display()
                                                );
                                            }
                                            Err(e) => {
                                                status_line = format!("重命名项目失败: {}", e);
                                            }
                                        }
                                    }
                                }
                                project_rename_buffer.clear();
                                input_mode = InputMode::Normal;
                            }
                            KeyCode::Backspace => {
                                project_rename_buffer.pop();
                            }
                            KeyCode::Char(c) => {
                                project_rename_buffer.push(c);
                            }
                            _ => {}
                        },
                        InputMode::ResultSearchInput => match key.code {
                            KeyCode::Esc => {
                                input_mode = InputMode::Normal;
                                result_search_buffer.clear();
                            }
                            KeyCode::Enter => {
                                result_query = result_search_buffer.trim().to_string();
                                result_selected = 0;
                                effect_scroll = 0;
                                input_mode = InputMode::Normal;
                            }
                            KeyCode::Backspace => {
                                result_search_buffer.pop();
                            }
                            KeyCode::Char(c) => {
                                result_search_buffer.push(c);
                            }
                            _ => {}
                        },
                    }
                }
                _ => {}
            }
        }
    };

    disable_raw_mode().map_err(RustpenError::Io)?;
    crossterm::execute!(
        terminal.backend_mut(),
        crossterm::event::DisableMouseCapture,
        crossterm::terminal::LeaveAlternateScreen
    )
    .map_err(RustpenError::Io)?;
    terminal.show_cursor().ok();
    res
}

fn launcher_commands() -> Vec<(&'static str, &'static str)> {
    vec![
        ("Host Quick (127.0.0.1)", "h.quick 127.0.0.1"),
        ("Host TCP 22,80,443", "h.tcp 127.0.0.1 22,80,443"),
        (
            "Web Dir example.com",
            "w.dir https://example.com /,/robots.txt",
        ),
        (
            "Web Fuzz example.com/FUZZ",
            "w.fuzz https://example.com/FUZZ admin,login",
        ),
        ("Web DNS example.com", "w.dns example.com www,api,dev"),
        ("Vuln Scan example.com", "v.scan https://example.com"),
        ("Reverse Analyze /bin/ls", "r.analyze /bin/ls"),
        ("Reverse Plan /bin/ls", "r.plan /bin/ls objdump"),
    ]
}

fn load_tasks(dir: PathBuf) -> Result<Vec<TaskView>, RustpenError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut metas = Vec::new();
    for entry in fs::read_dir(&dir).map_err(RustpenError::Io)? {
        let entry = entry.map_err(RustpenError::Io)?;
        let p = entry.path().join("meta.json");
        if !p.is_file() {
            continue;
        }
        if let Ok(text) = fs::read_to_string(&p)
            && let Ok(meta) = serde_json::from_str::<TaskMeta>(&text)
        {
            metas.push(TaskView {
                meta,
                dir: entry.path(),
            });
        }
    }
    metas.sort_by_key(|m| std::cmp::Reverse(m.meta.created_at));
    Ok(metas)
}

fn project_name_from_path(path: &PathBuf) -> String {
    path.file_name()
        .map(|s| s.to_string_lossy().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| path.display().to_string())
}

fn projects_root_dir(root_ws: &PathBuf) -> PathBuf {
    root_ws.join("projects")
}

fn project_registry_path(root_ws: &PathBuf) -> PathBuf {
    root_ws.join(".rscan_projects_imports.json")
}

fn ensure_project_layout(project_dir: &PathBuf) -> Result<(), RustpenError> {
    fs::create_dir_all(project_dir).map_err(RustpenError::Io)?;
    fs::create_dir_all(project_dir.join("tasks")).map_err(RustpenError::Io)?;
    fs::create_dir_all(project_dir.join("scripts")).map_err(RustpenError::Io)?;
    fs::create_dir_all(project_dir.join("vuln_templates")).map_err(RustpenError::Io)?;
    Ok(())
}

fn load_imported_project_paths(root_ws: &PathBuf) -> Result<Vec<PathBuf>, RustpenError> {
    let path = project_registry_path(root_ws);
    if !path.is_file() {
        return Ok(vec![]);
    }
    let text = fs::read_to_string(path).map_err(RustpenError::Io)?;
    let entries = serde_json::from_str::<Vec<String>>(&text).unwrap_or_default();
    Ok(entries.into_iter().map(PathBuf::from).collect())
}

fn save_imported_project_paths(root_ws: &PathBuf, paths: &[PathBuf]) -> Result<(), RustpenError> {
    let text = serde_json::to_string_pretty(
        &paths
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
    )
    .map_err(|e| RustpenError::ParseError(e.to_string()))?;
    fs::write(project_registry_path(root_ws), text).map_err(RustpenError::Io)?;
    Ok(())
}

fn same_path(a: &PathBuf, b: &PathBuf) -> bool {
    let ca = fs::canonicalize(a).unwrap_or_else(|_| a.clone());
    let cb = fs::canonicalize(b).unwrap_or_else(|_| b.clone());
    ca == cb
}

fn load_projects(root_ws: &PathBuf) -> Result<Vec<ProjectEntry>, RustpenError> {
    let project_root = projects_root_dir(root_ws);
    fs::create_dir_all(&project_root).map_err(RustpenError::Io)?;

    let mut out: Vec<ProjectEntry> = Vec::new();
    for entry in fs::read_dir(&project_root).map_err(RustpenError::Io)? {
        let entry = entry.map_err(RustpenError::Io)?;
        let p = entry.path();
        if !p.is_dir() {
            continue;
        }
        ensure_project_layout(&p)?;
        out.push(ProjectEntry {
            name: project_name_from_path(&p),
            path: p,
            imported: false,
        });
    }

    if out.is_empty() {
        let default_path = project_root.join("default");
        ensure_project_layout(&default_path)?;
        init_project_template(&default_path, ProjectTemplate::Minimal)?;
        out.push(ProjectEntry {
            name: "default".to_string(),
            path: default_path,
            imported: false,
        });
    }

    for p in load_imported_project_paths(root_ws)? {
        if !p.is_dir() {
            continue;
        }
        if out.iter().any(|x| same_path(&x.path, &p)) {
            continue;
        }
        if ensure_project_layout(&p).is_err() {
            continue;
        }
        out.push(ProjectEntry {
            name: project_name_from_path(&p),
            path: p,
            imported: true,
        });
    }

    out.sort_by(|a, b| {
        a.imported
            .cmp(&b.imported)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(out)
}

fn sanitize_project_name(raw: &str) -> String {
    let mut s = String::with_capacity(raw.len());
    for ch in raw.trim().chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            s.push(ch);
        } else if ch.is_whitespace() {
            s.push('_');
        }
    }
    while s.contains("__") {
        s = s.replace("__", "_");
    }
    s.trim_matches('_').to_string()
}

fn write_if_missing(path: &PathBuf, content: &str) -> Result<(), RustpenError> {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(RustpenError::Io)?;
        }
        fs::write(path, content).map_err(RustpenError::Io)?;
    }
    Ok(())
}

fn init_project_template(
    project_path: &PathBuf,
    template: ProjectTemplate,
) -> Result<(), RustpenError> {
    let readme = match template {
        ProjectTemplate::Minimal => {
            "# rscan Project\n\nTemplate: minimal\n\n- tasks/\n- scripts/\n- vuln_templates/\n"
        }
        ProjectTemplate::Recon => {
            "# rscan Project\n\nTemplate: recon\n\n建议流程:\n1. host quick/tcp\n2. web dir/fuzz/dns\n3. vuln scan\n"
        }
        ProjectTemplate::Reverse => {
            "# rscan Project\n\nTemplate: reverse\n\n建议流程:\n1. reverse analyze\n2. reverse decompile-plan\n3. reverse jobs/console\n"
        }
    };
    write_if_missing(&project_path.join("README.md"), readme)?;

    match template {
        ProjectTemplate::Minimal => {
            write_if_missing(
                &project_path.join("scripts").join("hello.py"),
                "print('hello from project template: minimal')\n",
            )?;
        }
        ProjectTemplate::Recon => {
            write_if_missing(
                &project_path.join("scripts").join("recon.py"),
                "targets = ['127.0.0.1']\nfor t in targets:\n    print(f'recon target={t}')\n",
            )?;
            write_if_missing(
                &project_path.join("vuln_templates").join("basic_http.yaml"),
                "id: project-basic-http\ninfo:\n  name: Project Basic HTTP\n  severity: info\nhttp:\n  - method: GET\n    path: ['/', '/robots.txt']\n    matchers:\n      - type: status\n        status: [200,301,302,401,403]\n",
            )?;
        }
        ProjectTemplate::Reverse => {
            write_if_missing(
                &project_path.join("scripts").join("reverse_notes.rs"),
                "fn main() {\n    println!(\"reverse template project ready\");\n}\n",
            )?;
        }
    }
    Ok(())
}

fn create_local_project(
    root_ws: &PathBuf,
    raw_name: &str,
    template: ProjectTemplate,
) -> Result<PathBuf, RustpenError> {
    let name = sanitize_project_name(raw_name);
    if name.is_empty() {
        return Err(RustpenError::ParseError(
            "project name contains no valid characters".to_string(),
        ));
    }
    let path = projects_root_dir(root_ws).join(name);
    if path.exists() {
        return Err(RustpenError::ParseError(format!(
            "project already exists: {}",
            path.display()
        )));
    }
    ensure_project_layout(&path)?;
    init_project_template(&path, template)?;
    Ok(path)
}

fn import_project(root_ws: &PathBuf, raw_path: &PathBuf) -> Result<PathBuf, RustpenError> {
    let path = if raw_path.is_absolute() {
        raw_path.clone()
    } else {
        std::env::current_dir()?.join(raw_path)
    };
    if !path.is_dir() {
        return Err(RustpenError::ParseError(format!(
            "project path not found: {}",
            path.display()
        )));
    }
    ensure_project_layout(&path)?;
    let mut imports = load_imported_project_paths(root_ws)?;
    if !imports.iter().any(|p| same_path(p, &path)) {
        imports.push(path.clone());
        save_imported_project_paths(root_ws, &imports)?;
    }
    Ok(path)
}

fn remove_imported_project(root_ws: &PathBuf, path: &PathBuf) -> Result<(), RustpenError> {
    let imports = load_imported_project_paths(root_ws)?;
    let kept = imports
        .into_iter()
        .filter(|p| !same_path(p, path))
        .collect::<Vec<_>>();
    save_imported_project_paths(root_ws, &kept)?;
    Ok(())
}

fn delete_local_project(root_ws: &PathBuf, path: &PathBuf) -> Result<(), RustpenError> {
    let root = projects_root_dir(root_ws);
    if !path.starts_with(&root) {
        return Err(RustpenError::ParseError(format!(
            "refuse deleting non-local project: {}",
            path.display()
        )));
    }
    if path.exists() {
        fs::remove_dir_all(path).map_err(RustpenError::Io)?;
    }
    Ok(())
}

fn copy_dir_recursive(src: &PathBuf, dst: &PathBuf) -> Result<(), RustpenError> {
    if !src.is_dir() {
        return Err(RustpenError::ParseError(format!(
            "source is not directory: {}",
            src.display()
        )));
    }
    if dst.exists() {
        return Err(RustpenError::ParseError(format!(
            "destination already exists: {}",
            dst.display()
        )));
    }
    fs::create_dir_all(dst).map_err(RustpenError::Io)?;
    for entry in fs::read_dir(src).map_err(RustpenError::Io)? {
        let entry = entry.map_err(RustpenError::Io)?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if from.is_dir() {
            copy_dir_recursive(&from, &to)?;
        } else if from.is_file() {
            fs::copy(&from, &to).map_err(RustpenError::Io)?;
        }
    }
    Ok(())
}

fn copy_project_to_local(
    root_ws: &PathBuf,
    source_project: &PathBuf,
    new_name: &str,
) -> Result<PathBuf, RustpenError> {
    let name = sanitize_project_name(new_name);
    if name.is_empty() {
        return Err(RustpenError::ParseError(
            "copy project name contains no valid characters".to_string(),
        ));
    }
    let dst = projects_root_dir(root_ws).join(name);
    copy_dir_recursive(source_project, &dst)?;
    ensure_project_layout(&dst)?;
    Ok(dst)
}

fn rename_local_project(
    root_ws: &PathBuf,
    source_project: &PathBuf,
    new_name: &str,
) -> Result<PathBuf, RustpenError> {
    let root = projects_root_dir(root_ws);
    if !source_project.starts_with(&root) {
        return Err(RustpenError::ParseError(format!(
            "only local project can be renamed: {}",
            source_project.display()
        )));
    }
    let name = sanitize_project_name(new_name);
    if name.is_empty() {
        return Err(RustpenError::ParseError(
            "rename target name contains no valid characters".to_string(),
        ));
    }
    let dst = root.join(name);
    if same_path(&dst, source_project) {
        return Ok(source_project.clone());
    }
    if dst.exists() {
        return Err(RustpenError::ParseError(format!(
            "target project already exists: {}",
            dst.display()
        )));
    }
    fs::rename(source_project, &dst).map_err(RustpenError::Io)?;
    Ok(dst)
}

fn export_project_snapshot(
    root_ws: &PathBuf,
    source_project: &PathBuf,
) -> Result<PathBuf, RustpenError> {
    let exports_dir = root_ws.join("exports");
    fs::create_dir_all(&exports_dir).map_err(RustpenError::Io)?;
    let name = sanitize_project_name(&project_name_from_path(source_project));
    let out = exports_dir.join(format!("{}_{}", name, now_epoch_secs()));
    copy_dir_recursive(source_project, &out)?;
    Ok(out)
}

fn task_matches_result_filter(task: &TaskView, filter: ResultKindFilter) -> bool {
    match filter {
        ResultKindFilter::All => true,
        ResultKindFilter::Host => task.meta.kind == "host",
        ResultKindFilter::Web => task.meta.kind == "web",
        ResultKindFilter::Vuln => task.meta.kind == "vuln",
        ResultKindFilter::Reverse => task.meta.kind == "reverse",
        ResultKindFilter::Script => task.meta.kind == "script",
    }
}

fn result_status_rank(status: &TaskStatus) -> u8 {
    match status {
        TaskStatus::Failed => 0,
        TaskStatus::Running => 1,
        TaskStatus::Succeeded => 2,
        TaskStatus::Queued => 3,
        TaskStatus::Canceled => 4,
    }
}

fn task_matches_result_query(task: &TaskView, query: &str) -> bool {
    let q = query.trim().to_ascii_lowercase();
    if q.is_empty() {
        return true;
    }

    let meta = &task.meta;
    let mut hay = vec![
        meta.id.to_ascii_lowercase(),
        meta.kind.to_ascii_lowercase(),
        meta.status.to_string().to_ascii_lowercase(),
        meta.note.clone().unwrap_or_default().to_ascii_lowercase(),
        meta.tags.join(" ").to_ascii_lowercase(),
        meta.artifacts
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase(),
        meta.logs
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_lowercase(),
    ];
    if hay.iter().any(|h| h.contains(&q)) {
        return true;
    }

    let ev_join = load_events(&task.dir, 30)
        .into_iter()
        .map(|ev| {
            format!(
                "{} {:?} {} {}",
                ev.level,
                ev.kind,
                ev.message.unwrap_or_default(),
                ev.data.map(|v| v.to_string()).unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    hay.push(ev_join);

    let out_join = load_log_tail(&task.dir, "stdout.log", 30)
        .into_iter()
        .chain(load_log_tail(&task.dir, "stderr.log", 30))
        .collect::<Vec<_>>()
        .join("\n")
        .to_ascii_lowercase();
    hay.push(out_join);
    hay.iter().any(|h| h.contains(&q))
}

fn build_result_indices(
    all_tasks: &[TaskView],
    filter: ResultKindFilter,
    failed_first: bool,
    query: &str,
) -> Vec<usize> {
    let mut indices: Vec<usize> = all_tasks
        .iter()
        .enumerate()
        .filter_map(|(idx, t)| {
            (task_matches_result_filter(t, filter) && task_matches_result_query(t, query))
                .then_some(idx)
        })
        .collect();
    if failed_first {
        indices.sort_by(|a, b| {
            let ta = &all_tasks[*a];
            let tb = &all_tasks[*b];
            result_status_rank(&ta.meta.status)
                .cmp(&result_status_rank(&tb.meta.status))
                .then_with(|| tb.meta.created_at.cmp(&ta.meta.created_at))
        });
    }
    indices
}

fn load_events(task_dir: &PathBuf, limit: usize) -> Vec<TaskEvent> {
    let path = task_dir.join("events.jsonl");
    if !path.is_file() {
        return vec![];
    }
    let Ok(text) = fs::read_to_string(&path) else {
        return vec![];
    };
    text.lines()
        .rev()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            serde_json::from_str::<TaskEvent>(line).ok()
        })
        .take(limit)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
}

fn load_log_tail(task_dir: &PathBuf, filename: &str, limit: usize) -> Vec<String> {
    let path = task_dir.join(filename);
    if !path.is_file() {
        return Vec::new();
    }
    let Ok(text) = fs::read_to_string(&path) else {
        return Vec::new();
    };
    let mut lines: Vec<String> = text
        .lines()
        .rev()
        .take(limit)
        .map(|s| s.to_string())
        .collect();
    lines.reverse();
    lines
}

fn load_script_files(dir: &PathBuf) -> Result<Vec<PathBuf>, RustpenError> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).map_err(RustpenError::Io)? {
        let entry = entry.map_err(RustpenError::Io)?;
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        match p.extension().and_then(|s| s.to_str()) {
            Some("py") | Some("rs") => out.push(p),
            _ => {}
        }
    }
    out.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    Ok(out)
}

fn read_script_text(path: &PathBuf) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn switch_script_selection(
    new_index: usize,
    scripts: &[PathBuf],
    selected: &mut usize,
    script_buffer: &mut String,
    script_dirty: &mut bool,
    status_line: &mut String,
) {
    if scripts.is_empty() {
        *selected = 0;
        script_buffer.clear();
        *script_dirty = false;
        return;
    }
    if *script_dirty {
        *status_line = "当前脚本有未保存内容，先按 S 保存".to_string();
        return;
    }
    *selected = new_index.min(scripts.len().saturating_sub(1));
    *script_buffer = read_script_text(&scripts[*selected]);
    *script_dirty = false;
}

fn script_template_for(name: &str) -> String {
    if name.ends_with(".rs") {
        return "fn main() {\n    println!(\"hello from rscan script\");\n}\n".to_string();
    }
    "print(\"hello from rscan script\")\n".to_string()
}

fn create_script_file(dir: &PathBuf, name: &str) -> Result<PathBuf, RustpenError> {
    let mut final_name = name.trim().to_string();
    if !final_name.ends_with(".py") && !final_name.ends_with(".rs") {
        final_name.push_str(".py");
    }
    let path = dir.join(final_name.clone());
    if path.exists() {
        return Err(RustpenError::ParseError(format!(
            "script already exists: {}",
            path.display()
        )));
    }
    fs::write(&path, script_template_for(&final_name)).map_err(RustpenError::Io)?;
    Ok(path)
}

fn save_current_script(
    scripts: &[PathBuf],
    script_selected: usize,
    script_buffer: &str,
) -> Result<String, RustpenError> {
    let Some(path) = scripts.get(script_selected) else {
        return Err(RustpenError::MissingArgument {
            arg: "script file".to_string(),
        });
    };
    fs::write(path, script_buffer).map_err(RustpenError::Io)?;
    Ok(format!("saved: {}", path.display()))
}

fn start_script_runner(path: PathBuf) -> Receiver<ScriptRunResult> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let result = run_script_once(path);
        let _ = tx.send(result);
    });
    rx
}

fn run_script_once(path: PathBuf) -> ScriptRunResult {
    let ext = path
        .extension()
        .and_then(|s| s.to_str())
        .unwrap_or_default();
    match ext {
        "py" => run_process(path.clone(), "python3", vec![path.display().to_string()]),
        "rs" => run_rust_script(path),
        _ => ScriptRunResult {
            file: path,
            ok: false,
            exit_code: None,
            stdout: String::new(),
            stderr: "unsupported script extension".to_string(),
        },
    }
}

fn run_rust_script(path: PathBuf) -> ScriptRunResult {
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("script")
        .replace([' ', '/'], "_");
    let bin = std::env::temp_dir().join(format!("rscan_script_{}_{}", stem, now_epoch_secs()));

    let compile = Command::new("rustc")
        .arg(&path)
        .arg("-O")
        .arg("-o")
        .arg(&bin)
        .output();

    let Ok(compile_out) = compile else {
        return ScriptRunResult {
            file: path,
            ok: false,
            exit_code: None,
            stdout: String::new(),
            stderr: "failed to launch rustc".to_string(),
        };
    };

    if !compile_out.status.success() {
        return ScriptRunResult {
            file: path,
            ok: false,
            exit_code: compile_out.status.code(),
            stdout: String::from_utf8_lossy(&compile_out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&compile_out.stderr).to_string(),
        };
    }

    let run = Command::new(&bin).output();
    let _ = fs::remove_file(&bin);
    match run {
        Ok(out) => ScriptRunResult {
            file: path,
            ok: out.status.success(),
            exit_code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        },
        Err(e) => ScriptRunResult {
            file: path,
            ok: false,
            exit_code: None,
            stdout: String::new(),
            stderr: e.to_string(),
        },
    }
}

fn run_process(path: PathBuf, cmd: &str, args: Vec<String>) -> ScriptRunResult {
    match Command::new(cmd).args(args).output() {
        Ok(out) => ScriptRunResult {
            file: path,
            ok: out.status.success(),
            exit_code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).to_string(),
            stderr: String::from_utf8_lossy(&out.stderr).to_string(),
        },
        Err(e) => ScriptRunResult {
            file: path,
            ok: false,
            exit_code: None,
            stdout: String::new(),
            stderr: format!("failed to start '{}': {}", cmd, e),
        },
    }
}

fn poll_script_runner(rx: &mut Option<Receiver<ScriptRunResult>>) -> Option<ScriptRunResult> {
    let Some(r) = rx else {
        return None;
    };
    match r.try_recv() {
        Ok(done) => {
            *rx = None;
            Some(done)
        }
        Err(TryRecvError::Empty) => None,
        Err(TryRecvError::Disconnected) => {
            *rx = None;
            None
        }
    }
}

fn start_script_task(
    workspace: &PathBuf,
    script_file: &PathBuf,
) -> Result<ScriptTaskCtx, RustpenError> {
    let task_id = new_task_id();
    let dir = ensure_task_dir(workspace, &task_id)?;
    let now = now_epoch_secs();
    let meta = TaskMeta {
        id: task_id,
        kind: "script".to_string(),
        tags: vec![script_file.display().to_string()],
        status: TaskStatus::Running,
        created_at: now,
        started_at: Some(now),
        ended_at: None,
        progress: Some(0.0),
        note: Some("script run".to_string()),
        artifacts: vec![script_file.clone()],
        logs: Vec::new(),
        extra: None,
    };
    write_task_meta(&dir, &meta)?;
    let _ = append_task_event(
        &dir,
        &TaskEvent {
            ts: now,
            level: "info".to_string(),
            kind: EventKind::Log,
            message: Some(format!("script start: {}", script_file.display())),
            data: None,
        },
    );
    Ok(ScriptTaskCtx { dir, meta })
}

fn finalize_script_task(
    task: &mut Option<ScriptTaskCtx>,
    done: &ScriptRunResult,
) -> Result<(), RustpenError> {
    let Some(mut ctx) = task.take() else {
        return Ok(());
    };

    let stdout_path = ctx.dir.join("stdout.log");
    let stderr_path = ctx.dir.join("stderr.log");
    fs::write(&stdout_path, &done.stdout).map_err(RustpenError::Io)?;
    fs::write(&stderr_path, &done.stderr).map_err(RustpenError::Io)?;

    ctx.meta.status = if done.ok {
        TaskStatus::Succeeded
    } else {
        TaskStatus::Failed
    };
    ctx.meta.ended_at = Some(now_epoch_secs());
    ctx.meta.progress = Some(100.0);
    ctx.meta.logs = vec![stdout_path.clone(), stderr_path.clone()];
    if !ctx.meta.artifacts.iter().any(|p| p == &done.file) {
        ctx.meta.artifacts.push(done.file.clone());
    }

    write_task_meta(&ctx.dir, &ctx.meta)?;
    let _ = append_task_event(
        &ctx.dir,
        &TaskEvent {
            ts: now_epoch_secs(),
            level: if done.ok { "info" } else { "error" }.to_string(),
            kind: EventKind::Control,
            message: Some(format!(
                "script finished: ok={} exit_code={}",
                done.ok,
                done.exit_code
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "none".to_string())
            )),
            data: None,
        },
    );
    Ok(())
}

fn append_output_block(
    output: &mut Vec<String>,
    out_header: &str,
    out_body: &str,
    err_header: &str,
    err_body: &str,
) {
    output.push(format!("{}", out_header));
    if out_body.trim().is_empty() {
        output.push("<empty>".to_string());
    } else {
        output.extend(out_body.lines().map(|s| s.to_string()));
    }
    output.push(format!("{}", err_header));
    if err_body.trim().is_empty() {
        output.push("<empty>".to_string());
    } else {
        output.extend(err_body.lines().map(|s| s.to_string()));
    }

    const MAX_LINES: usize = 600;
    if output.len() > MAX_LINES {
        let drop_n = output.len() - MAX_LINES;
        output.drain(0..drop_n);
    }
}

fn execute_short_command(workspace: &PathBuf, cmd: &str) -> String {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return "空命令".to_string();
    }
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    let head = parts.first().copied().unwrap_or("");
    let mut args: Vec<String> = Vec::new();
    let task_id = new_task_id();

    match head {
        "h.quick" => {
            if parts.len() < 2 {
                return "用法: h.quick <host>".to_string();
            }
            args.extend([
                "host".to_string(),
                "quick".to_string(),
                "--host".to_string(),
                parts[1].to_string(),
            ]);
        }
        "h.tcp" => {
            if parts.len() < 3 {
                return "用法: h.tcp <host> <ports>".to_string();
            }
            args.extend([
                "host".to_string(),
                "tcp".to_string(),
                "--host".to_string(),
                parts[1].to_string(),
                "--ports".to_string(),
                parts[2].to_string(),
            ]);
        }
        "w.dir" => {
            if parts.len() < 3 {
                return "用法: w.dir <base> <paths_csv>".to_string();
            }
            args.extend([
                "web".to_string(),
                "dir".to_string(),
                "--base".to_string(),
                parts[1].to_string(),
            ]);
            for p in parts[2].split(',') {
                args.push("--paths".into());
                args.push(p.to_string());
            }
        }
        "w.fuzz" => {
            if parts.len() < 3 {
                return "用法: w.fuzz <url_with_FUZZ> <keywords_csv>".to_string();
            }
            args.extend([
                "web".to_string(),
                "fuzz".to_string(),
                "--url".to_string(),
                parts[1].to_string(),
            ]);
            for kw in parts[2].split(',') {
                args.push("--keywords".into());
                args.push(kw.to_string());
            }
        }
        "w.dns" => {
            if parts.len() < 3 {
                return "用法: w.dns <domain> <words_csv>".to_string();
            }
            args.extend([
                "web".to_string(),
                "dns".to_string(),
                "--domain".to_string(),
                parts[1].to_string(),
            ]);
            for w in parts[2].split(',') {
                args.push("--words".into());
                args.push(w.to_string());
            }
        }
        "v.scan" => {
            if parts.len() < 2 {
                return "用法: v.scan <target_url> [templates_dir]".to_string();
            }
            let templates = if parts.len() >= 3 {
                PathBuf::from(parts[2])
            } else {
                match ensure_builtin_vuln_templates(workspace) {
                    Ok(p) => p,
                    Err(e) => return format!("准备漏洞模板失败: {}", e),
                }
            };
            if !templates.exists() {
                return format!("模板目录不存在: {}", templates.display());
            }
            args.extend([
                "vuln".to_string(),
                "scan".to_string(),
                "--targets".to_string(),
                parts[1].to_string(),
                "--templates".to_string(),
                templates.display().to_string(),
            ]);
        }
        "r.analyze" => {
            if parts.len() < 2 {
                return "用法: r.analyze <input_file>".to_string();
            }
            args.extend([
                "reverse".to_string(),
                "analyze".to_string(),
                "--input".to_string(),
                parts[1].to_string(),
            ]);
        }
        "r.plan" => {
            if parts.len() < 2 {
                return "用法: r.plan <input_file> [engine]".to_string();
            }
            let engine = parts.get(2).copied().unwrap_or("objdump");
            let engine_ok = matches!(
                engine.to_ascii_lowercase().as_str(),
                "objdump" | "radare2" | "r2" | "ghidra" | "ida" | "idat64" | "jadx"
            );
            if !engine_ok {
                return format!(
                    "engine 不支持: {}，可选 objdump|radare2|ghidra|ida|jadx",
                    engine
                );
            }
            args.extend([
                "reverse".to_string(),
                "decompile-plan".to_string(),
                "--input".to_string(),
                parts[1].to_string(),
                "--engine".to_string(),
                engine.to_string(),
            ]);
        }
        _ => return format!("未知命令: {head}"),
    }

    args.push("--task-workspace".into());
    args.push(workspace.display().to_string());
    args.push("--task-id".into());
    args.push(task_id.clone());

    let task_dir = workspace.join("tasks").join(&task_id);
    if let Err(e) = fs::create_dir_all(&task_dir) {
        return format!("启动失败: 创建任务目录失败: {}", e);
    }
    let stdout_path = task_dir.join("stdout.log");
    let stderr_path = task_dir.join("stderr.log");
    let stdout_file = match fs::File::create(&stdout_path) {
        Ok(f) => f,
        Err(e) => return format!("启动失败: 创建 stdout.log 失败: {}", e),
    };
    let stderr_file = match fs::File::create(&stderr_path) {
        Ok(f) => f,
        Err(e) => return format!("启动失败: 创建 stderr.log 失败: {}", e),
    };

    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("rscan"));
    let spawn_res = Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .spawn();
    match spawn_res {
        Ok(_) => format!(
            "launching {head} task_id={task_id} (logs: {}/stdout.log)",
            task_dir.display()
        ),
        Err(e) => format!("启动失败: {e}"),
    }
}

fn ensure_builtin_vuln_templates(workspace: &PathBuf) -> Result<PathBuf, RustpenError> {
    let dir = workspace.join("vuln_templates");
    fs::create_dir_all(&dir).map_err(RustpenError::Io)?;
    let tpl_path = dir.join("basic_http.yaml");
    if !tpl_path.exists() {
        let content = r#"id: rscan-basic-http
info:
  name: Basic HTTP Status Probe
  severity: info
  tags: [default, health]
http:
  - method: GET
    path:
      - /
      - /robots.txt
    matchers:
      - type: status
        status: [200, 204, 301, 302, 401, 403]
"#;
        fs::write(&tpl_path, content).map_err(RustpenError::Io)?;
    }
    Ok(dir)
}

fn mini_console_dock_rect(
    area: Rect,
    dock_right: bool,
    width_pct: u16,
    preferred_height: u16,
    min_width: u16,
    min_height: u16,
) -> Rect {
    if area.width == 0 || area.height == 0 {
        return area;
    }
    let mut width = ((area.width as u32 * width_pct as u32) / 100) as u16;
    width = width.max(min_width).min(area.width);
    let mut height = preferred_height.max(min_height);
    height = height.min(area.height);
    let x = if dock_right {
        area.x + area.width.saturating_sub(width)
    } else {
        area.x
    };
    let y = area.y + area.height.saturating_sub(height);
    Rect {
        x,
        y,
        width,
        height,
    }
}

fn mini_console_rect_for_layout(
    area: Rect,
    layout: MiniConsoleLayout,
    float_x_pct: u16,
    float_y_pct: u16,
    float_w_pct: u16,
    float_h_pct: u16,
) -> Rect {
    match layout {
        MiniConsoleLayout::DockRightBottom => mini_console_dock_rect(area, true, 48, 11, 36, 8),
        MiniConsoleLayout::DockLeftBottom => mini_console_dock_rect(area, false, 48, 11, 36, 8),
        MiniConsoleLayout::Floating => {
            if area.width == 0 || area.height == 0 {
                return area;
            }
            let mut width = ((area.width as u32 * float_w_pct as u32) / 100) as u16;
            width = width.max(30).min(area.width);
            let mut height = ((area.height as u32 * float_h_pct as u32) / 100) as u16;
            height = height.max(8).min(area.height);

            let max_x = area.width.saturating_sub(width);
            let max_y = area.height.saturating_sub(height);
            let x_off = ((max_x as u32 * float_x_pct.min(100) as u32) / 100) as u16;
            let y_off = ((max_y as u32 * float_y_pct.min(100) as u32) / 100) as u16;

            Rect {
                x: area.x + x_off,
                y: area.y + y_off,
                width,
                height,
            }
        }
    }
}

fn append_mini_terminal_line(lines: &mut Vec<String>, line: String) {
    lines.push(line);
    const MAX_LINES: usize = 500;
    if lines.len() > MAX_LINES {
        let drop_n = lines.len() - MAX_LINES;
        lines.drain(0..drop_n);
    }
}

fn build_mini_console_lines(
    tab: MiniConsoleTab,
    pane: MainPane,
    all_tasks: &[TaskView],
    tasks: &[TaskView],
    task_selected: usize,
    result_indices: &[usize],
    result_selected: usize,
    script_output: &[String],
    mini_terminal_lines: &[String],
    status_line: &str,
) -> Vec<Line<'static>> {
    let mut out = vec![line_s(&format!(
        "pane={} | tab={} | status={}",
        pane.label(),
        match tab {
            MiniConsoleTab::Output => "Output",
            MiniConsoleTab::Terminal => "Terminal",
            MiniConsoleTab::Problems => "Problems",
        },
        status_line
    ))];
    out.push(line_s(
        "controls: v=toggle b=layout z=dock p=popup 0=reset [/]=tab j/k=scroll",
    ));
    out.push(line_s("floating: Ctrl+Arrows=move Alt+Arrows=resize"));
    out.push(line_s(""));

    if tab == MiniConsoleTab::Terminal {
        out.push(line_s("integrated terminal stream:"));
        if mini_terminal_lines.is_empty() {
            out.push(line_s("- <empty>"));
        } else {
            for line in mini_terminal_lines.iter().rev().take(12).rev() {
                out.push(line_s(line));
            }
        }
        return out;
    }

    if pane == MainPane::Scripts {
        if tab == MiniConsoleTab::Problems {
            out.push(line_s("script problems:"));
            let err_lines = script_output
                .iter()
                .filter(|l| {
                    let low = l.to_ascii_lowercase();
                    low.contains("error")
                        || low.contains("failed")
                        || low.contains("panic")
                        || low.contains("traceback")
                        || low.contains("[script] stderr")
                })
                .take(10)
                .cloned()
                .collect::<Vec<_>>();
            if err_lines.is_empty() {
                out.push(line_s("- <no problem lines>"));
            } else {
                for line in err_lines {
                    out.push(line_s(&line));
                }
            }
        } else {
            out.push(line_s("script output tail:"));
            if script_output.is_empty() {
                out.push(line_s("- <empty>"));
            } else {
                for line in script_output.iter().rev().take(8).rev() {
                    out.push(line_s(line));
                }
            }
        }
        return out;
    }

    let selected_task = if pane == MainPane::Results {
        result_indices
            .get(result_selected)
            .and_then(|idx| all_tasks.get(*idx))
    } else {
        tasks.get(task_selected).or_else(|| all_tasks.first())
    };

    let Some(task) = selected_task else {
        out.push(line_s("<no task selected>"));
        return out;
    };

    out.push(line_s(&format!(
        "task={} kind={} status={}",
        task.meta.id, task.meta.kind, task.meta.status
    )));
    if tab == MiniConsoleTab::Problems {
        out.push(line_s("problems (failed tasks):"));
        let failed = all_tasks
            .iter()
            .filter(|t| t.meta.status == TaskStatus::Failed)
            .take(8)
            .collect::<Vec<_>>();
        if failed.is_empty() {
            out.push(line_s("- <no failed tasks>"));
        } else {
            for t in failed {
                out.push(line_s(&format!("- [{}] {}", t.meta.kind, t.meta.id)));
            }
        }
        out.push(line_s(""));
        out.push(line_s("selected task problem lines:"));
        let events = load_events(&task.dir, 16);
        let mut has_problem = false;
        for ev in events {
            let low = ev.level.to_ascii_lowercase();
            if low.contains("error") || low.contains("warn") {
                out.push(line_s(&format!(
                    "- [{}] {}",
                    ev.level,
                    ev.message.unwrap_or_default()
                )));
                has_problem = true;
            }
        }
        for line in load_log_tail(&task.dir, "stderr.log", 8) {
            if !line.trim().is_empty() {
                out.push(line_s(&format!("err> {}", line)));
                has_problem = true;
            }
        }
        if !has_problem {
            out.push(line_s("- <no explicit problem line>"));
        }
        return out;
    }

    out.push(line_s("events:"));
    let events = load_events(&task.dir, 4);
    if events.is_empty() {
        out.push(line_s("- <empty>"));
    } else {
        for ev in events {
            out.push(line_s(&format!(
                "- [{}] {}",
                ev.level,
                ev.message.unwrap_or_default()
            )));
        }
    }
    out.push(line_s("stdout/stderr:"));
    let stdout = load_log_tail(&task.dir, "stdout.log", 2);
    let stderr = load_log_tail(&task.dir, "stderr.log", 2);
    if stdout.is_empty() && stderr.is_empty() {
        out.push(line_s("- <empty>"));
    } else {
        for line in stdout {
            out.push(line_s(&format!("out> {}", line)));
        }
        for line in stderr {
            out.push(line_s(&format!("err> {}", line)));
        }
    }
    out
}

fn build_dashboard_lines(tasks: &[TaskView]) -> Vec<Line<'static>> {
    use std::collections::BTreeMap;

    let total = tasks.len();
    let running = tasks
        .iter()
        .filter(|t| t.meta.status == TaskStatus::Running)
        .count();
    let failed = tasks
        .iter()
        .filter(|t| t.meta.status == TaskStatus::Failed)
        .count();
    let succeeded = tasks
        .iter()
        .filter(|t| t.meta.status == TaskStatus::Succeeded)
        .count();

    let mut kinds: BTreeMap<String, usize> = BTreeMap::new();
    for t in tasks {
        *kinds.entry(t.meta.kind.clone()).or_insert(0) += 1;
    }

    let mut out = vec![
        line_s("rscan 统一终端界面（阶段1）"),
        line_s("- 保留 CLI，不改变已有命令行为"),
        line_s("- 多面板：Dashboard / Tasks / Launcher / Scripts / Results / Projects"),
        line_s("- Projects 支持新建/删除/导入/切换"),
        line_s(""),
        line_s(&format!(
            "Tasks: total={} running={} succeeded={} failed={}",
            total, running, succeeded, failed
        )),
        line_s(""),
        line_s("Kinds:"),
    ];

    if kinds.is_empty() {
        out.push(line_s("- <none>"));
    } else {
        for (k, v) in kinds {
            out.push(line_s(&format!("- {}: {}", k, v)));
        }
    }

    out.push(line_s(""));
    out.push(line_s("Recent tasks:"));
    for t in tasks.iter().take(12) {
        out.push(line_s(&format!(
            "- {} [{}] {}",
            t.meta.id, t.meta.kind, t.meta.status
        )));
    }

    out
}

fn build_overview_lines(cur: &TaskView) -> Vec<Line<'static>> {
    let meta = &cur.meta;
    let mut lines = vec![
        format!("id: {}", meta.id),
        format!("kind: {}", meta.kind),
        format!("status: {}", meta.status),
        format!("created_at: {}", meta.created_at),
        format!(
            "started_at: {}",
            meta.started_at
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into())
        ),
        format!(
            "ended_at: {}",
            meta.ended_at
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".into())
        ),
        format!(
            "progress: {}",
            meta.progress
                .map(|v| format!("{:.1}%", v))
                .unwrap_or_else(|| "-".into())
        ),
        format!("tags: {}", meta.tags.join(",")),
    ];
    if let Some(note) = &meta.note {
        lines.push(format!("note: {}", note));
    }
    if !meta.artifacts.is_empty() {
        lines.push(format!(
            "artifacts: {}",
            meta.artifacts
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !meta.logs.is_empty() {
        lines.push(format!(
            "logs: {}",
            meta.logs
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    lines.into_iter().map(|s| line_s(&s)).collect()
}

fn build_event_lines(task_dir: &PathBuf, limit: usize) -> Vec<Line<'static>> {
    let events = load_events(task_dir, limit);
    if events.is_empty() {
        return vec![line_s("<no events>")];
    }
    events
        .into_iter()
        .map(|ev| {
            let level_style = match ev.level.to_ascii_lowercase().as_str() {
                "warn" => Style::default().fg(Color::Yellow),
                "error" => Style::default().fg(Color::Red),
                "debug" => Style::default().fg(Color::Blue),
                _ => Style::default(),
            };
            let kind_style = match ev.kind {
                EventKind::Progress => Style::default().fg(Color::Cyan),
                EventKind::Metric => Style::default().fg(Color::Green),
                EventKind::Control => Style::default().fg(Color::Magenta),
                EventKind::Log => Style::default(),
            };
            let msg = ev.message.unwrap_or_default();
            let data_snip = ev
                .data
                .as_ref()
                .map(|d| format!(" {}", d))
                .unwrap_or_default();
            Line::from(vec![
                Span::raw(format!("{} ", ev.ts)),
                Span::styled(ev.level, level_style),
                Span::raw(" "),
                Span::styled(format!("{:?}", ev.kind).to_lowercase(), kind_style),
                Span::raw(" "),
                Span::raw(msg),
                Span::raw(data_snip),
            ])
        })
        .collect()
}

fn build_logs_lines(task_dir: &PathBuf, limit: usize) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    out.push(line_s("---- stdout.log ----"));
    let stdout = load_log_tail(task_dir, "stdout.log", limit);
    if stdout.is_empty() {
        out.push(line_s("<empty>"));
    } else {
        out.extend(stdout.into_iter().map(|s| line_s(&s)));
    }
    out.push(line_s("---- stderr.log ----"));
    let stderr = load_log_tail(task_dir, "stderr.log", limit);
    if stderr.is_empty() {
        out.push(line_s("<empty>"));
    } else {
        out.extend(stderr.into_iter().map(|s| line_s(&s)));
    }
    out
}

fn build_effect_lines(cur: &TaskView) -> Vec<Line<'static>> {
    let mut out = vec![
        line_s(&format!("task: {}", cur.meta.id)),
        line_s(&format!("module: {}", cur.meta.kind)),
        line_s(&format!("status: {}", cur.meta.status)),
        line_s(&format!(
            "progress: {}",
            cur.meta
                .progress
                .map(|p| format!("{:.1}%", p))
                .unwrap_or_else(|| "-".to_string())
        )),
        line_s(""),
        line_s("recent events:"),
    ];

    let events = load_events(&cur.dir, 20);
    if events.is_empty() {
        out.push(line_s("- <no events>"));
    } else {
        for ev in events {
            out.push(line_s(&format!(
                "- [{}][{:?}] {}",
                ev.level,
                ev.kind,
                ev.message.unwrap_or_default()
            )));
        }
    }

    out.push(line_s(""));
    out.push(line_s("stdout tail:"));
    let stdout = load_log_tail(&cur.dir, "stdout.log", 20);
    if stdout.is_empty() {
        out.push(line_s("- <empty>"));
    } else {
        for line in stdout {
            out.push(line_s(&line));
        }
    }

    out.push(line_s(""));
    out.push(line_s("stderr tail:"));
    let stderr = load_log_tail(&cur.dir, "stderr.log", 20);
    if stderr.is_empty() {
        out.push(line_s("- <empty>"));
    } else {
        for line in stderr {
            out.push(line_s(&line));
        }
    }

    out
}

fn build_notes_lines(cur: &TaskView, buffer: &str, mode: InputMode) -> Vec<Line<'static>> {
    let mut out = Vec::new();
    out.push(line_s("Notes"));
    if let Some(note) = &cur.meta.note {
        for l in note.lines() {
            out.push(line_s(&format!("- {}", l)));
        }
    } else {
        out.push(line_s("<no note>"));
    }
    out.push(line_s(" "));
    match mode {
        InputMode::Normal => {
            out.push(line_s("按 n 进入记事模式，Enter 保存，Esc 取消"));
        }
        InputMode::NoteInput => {
            out.push(Line::from(vec![
                Span::raw("输入: "),
                Span::styled(buffer.to_string(), Style::default().fg(Color::Yellow)),
                Span::raw(" ▌"),
            ]));
        }
        _ => {
            out.push(line_s("当前不是记事模式"));
        }
    }
    out
}

fn task_tab_label(tab: TaskTab) -> &'static str {
    match tab {
        TaskTab::Overview => "overview",
        TaskTab::Events => "events",
        TaskTab::Logs => "logs",
        TaskTab::Notes => "notes",
    }
}

fn apply_filter(all: &[TaskView], filter: StatusFilter) -> Vec<TaskView> {
    all.iter()
        .filter(|t| match filter {
            StatusFilter::All => true,
            StatusFilter::Running => t.meta.status == TaskStatus::Running,
            StatusFilter::Failed => t.meta.status == TaskStatus::Failed,
            StatusFilter::Succeeded => t.meta.status == TaskStatus::Succeeded,
        })
        .cloned()
        .collect()
}

fn line_s(s: &str) -> Line<'static> {
    Line::from(Span::raw(s.to_string()))
}
