use std::path::PathBuf;

use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};

use crate::cores::engine::task::{EventKind, TaskStatus};

use super::models::{InputMode, MainPane, MiniConsoleLayout, MiniConsoleTab, TaskTab, TaskView};
use super::task_store::{load_events, load_log_tail};

pub(crate) fn mini_console_dock_rect(
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

pub(crate) fn mini_console_rect_for_layout(
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

pub(crate) fn append_mini_terminal_line(lines: &mut Vec<String>, line: String) {
    lines.push(line);
    const MAX_LINES: usize = 500;
    if lines.len() > MAX_LINES {
        let drop_n = lines.len() - MAX_LINES;
        lines.drain(0..drop_n);
    }
}

pub(crate) fn build_mini_console_lines(
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

pub(crate) fn build_dashboard_lines(tasks: &[TaskView]) -> Vec<Line<'static>> {
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

pub(crate) fn build_overview_lines(cur: &TaskView) -> Vec<Line<'static>> {
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

pub(crate) fn build_event_lines(task_dir: &PathBuf, limit: usize) -> Vec<Line<'static>> {
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

pub(crate) fn build_logs_lines(task_dir: &PathBuf, limit: usize) -> Vec<Line<'static>> {
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

pub(crate) fn build_effect_lines(cur: &TaskView) -> Vec<Line<'static>> {
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

pub(crate) fn build_notes_lines(
    cur: &TaskView,
    buffer: &str,
    mode: InputMode,
) -> Vec<Line<'static>> {
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

pub(crate) fn task_tab_label(tab: TaskTab) -> &'static str {
    match tab {
        TaskTab::Overview => "overview",
        TaskTab::Events => "events",
        TaskTab::Logs => "logs",
        TaskTab::Notes => "notes",
    }
}

pub(crate) fn line_s(s: &str) -> Line<'static> {
    Line::from(Span::raw(s.to_string()))
}
