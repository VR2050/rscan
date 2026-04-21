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
    terminal_screen_lines: &[Line<'static>],
    zellij_managed: bool,
    zellij_session: Option<&str>,
    zellij_tabs: &[&str],
) -> Vec<Line<'static>> {
    let terminal_label = if zellij_managed { "Zellij" } else { "Terminal" };
    let mut out = vec![line_s(&format!(
        "pane={} | tab={}",
        pane.label(),
        match tab {
            MiniConsoleTab::Output => "Output",
            MiniConsoleTab::Terminal => terminal_label,
            MiniConsoleTab::Problems => "Problems",
        },
    ))];
    out.push(line_s(
        "mini: v=toggle  [/] tab  j/k=scroll  b/z/p/0=layout",
    ));
    out.push(line_s(""));

    if tab == MiniConsoleTab::Terminal {
        if zellij_managed {
            out.push(line_s("zellij runtime: compact view"));
            if let Some(session) = zellij_session {
                out.push(line_s(&format!("session={session}")));
            }
            out.push(line_s(&format!("managed tabs={}", zellij_tabs.join(" | "))));
            out.push(line_s(
                "ops: g=control-shell  zrun=<work pane>  L/W/A=<native panes>",
            ));
            out.push(line_s(
                "tip: zellij Normal mode may swallow keys; Ctrl-g -> Locked",
            ));
            out.push(line_s(""));
            out.push(line_s("recent control log:"));
            if mini_terminal_lines.is_empty() {
                out.push(line_s("- <empty>"));
            } else {
                for line in mini_terminal_lines.iter().rev().take(12).rev() {
                    out.push(line_s(line));
                }
            }
            return out;
        }
        out.push(line_s("integrated terminal stream:"));
        out.push(line_s(
            "press g to enter terminal input, Esc/Ctrl+g to exit",
        ));
        if terminal_screen_lines.is_empty() {
            out.push(line_s("- <empty>"));
        } else {
            for line in terminal_screen_lines {
                out.push(line.clone());
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
            out.push(line_s("scripts pane summary:"));
            out.push(line_s("- 主面板已显示 Run Log (tail)，这里不重复展开日志"));
            out.push(line_s("- I/H 打开 Helix，R 运行脚本"));
            let last = script_output
                .iter()
                .rev()
                .find(|line| !line.trim().is_empty())
                .cloned()
                .unwrap_or_else(|| "<no status yet>".to_string());
            out.push(line_s(&format!("- last: {}", last)));
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

    out.push(line_s("quick status (full detail in main pane):"));
    out.push(line_s(&format!(
        "- progress={}",
        task.meta
            .progress
            .map(|v| format!("{v:.0}%"))
            .unwrap_or_else(|| "-".to_string())
    )));
    let latest_event = load_events(&task.dir, 1);
    if let Some(ev) = latest_event.first() {
        out.push(line_s(&format!(
            "- last-event [{}] {}",
            ev.level,
            ev.message.clone().unwrap_or_default()
        )));
    } else {
        out.push(line_s("- last-event <empty>"));
    }
    let stderr = load_log_tail(&task.dir, "stderr.log", 1);
    if let Some(line) = stderr.first() {
        out.push(line_s(&format!("- last-err {}", line)));
    } else {
        out.push(line_s("- last-err <empty>"));
    }
    out.push(line_s("- 详细事件/日志请看主面板；Problems tab 只看异常"));
    out
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cores::engine::task::{TaskMeta, TaskStatus};
    use crate::tui::models::TaskOrigin;

    fn make_task(
        base_name: &str,
        kind: &str,
        artifact_body: &str,
    ) -> (std::path::PathBuf, TaskView) {
        let base = std::env::temp_dir().join(format!(
            "rscan_mini_console_{base_name}_{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let task_dir = base.join("tasks").join(format!("task-{kind}"));
        std::fs::create_dir_all(&task_dir).unwrap();
        let artifact = task_dir.join(format!("{kind}-result.txt"));
        std::fs::write(&artifact, artifact_body).unwrap();
        let task = TaskView {
            meta: TaskMeta {
                id: format!("task-{kind}"),
                kind: kind.to_string(),
                tags: vec!["127.0.0.1".to_string()],
                status: TaskStatus::Succeeded,
                created_at: 1,
                started_at: Some(1),
                ended_at: Some(2),
                progress: Some(100.0),
                note: None,
                artifacts: vec![artifact],
                logs: vec![task_dir.join("stdout.log"), task_dir.join("stderr.log")],
                extra: None,
            },
            dir: task_dir,
            origin: TaskOrigin::Task,
        };
        (base, task)
    }

    #[test]
    fn mini_console_output_is_compact_without_artifact_snippet_duplication() {
        let (base, task) = make_task(
            "artifact_snippet",
            "host",
            "host=127.0.0.1 open=2\n22 tcp ssh\n80 tcp http\n",
        );

        let lines = build_mini_console_lines(
            MiniConsoleTab::Output,
            MainPane::Tasks,
            std::slice::from_ref(&task),
            std::slice::from_ref(&task),
            0,
            &[],
            0,
            &[],
            &[],
            &[],
            false,
            None,
            &[],
        );
        let rendered = lines
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("quick status (full detail in main pane):"));
        assert!(rendered.contains("last-event <empty>"));
        assert!(rendered.contains("last-err <empty>"));
        assert!(!rendered.contains("art> [host-result.txt]"));

        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn mini_console_problems_lists_failed_task_and_stderr() {
        let (base, mut task) = make_task("problems", "web", "OK 200 https://example.com/\n");
        task.meta.status = TaskStatus::Failed;
        std::fs::write(task.dir.join("stderr.log"), "network timeout\n").unwrap();

        let lines = build_mini_console_lines(
            MiniConsoleTab::Problems,
            MainPane::Tasks,
            std::slice::from_ref(&task),
            std::slice::from_ref(&task),
            0,
            &[],
            0,
            &[],
            &[],
            &[],
            false,
            None,
            &[],
        );
        let rendered = lines
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(rendered.contains("[web] task-web"));
        assert!(rendered.contains("network timeout"));

        let _ = std::fs::remove_dir_all(base);
    }
}
