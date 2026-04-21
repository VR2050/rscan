use std::path::PathBuf;

use crate::cores::engine::task::{TaskMeta, TaskRuntimeBinding, task_runtime_binding_from_extra};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum TaskOrigin {
    Task,
    ReverseJob,
}

#[derive(Clone)]
pub(crate) struct TaskView {
    pub(crate) meta: TaskMeta,
    pub(crate) dir: PathBuf,
    pub(crate) origin: TaskOrigin,
}

impl TaskView {
    pub(crate) fn origin_label(&self) -> &'static str {
        match self.origin {
            TaskOrigin::Task => "task",
            TaskOrigin::ReverseJob => "reverse-job",
        }
    }

    pub(crate) fn workspace_root(&self) -> Option<PathBuf> {
        self.dir.parent()?.parent().map(|p| p.to_path_buf())
    }

    pub(crate) fn runtime_binding(&self) -> Option<TaskRuntimeBinding> {
        task_runtime_binding_from_extra(&self.meta.extra)
    }
}

#[derive(Clone)]
pub(crate) struct ProjectEntry {
    pub(crate) name: String,
    pub(crate) path: PathBuf,
    pub(crate) imported: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum StatusFilter {
    All,
    Running,
    Failed,
    Succeeded,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ResultKindFilter {
    All,
    Host,
    Web,
    Vuln,
    Reverse,
    Script,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ProjectTemplate {
    Minimal,
    Recon,
    Reverse,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum MiniConsoleLayout {
    DockRightBottom,
    DockLeftBottom,
    Floating,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum MiniConsoleTab {
    Output,
    Terminal,
    Problems,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum TaskTab {
    Overview,
    Events,
    Logs,
    Notes,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum MainPane {
    Dashboard,
    Tasks,
    Launcher,
    Scripts,
    Results,
    Projects,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum MainLayout {
    Single,
    SplitLeftTasks,
    TriPanel,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum InputMode {
    Normal,
    NoteInput,
    CommandInput,
    TerminalInput,
    ScriptNewInput,
    ProjectNewInput,
    ProjectImportInput,
    ProjectCopyInput,
    ProjectRenameInput,
    ResultSearchInput,
}

impl StatusFilter {
    pub(crate) fn next(self) -> Self {
        match self {
            StatusFilter::All => StatusFilter::Running,
            StatusFilter::Running => StatusFilter::Failed,
            StatusFilter::Failed => StatusFilter::Succeeded,
            StatusFilter::Succeeded => StatusFilter::All,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            StatusFilter::All => "all",
            StatusFilter::Running => "running",
            StatusFilter::Failed => "failed",
            StatusFilter::Succeeded => "succeeded",
        }
    }
}

impl ResultKindFilter {
    pub(crate) fn next(self) -> Self {
        match self {
            ResultKindFilter::All => ResultKindFilter::Host,
            ResultKindFilter::Host => ResultKindFilter::Web,
            ResultKindFilter::Web => ResultKindFilter::Vuln,
            ResultKindFilter::Vuln => ResultKindFilter::Reverse,
            ResultKindFilter::Reverse => ResultKindFilter::Script,
            ResultKindFilter::Script => ResultKindFilter::All,
        }
    }

    pub(crate) fn label(self) -> &'static str {
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
    pub(crate) fn next(self) -> Self {
        match self {
            ProjectTemplate::Minimal => ProjectTemplate::Recon,
            ProjectTemplate::Recon => ProjectTemplate::Reverse,
            ProjectTemplate::Reverse => ProjectTemplate::Minimal,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            ProjectTemplate::Minimal => "minimal",
            ProjectTemplate::Recon => "recon",
            ProjectTemplate::Reverse => "reverse",
        }
    }
}

impl MiniConsoleLayout {
    pub(crate) fn next(self) -> Self {
        match self {
            MiniConsoleLayout::DockRightBottom => MiniConsoleLayout::DockLeftBottom,
            MiniConsoleLayout::DockLeftBottom => MiniConsoleLayout::Floating,
            MiniConsoleLayout::Floating => MiniConsoleLayout::DockRightBottom,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            MiniConsoleLayout::DockRightBottom => "dock-right",
            MiniConsoleLayout::DockLeftBottom => "dock-left",
            MiniConsoleLayout::Floating => "floating",
        }
    }
}

impl MiniConsoleTab {
    pub(crate) fn next(self) -> Self {
        match self {
            MiniConsoleTab::Output => MiniConsoleTab::Terminal,
            MiniConsoleTab::Terminal => MiniConsoleTab::Problems,
            MiniConsoleTab::Problems => MiniConsoleTab::Output,
        }
    }

    pub(crate) fn prev(self) -> Self {
        match self {
            MiniConsoleTab::Output => MiniConsoleTab::Problems,
            MiniConsoleTab::Terminal => MiniConsoleTab::Output,
            MiniConsoleTab::Problems => MiniConsoleTab::Terminal,
        }
    }

    pub(crate) fn index(self) -> usize {
        match self {
            MiniConsoleTab::Output => 0,
            MiniConsoleTab::Terminal => 1,
            MiniConsoleTab::Problems => 2,
        }
    }
}

impl MainPane {
    pub(crate) fn label(self) -> &'static str {
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

impl MainLayout {
    pub(crate) fn next(self) -> Self {
        match self {
            MainLayout::Single => MainLayout::SplitLeftTasks,
            MainLayout::SplitLeftTasks => MainLayout::TriPanel,
            MainLayout::TriPanel => MainLayout::Single,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            MainLayout::Single => "single",
            MainLayout::SplitLeftTasks => "split-left-tasks",
            MainLayout::TriPanel => "tri-panel",
        }
    }
}
