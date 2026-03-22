use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;

use super::AppState;
use crate::tui::pane_cache_text::{
    build_launcher_detail_lines, build_launcher_list_items, build_project_detail_lines,
    build_project_list_items, build_result_list_items, build_script_file_items,
    build_script_output_lines, build_task_compact_items, build_task_table_rows,
};

impl AppState {
    pub(super) fn refresh_task_pane_cache(&mut self, task_signature: u64) {
        let task_pane_key = super::TaskPaneCacheKey {
            project: self.current_project.clone(),
            task_signature,
            filter: self.filter,
        };
        if self.task_pane_cache_key.as_ref() == Some(&task_pane_key) {
            return;
        }

        self.task_table_rows = build_task_table_rows(&self.tasks);
        self.task_compact_items = build_task_compact_items(&self.tasks);
        self.task_pane_cache_key = Some(task_pane_key);
        self.task_pane_render_serial = self.task_pane_render_serial.wrapping_add(1);
    }

    pub(super) fn refresh_result_list_cache(&mut self, task_signature: u64) {
        let result_list_key = super::ResultListCacheKey {
            project: self.current_project.clone(),
            task_signature,
            filter: self.result_kind_filter,
            failed_first: self.result_failed_first,
            query: self.result_query.clone(),
        };
        if self.result_list_cache_key.as_ref() == Some(&result_list_key) {
            return;
        }

        self.result_list_items = build_result_list_items(&self.all_tasks, &self.result_indices);
        self.result_list_cache_key = Some(result_list_key);
        self.result_list_render_serial = self.result_list_render_serial.wrapping_add(1);
    }

    pub(super) fn refresh_scripts_pane_cache(&mut self) {
        let scripts_pane_key = super::ScriptsPaneCacheKey {
            project: self.current_project.clone(),
            scripts_signature: script_collection_signature(&self.scripts),
            script_output_serial: self.script_output_serial,
        };
        if self.scripts_pane_cache_key.as_ref() == Some(&scripts_pane_key) {
            return;
        }

        self.script_file_items = build_script_file_items(&self.scripts);
        self.script_output_lines = build_script_output_lines(&self.script_output);
        self.scripts_pane_cache_key = Some(scripts_pane_key);
        self.scripts_pane_render_serial = self.scripts_pane_render_serial.wrapping_add(1);
    }

    pub(super) fn refresh_projects_pane_cache(&mut self) {
        let projects_pane_key = super::ProjectsPaneCacheKey {
            project: self.current_project.clone(),
            projects_signature: projects_signature(&self.projects),
            project_selected: self.project_selected,
            current_project: self.current_project.clone(),
            project_template: self.project_template,
        };
        if self.projects_pane_cache_key.as_ref() == Some(&projects_pane_key) {
            return;
        }

        self.project_list_items = build_project_list_items(&self.projects);
        self.project_detail_lines = build_project_detail_lines(
            &self.projects,
            self.project_selected,
            self.current_project.as_path(),
            self.project_template,
        );
        self.projects_pane_cache_key = Some(projects_pane_key);
        self.projects_pane_render_serial = self.projects_pane_render_serial.wrapping_add(1);
    }

    pub(super) fn refresh_launcher_pane_cache(&mut self) {
        let launcher_pane_key = super::LauncherPaneCacheKey {
            selected: self.launcher_selected,
            items_signature: launcher_items_signature(&self.launcher_items),
        };
        if self.launcher_pane_cache_key.as_ref() == Some(&launcher_pane_key) {
            return;
        }

        self.launcher_list_items = build_launcher_list_items(&self.launcher_items);
        self.launcher_detail_lines =
            build_launcher_detail_lines(&self.launcher_items, self.launcher_selected);
        self.launcher_pane_cache_key = Some(launcher_pane_key);
        self.launcher_pane_render_serial = self.launcher_pane_render_serial.wrapping_add(1);
    }
}

fn script_collection_signature(scripts: &[PathBuf]) -> u64 {
    let mut hasher = DefaultHasher::new();
    scripts.len().hash(&mut hasher);
    for script in scripts {
        script.hash(&mut hasher);
    }
    hasher.finish()
}

fn projects_signature(projects: &[crate::tui::models::ProjectEntry]) -> u64 {
    let mut hasher = DefaultHasher::new();
    projects.len().hash(&mut hasher);
    for project in projects {
        project.name.hash(&mut hasher);
        project.path.hash(&mut hasher);
        project.imported.hash(&mut hasher);
    }
    hasher.finish()
}

fn launcher_items_signature(items: &[(&'static str, &'static str)]) -> u64 {
    let mut hasher = DefaultHasher::new();
    items.len().hash(&mut hasher);
    for (label, command) in items {
        label.hash(&mut hasher);
        command.hash(&mut hasher);
    }
    hasher.finish()
}
