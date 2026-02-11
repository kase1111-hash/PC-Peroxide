//! Scheduled tasks scanner for persistence detection.
//!
//! Scans Windows Task Scheduler for suspicious tasks:
//! - Tasks running from unusual locations
//! - Tasks with suspicious commands
//! - Hidden or disabled tasks that might be malware

use super::{PersistenceEntry, PersistenceType};
use crate::core::error::Result;
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use std::process::Command;

/// Represents a scheduled task.
#[derive(Debug, Clone)]
pub struct ScheduledTask {
    /// Task name
    pub name: String,
    /// Task path (folder)
    pub task_path: String,
    /// Full path of task
    pub full_path: String,
    /// Command/executable to run
    pub command: Option<String>,
    /// Arguments
    pub arguments: Option<String>,
    /// Working directory
    pub working_directory: Option<String>,
    /// Task state (Ready, Disabled, Running, etc.)
    pub state: String,
    /// Last run time
    pub last_run: Option<String>,
    /// Next run time
    pub next_run: Option<String>,
    /// Task author
    pub author: Option<String>,
    /// Description
    pub description: Option<String>,
    /// Whether the task is enabled
    pub enabled: bool,
    /// Whether this task runs at logon
    pub runs_at_logon: bool,
    /// Whether this task runs at startup
    pub runs_at_startup: bool,
}

impl ScheduledTask {
    /// Create a new scheduled task entry.
    pub fn new(name: impl Into<String>, task_path: impl Into<String>) -> Self {
        let name = name.into();
        let task_path = task_path.into();
        let full_path = if task_path == "\\" {
            format!("\\{}", name)
        } else {
            format!("{}\\{}", task_path, name)
        };

        Self {
            name,
            task_path,
            full_path,
            command: None,
            arguments: None,
            working_directory: None,
            state: "Unknown".to_string(),
            last_run: None,
            next_run: None,
            author: None,
            description: None,
            enabled: true,
            runs_at_logon: false,
            runs_at_startup: false,
        }
    }

    /// Set the command.
    pub fn with_command(mut self, command: impl Into<String>) -> Self {
        self.command = Some(command.into());
        self
    }

    /// Set arguments.
    pub fn with_arguments(mut self, args: impl Into<String>) -> Self {
        self.arguments = Some(args.into());
        self
    }

    /// Set the state.
    pub fn with_state(mut self, state: impl Into<String>) -> Self {
        self.state = state.into();
        self.enabled = self.state.to_lowercase() != "disabled";
        self
    }

    /// Set the author.
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// Get the executable path from the command.
    pub fn get_executable_path(&self) -> Option<PathBuf> {
        self.command.as_ref().map(|cmd| {
            let cmd = cmd.trim();
            // Handle quoted paths
            #[allow(clippy::manual_strip)]
            if cmd.starts_with('"') {
                if let Some(end) = cmd[1..].find('"') {
                    return PathBuf::from(&cmd[1..=end]);
                }
            }
            // Handle unquoted paths
            if let Some(space) = cmd.find(' ') {
                PathBuf::from(&cmd[..space])
            } else {
                PathBuf::from(cmd)
            }
        })
    }
}

/// Scanner for Windows scheduled tasks.
pub struct TaskScanner {
    /// Suspicious command keywords
    suspicious_commands: Vec<String>,
    /// Suspicious paths
    suspicious_paths: Vec<String>,
    /// Known legitimate task authors
    known_authors: Vec<String>,
    /// Known legitimate task prefixes
    known_task_prefixes: Vec<String>,
}

impl Default for TaskScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskScanner {
    /// Create a new task scanner.
    pub fn new() -> Self {
        Self {
            suspicious_commands: vec![
                "powershell".to_string(),
                "cmd.exe".to_string(),
                "wscript".to_string(),
                "cscript".to_string(),
                "mshta".to_string(),
                "regsvr32".to_string(),
                "rundll32".to_string(),
                "certutil".to_string(),
                "bitsadmin".to_string(),
                "msiexec".to_string(),
                "curl".to_string(),
                "wget".to_string(),
            ],
            suspicious_paths: vec![
                "\\temp\\".to_string(),
                "\\tmp\\".to_string(),
                "\\appdata\\local\\temp".to_string(),
                "\\users\\public".to_string(),
                "\\programdata\\".to_string(),
                "\\downloads\\".to_string(),
            ],
            known_authors: vec![
                "Microsoft".to_string(),
                "Microsoft Corporation".to_string(),
                "Adobe".to_string(),
                "Google".to_string(),
                "NVIDIA".to_string(),
                "Intel".to_string(),
                "Apple".to_string(),
            ],
            known_task_prefixes: vec![
                "\\Microsoft\\".to_string(),
                "\\Google\\".to_string(),
                "\\Adobe\\".to_string(),
                "\\Apple\\".to_string(),
            ],
        }
    }

    /// Scan all scheduled tasks.
    pub fn scan_all(&self) -> Result<Vec<PersistenceEntry>> {
        let tasks = self.enumerate_tasks()?;
        let mut entries = Vec::new();

        for task in tasks {
            let entry = self.analyze_task(&task);
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Enumerate all scheduled tasks.
    pub fn enumerate_tasks(&self) -> Result<Vec<ScheduledTask>> {
        #[cfg(target_os = "windows")]
        {
            self.enumerate_tasks_windows()
        }

        #[cfg(not(target_os = "windows"))]
        {
            Ok(Vec::new())
        }
    }

    /// Enumerate tasks on Windows using schtasks.
    #[cfg(target_os = "windows")]
    fn enumerate_tasks_windows(&self) -> Result<Vec<ScheduledTask>> {
        let mut tasks = Vec::new();

        // Use schtasks to list all tasks in CSV format
        let output = Command::new("schtasks")
            .args(["/query", "/fo", "csv", "/v"])
            .output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    tasks.extend(self.parse_schtasks_csv(&stdout));
                }
            }
            Err(_) => {
                // schtasks failed, try alternative method
            }
        }

        Ok(tasks)
    }

    /// Parse schtasks CSV output.
    #[cfg(target_os = "windows")]
    fn parse_schtasks_csv(&self, csv: &str) -> Vec<ScheduledTask> {
        let mut tasks = Vec::new();
        let mut lines = csv.lines();

        // Get header line to find column indices
        let header = match lines.next() {
            Some(h) => h,
            None => return tasks,
        };

        let columns: Vec<&str> = Self::parse_csv_line(header);

        // Find column indices
        let task_name_idx = columns.iter().position(|c| c.contains("TaskName"));
        let next_run_idx = columns.iter().position(|c| c.contains("Next Run"));
        let status_idx = columns.iter().position(|c| c.contains("Status"));
        let task_to_run_idx = columns.iter().position(|c| c.contains("Task To Run"));
        let author_idx = columns.iter().position(|c| c.contains("Author"));

        for line in lines {
            if line.trim().is_empty() {
                continue;
            }

            let fields: Vec<&str> = Self::parse_csv_line(line);

            if let Some(name_idx) = task_name_idx {
                if let Some(task_name) = fields.get(name_idx) {
                    // Extract folder path and name
                    let full_path = task_name.to_string();
                    let (folder, name) = if let Some(last_sep) = full_path.rfind('\\') {
                        (
                            full_path[..last_sep].to_string(),
                            full_path[last_sep + 1..].to_string(),
                        )
                    } else {
                        ("\\".to_string(), full_path.clone())
                    };

                    let mut task = ScheduledTask::new(name, folder);
                    task.full_path = full_path;

                    if let Some(idx) = status_idx {
                        if let Some(status) = fields.get(idx) {
                            task = task.with_state(*status);
                        }
                    }

                    if let Some(idx) = task_to_run_idx {
                        if let Some(cmd) = fields.get(idx) {
                            if !cmd.is_empty() && *cmd != "N/A" {
                                task = task.with_command(*cmd);
                            }
                        }
                    }

                    if let Some(idx) = author_idx {
                        if let Some(author) = fields.get(idx) {
                            if !author.is_empty() && *author != "N/A" {
                                task = task.with_author(*author);
                            }
                        }
                    }

                    if let Some(idx) = next_run_idx {
                        if let Some(next_run) = fields.get(idx) {
                            task.next_run = Some(next_run.to_string());
                        }
                    }

                    tasks.push(task);
                }
            }
        }

        tasks
    }

    /// Parse a CSV line handling quoted fields.
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    fn parse_csv_line(line: &str) -> Vec<&str> {
        let mut fields = Vec::new();
        let mut in_quotes = false;
        let mut start = 0;

        for (i, c) in line.char_indices() {
            match c {
                '"' => in_quotes = !in_quotes,
                ',' if !in_quotes => {
                    let field = &line[start..i];
                    fields.push(field.trim_matches('"').trim());
                    start = i + 1;
                }
                _ => {}
            }
        }

        // Don't forget the last field
        if start < line.len() {
            fields.push(line[start..].trim_matches('"').trim());
        }

        fields
    }

    /// Analyze a task and convert to persistence entry.
    fn analyze_task(&self, task: &ScheduledTask) -> PersistenceEntry {
        let mut entry =
            PersistenceEntry::new(PersistenceType::ScheduledTask, &task.name, &task.full_path);

        if task.command.is_some() {
            if let Some(exe_path) = task.get_executable_path() {
                entry = entry.with_path(&exe_path);
            }
            if let Some(ref args) = task.arguments {
                entry = entry.with_arguments(args);
            }
        }

        // Calculate suspicion
        let (score, reason) = self.calculate_suspicion(task);

        if score > 0 {
            entry = entry.mark_suspicious(reason, score);
        }

        entry
    }

    /// Calculate suspicion score for a task.
    fn calculate_suspicion(&self, task: &ScheduledTask) -> (u8, String) {
        let mut score = 0u8;
        let mut reasons = Vec::new();

        // Check if it's a known task
        if self.is_known_task(task) {
            return (0, String::new());
        }

        // Check command for suspicious patterns
        if let Some(ref cmd) = task.command {
            let cmd_lower = cmd.to_lowercase();

            for suspicious in &self.suspicious_commands {
                if cmd_lower.contains(suspicious) {
                    score = score.saturating_add(25);
                    reasons.push(format!("Uses {}", suspicious));
                }
            }

            for path in &self.suspicious_paths {
                if cmd_lower.contains(path) {
                    score = score.saturating_add(30);
                    reasons.push(format!("Executes from suspicious location: {}", path));
                }
            }

            // Check for encoded commands
            if cmd_lower.contains("-enc") || cmd_lower.contains("-encodedcommand") {
                score = score.saturating_add(40);
                reasons.push("Uses encoded command".to_string());
            }

            // Check for hidden window
            if cmd_lower.contains("-windowstyle hidden")
                || cmd_lower.contains("-w hidden")
                || cmd_lower.contains("/b")
            {
                score = score.saturating_add(20);
                reasons.push("Runs hidden".to_string());
            }

            // Check for download commands
            if cmd_lower.contains("downloadstring")
                || cmd_lower.contains("downloadfile")
                || cmd_lower.contains("invoke-webrequest")
                || cmd_lower.contains("wget")
                || cmd_lower.contains("curl")
            {
                score = score.saturating_add(35);
                reasons.push("Downloads content".to_string());
            }

            // Check for execution bypass
            if cmd_lower.contains("-executionpolicy bypass")
                || cmd_lower.contains("-ep bypass")
                || cmd_lower.contains("set-executionpolicy")
            {
                score = score.saturating_add(30);
                reasons.push("Bypasses execution policy".to_string());
            }
        }

        // Unknown author
        if task.author.is_none() {
            score = score.saturating_add(10);
            reasons.push("No author specified".to_string());
        } else if let Some(ref author) = task.author {
            if !self.is_known_author(author) {
                score = score.saturating_add(5);
            }
        }

        // Task in root folder (not under known vendors)
        if task.task_path == "\\" || task.task_path.is_empty() {
            score = score.saturating_add(10);
            reasons.push("Task in root folder".to_string());
        }

        let reason = if reasons.is_empty() {
            format!("Unknown task: {}", task.name)
        } else {
            reasons.join("; ")
        };

        (score.min(100), reason)
    }

    /// Check if a task is from a known vendor.
    fn is_known_task(&self, task: &ScheduledTask) -> bool {
        // Check path prefix
        for prefix in &self.known_task_prefixes {
            if task.full_path.starts_with(prefix) {
                return true;
            }
        }

        // Check author
        if let Some(ref author) = task.author {
            if self.is_known_author(author) {
                return true;
            }
        }

        false
    }

    /// Check if an author is known/trusted.
    fn is_known_author(&self, author: &str) -> bool {
        let author_lower = author.to_lowercase();
        self.known_authors
            .iter()
            .any(|k| author_lower.contains(&k.to_lowercase()))
    }

    /// Get only suspicious tasks.
    pub fn scan_suspicious(&self) -> Result<Vec<PersistenceEntry>> {
        Ok(self
            .scan_all()?
            .into_iter()
            .filter(|e| e.suspicious)
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduled_task_new() {
        let task = ScheduledTask::new("TestTask", "\\Microsoft\\Windows");
        assert_eq!(task.name, "TestTask");
        assert_eq!(task.task_path, "\\Microsoft\\Windows");
        assert_eq!(task.full_path, "\\Microsoft\\Windows\\TestTask");
    }

    #[test]
    fn test_scheduled_task_root() {
        let task = ScheduledTask::new("RootTask", "\\");
        assert_eq!(task.full_path, "\\RootTask");
    }

    #[test]
    fn test_scheduled_task_command() {
        let task =
            ScheduledTask::new("Test", "\\").with_command("powershell.exe -encodedcommand abc123");

        assert!(task.command.is_some());
        assert_eq!(
            task.get_executable_path(),
            Some(PathBuf::from("powershell.exe"))
        );
    }

    #[test]
    fn test_task_scanner_creation() {
        let scanner = TaskScanner::new();
        assert!(!scanner.suspicious_commands.is_empty());
        assert!(!scanner.known_authors.is_empty());
    }

    #[test]
    fn test_is_known_author() {
        let scanner = TaskScanner::new();

        assert!(scanner.is_known_author("Microsoft Corporation"));
        assert!(scanner.is_known_author("microsoft"));
        assert!(scanner.is_known_author("Google Inc"));
        assert!(!scanner.is_known_author("Malware Author"));
    }

    #[test]
    fn test_is_known_task() {
        let scanner = TaskScanner::new();

        let known_task = ScheduledTask::new("Update", "\\Microsoft\\Windows")
            .with_author("Microsoft Corporation");
        assert!(scanner.is_known_task(&known_task));

        let unknown_task = ScheduledTask::new("Malware", "\\");
        assert!(!scanner.is_known_task(&unknown_task));
    }

    #[test]
    fn test_calculate_suspicion_clean() {
        let scanner = TaskScanner::new();

        let task = ScheduledTask::new("GoogleUpdate", "\\Google")
            .with_command(r"C:\Program Files\Google\Update\GoogleUpdate.exe")
            .with_author("Google");

        let (score, _) = scanner.calculate_suspicion(&task);
        assert_eq!(score, 0);
    }

    #[test]
    fn test_calculate_suspicion_malicious() {
        let scanner = TaskScanner::new();

        let task = ScheduledTask::new("Update", "\\")
            .with_command("powershell.exe -encodedcommand abc -windowstyle hidden");

        let (score, reason) = scanner.calculate_suspicion(&task);
        assert!(score >= 50); // Multiple red flags
        assert!(reason.contains("encoded"));
        assert!(reason.contains("hidden"));
    }

    #[test]
    fn test_calculate_suspicion_temp_path() {
        let scanner = TaskScanner::new();

        let task = ScheduledTask::new("Updater", "\\")
            .with_command(r"C:\Users\User\AppData\Local\Temp\update.exe");

        let (score, reason) = scanner.calculate_suspicion(&task);
        assert!(score >= 30);
        assert!(reason.contains("suspicious location"));
    }

    #[test]
    fn test_parse_csv_line() {
        let line = r#""Field1","Field 2","Field,With,Commas","Field4""#;
        let fields = TaskScanner::parse_csv_line(line);

        assert_eq!(fields.len(), 4);
        assert_eq!(fields[0], "Field1");
        assert_eq!(fields[1], "Field 2");
        assert_eq!(fields[2], "Field,With,Commas");
        assert_eq!(fields[3], "Field4");
    }

    #[test]
    fn test_scan_all_non_windows() {
        let scanner = TaskScanner::new();
        let tasks = scanner.scan_all().unwrap();

        #[cfg(not(target_os = "windows"))]
        assert!(tasks.is_empty());
    }
}
