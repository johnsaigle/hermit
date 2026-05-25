use colored::Colorize;
use ignore::WalkBuilder;
use rayon::prelude::*;
use regex::Regex;
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;
use std::sync::LazyLock;

static CURL_PIPE_SHELL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\b(curl|wget)\b.*\|.*\b(bash|sh|zsh|fish|dash)\b").unwrap());

static CURL_PIPE_INTERPRETER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(curl|wget)\b.*\|.*\b(python[23]?|perl|ruby|lua[0-9]*|node)\b").unwrap()
});

static RAW_GITHUB_FULL_COMMIT_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"https://raw\.githubusercontent\.com/[^/\s'"]+/[^/\s'"]+/[0-9a-fA-F]{40}/[^\s|'"]+"#,
    )
    .unwrap()
});

static REMOTE_URL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#"https?://[^\s|'"]+"#).unwrap());

// Matches: eval "$(curl ...)" or eval "`curl ...`" — eval explicitly executes the output
static CURL_EVAL_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\beval\s+.*(\$\(|`).*\b(curl|wget)\b").unwrap());

static IGNORE_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"hermit:\s*ignore(?:\s*\[([^\]]*)\])?").unwrap());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    Error,
    Warning,
}

#[derive(Debug)]
struct Violation {
    line_num: usize,
    message: String,
    line_content: String,
    rule_id: Option<String>,
    severity: Severity,
}

struct CommentStyle {
    prefix: &'static str,
    suffix: &'static str,
}

enum IgnoreDirective {
    All,
    Specific(String),
}

struct LintResult {
    violations_found: usize,
    files_checked: usize,
}

struct FileLintResult {
    path: PathBuf,
    violations: Vec<Violation>,
}

struct LintContext {
    is_markdown: bool,
}

struct SubmodulePruner {
    root: PathBuf,
    gitmodules_paths: Vec<PathBuf>,
}

fn main() {
    let root = env::args()
        .nth(1)
        .map_or_else(|| PathBuf::from("."), PathBuf::from);

    println!(
        "{}",
        "hermit: checking for curl/wget into shell patterns...\n".blue()
    );

    let result = lint_files(&root);

    println!();
    println!("{}", "═══════════════════════════════════════".blue());

    if result.violations_found == 0 {
        println!("{}", "✓ No pipe-to-shell RCE patterns found!".green());
        println!(
            "{}",
            format!("Files checked: {}", result.files_checked).blue()
        );
        process::exit(0);
    } else {
        println!(
            "{}",
            format!(
                "✗ Found {} RCE violation(s) in {} files",
                result.violations_found, result.files_checked
            )
            .red()
        );
        print_remediation_tip();
        println!();
        process::exit(1);
    }
}

fn print_remediation_tip() {
    println!(
        "{}",
        "Fix: use a versioned, verifiable install path.".blue()
    );
    println!(
        "{}",
        "  - Prefer the system package manager or language toolchain with an explicit version."
            .blue()
    );
    println!(
        "{}",
        "  - In CI/docs, download a fixed GitHub release asset or commit-pinned raw file, then verify checksum/signature before executing."
            .blue()
    );
    println!(
        "{}",
        "  - Examples: rustup-init from a fixed rustup archive, Foundry/Tilt release tarballs, or brew/apt/asdf/nix pins."
            .blue()
    );
    println!(
        "{}",
        "  - Env pins like VERSION=v1.0 bash only help if the remote script itself is trusted and immutable."
            .blue()
    );
}

fn lint_files(root: &Path) -> LintResult {
    let submodule_pruner = SubmodulePruner::new(root);
    let files_to_check: Vec<PathBuf> = WalkBuilder::new(root)
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .parents(true)
        .filter_entry(move |e| {
            let path = e.path();
            !is_excluded(path) && (!path.is_dir() || !submodule_pruner.is_submodule_dir(path))
        })
        .build()
        .filter_map(Result::ok)
        .map(ignore::DirEntry::into_path)
        .filter(|path| path.is_file() && should_check_file(path))
        .collect();

    let mut checked_results: Vec<FileLintResult> = files_to_check
        .par_iter()
        .filter_map(|path| lint_file(path))
        .collect();

    checked_results.sort_by(|a, b| a.path.cmp(&b.path));

    let mut violations_found: usize = 0;

    for result in &checked_results {
        if !result.violations.is_empty() {
            print_violations(&result.path, &result.violations);
            violations_found = violations_found.saturating_add(result.violations.len());
        }
    }

    LintResult {
        violations_found,
        files_checked: checked_results.len(),
    }
}

fn lint_file(path: &Path) -> Option<FileLintResult> {
    let source = fs::read_to_string(path).ok()?;
    let comment_style = comment_style_for_file(path)?;
    let context = LintContext {
        is_markdown: has_extension(path, "md"),
    };

    Some(FileLintResult {
        path: path.to_path_buf(),
        violations: check_file(&source, &context, &comment_style),
    })
}

fn is_excluded(path: &Path) -> bool {
    path.components().any(|component| {
        let name = component.as_os_str();
        name == OsStr::new("node_modules")
            || name == OsStr::new(".git")
            || name == OsStr::new("target")
            || name == OsStr::new("dist")
            || name == OsStr::new("build")
            || name == OsStr::new("coverage")
            || name == OsStr::new("vendor")
            || name == OsStr::new(".next")
            || name == OsStr::new(".nuxt")
            || name == OsStr::new(".turbo")
            || name == OsStr::new(".cache")
    })
}

impl SubmodulePruner {
    fn new(root: &Path) -> Self {
        Self {
            root: root.to_path_buf(),
            gitmodules_paths: parse_gitmodules_paths(root),
        }
    }

    fn is_submodule_dir(&self, path: &Path) -> bool {
        self.is_declared_submodule_path(path)
            || (path != self.root && has_submodule_gitdir_file(path))
    }

    fn is_declared_submodule_path(&self, path: &Path) -> bool {
        let Ok(relative) = path.strip_prefix(&self.root) else {
            return false;
        };

        self.gitmodules_paths
            .iter()
            .any(|submodule_path| relative == submodule_path)
    }
}

fn parse_gitmodules_paths(root: &Path) -> Vec<PathBuf> {
    let Ok(content) = fs::read_to_string(root.join(".gitmodules")) else {
        return Vec::new();
    };

    parse_gitmodules_paths_from_content(&content)
}

fn parse_gitmodules_paths_from_content(content: &str) -> Vec<PathBuf> {
    content
        .lines()
        .filter_map(|line| line.trim().split_once('='))
        .filter_map(|(key, value)| {
            if key.trim() == "path" {
                Some(PathBuf::from(value.trim().trim_matches('"')))
            } else {
                None
            }
        })
        .collect()
}

fn has_submodule_gitdir_file(path: &Path) -> bool {
    fs::read_to_string(path.join(".git"))
        .ok()
        .and_then(|content| parse_gitdir_target_from_content(&content))
        .is_some_and(|gitdir| gitdir_target_is_submodule(&gitdir))
}

fn parse_gitdir_target_from_content(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        line.trim_start()
            .strip_prefix("gitdir:")
            .map(|gitdir| gitdir.trim().to_string())
    })
}

fn gitdir_target_is_submodule(gitdir: &str) -> bool {
    let normalized = gitdir.replace('\\', "/");
    normalized.contains("/.git/modules/")
        || normalized.starts_with(".git/modules/")
        || normalized.starts_with("../.git/modules/")
}

fn should_check_file(path: &Path) -> bool {
    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let path_str = path.to_string_lossy();

    if is_makefile(file_name) {
        return true;
    }

    if file_name.starts_with("Dockerfile") || file_name.ends_with(".dockerfile") {
        return true;
    }

    if has_extension(path, "md") {
        return true;
    }

    if is_shell_file(path) {
        return true;
    }

    let is_yaml = has_extension(path, "yml") || has_extension(path, "yaml");

    if is_yaml && path_str.contains(".github/workflows") {
        return true;
    }

    false
}

fn has_extension(path: &Path, extension: &str) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case(extension))
}

fn is_shell_file(path: &Path) -> bool {
    ["sh", "bash", "zsh", "fish", "ksh", "csh"]
        .iter()
        .any(|extension| has_extension(path, extension))
}

fn is_makefile(file_name: &str) -> bool {
    file_name == "Makefile"
        || file_name == "makefile"
        || file_name == "GNUmakefile"
        || has_extension(Path::new(file_name), "mk")
}

fn comment_style_for_file(path: &Path) -> Option<CommentStyle> {
    if has_extension(path, "md") {
        return Some(CommentStyle {
            prefix: "<!--",
            suffix: "-->",
        });
    }

    if is_shell_file(path) || is_makefile(path.file_name().and_then(|n| n.to_str()).unwrap_or("")) {
        return Some(CommentStyle {
            prefix: "#",
            suffix: "",
        });
    }

    if has_extension(path, "yml") || has_extension(path, "yaml") {
        return Some(CommentStyle {
            prefix: "#",
            suffix: "",
        });
    }

    let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if file_name.starts_with("Dockerfile") || file_name.ends_with(".dockerfile") {
        return Some(CommentStyle {
            prefix: "#",
            suffix: "",
        });
    }

    None
}

fn is_ignore_directive(line: &str, style: &CommentStyle) -> Option<IgnoreDirective> {
    let trimmed = line.trim();

    if !trimmed.starts_with(style.prefix) {
        return None;
    }

    if !style.suffix.is_empty() && !trimmed.ends_with(style.suffix) {
        return None;
    }

    let inner = trimmed.strip_prefix(style.prefix).and_then(|rest| {
        if style.suffix.is_empty() {
            Some(rest.trim())
        } else if let Some(stripped) = rest.strip_suffix(style.suffix) {
            Some(stripped.trim())
        } else {
            None
        }
    });

    inner.and_then(|content| {
        IGNORE_RE.find(content).map(|m| {
            let caps = IGNORE_RE.captures(m.as_str());
            caps.and_then(|c| c.get(1))
                .map_or(IgnoreDirective::All, |rule_match| {
                    let rule = rule_match.as_str().trim();
                    if rule.is_empty() {
                        IgnoreDirective::All
                    } else {
                        IgnoreDirective::Specific(rule.to_string())
                    }
                })
        })
    })
}

fn split_inline_ignore<'a>(
    line: &'a str,
    style: &CommentStyle,
) -> Option<(&'a str, IgnoreDirective)> {
    let trimmed = line.trim();

    if trimmed.starts_with(style.prefix) {
        return None;
    }

    let directive_match = IGNORE_RE.find(line)?;
    let directive_start = directive_match.start();
    let before_directive = &line[..directive_start];
    let prefix_pos = before_directive.rfind(style.prefix)?;

    if line[..prefix_pos].trim().is_empty() {
        return None;
    }

    let comment_part = &line[prefix_pos..];
    is_ignore_directive(comment_part, style).map(|directive| (&line[..prefix_pos], directive))
}

fn check_file(
    content: &str,
    lint_context: &LintContext,
    comment_style: &CommentStyle,
) -> Vec<Violation> {
    let mut violations = Vec::new();
    let mut in_code_block = false;
    let mut lint_code_block = false;
    let mut skip_next: Option<IgnoreDirective> = None;

    for (line_num, line) in content.lines().enumerate() {
        let line_num = line_num.saturating_add(1);

        // Track code blocks in markdown
        if lint_context.is_markdown && line.trim().starts_with("```") {
            if in_code_block {
                lint_code_block = false;
            } else {
                lint_code_block = should_lint_markdown_code_block(line);
            }
            in_code_block = !in_code_block;
            continue;
        }

        // Skip non-shell markdown code blocks
        if in_code_block && !lint_code_block {
            continue;
        }

        // Markdown prose, tables, and inline code often document unsafe commands.
        // Only executable-looking fenced shell blocks are linted.
        if lint_context.is_markdown && !in_code_block {
            continue;
        }

        // Check for end-of-line ignore directive
        let (effective_line, inline_skip): (&str, Option<IgnoreDirective>) =
            if let Some((content, directive)) = split_inline_ignore(line, comment_style) {
                (content, Some(directive))
            } else {
                (line, None)
            };

        // Check if this line is a standalone ignore directive
        if inline_skip.is_none()
            && let Some(directive) = is_ignore_directive(effective_line, comment_style)
        {
            skip_next = Some(directive);
            continue;
        }

        // Apply ignore from previous line's directive
        let prev_skip = skip_next.take();

        // If either prev or inline directive says skip all, skip this line
        if prev_skip
            .as_ref()
            .is_some_and(|d| matches!(d, IgnoreDirective::All))
            || inline_skip
                .as_ref()
                .is_some_and(|d| matches!(d, IgnoreDirective::All))
        {
            continue;
        }

        // Skip comments and placeholders
        if is_comment_or_placeholder(effective_line, lint_context.is_markdown) {
            continue;
        }

        // Check RCE patterns
        let mut line_violations: Vec<Violation> = Vec::new();
        line_violations.extend(check_pipe_to_shell(effective_line, line_num));
        line_violations.extend(check_pipe_to_interpreter(effective_line, line_num));
        line_violations.extend(check_eval_curl(effective_line, line_num));

        // Apply specific rule filters from prev-line or inline directives
        if let Some(IgnoreDirective::Specific(rule)) = &prev_skip {
            line_violations.retain(|v| v.rule_id.as_deref() != Some(rule.as_str()));
        }
        if let Some(IgnoreDirective::Specific(rule)) = &inline_skip {
            line_violations.retain(|v| v.rule_id.as_deref() != Some(rule.as_str()));
        }

        violations.extend(line_violations);
    }

    violations
}

fn is_comment_or_placeholder(line: &str, is_markdown: bool) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with('#')
        || trimmed.starts_with("//")
        || trimmed.starts_with("<!--")
        || trimmed.contains("<url>")
        || trimmed.contains("<URL>")
        || (is_markdown
            && (trimmed.starts_with('`') || trimmed.starts_with('>') || trimmed.starts_with('-')))
}

fn should_lint_markdown_code_block(fence_line: &str) -> bool {
    let info = fence_line.trim().trim_start_matches("```").trim();
    if info.is_empty() {
        return false;
    }

    let language = info.split_whitespace().next().unwrap_or("");
    matches!(
        language,
        "bash" | "sh" | "shell" | "zsh" | "console" | "terminal" | "dockerfile"
    )
}

fn check_pipe_to_shell(line: &str, line_num: usize) -> Vec<Violation> {
    let mut violations = Vec::new();

    if CURL_PIPE_SHELL_RE.is_match(line) && !is_pinned_raw_github_url(line) {
        violations.push(Violation {
            line_num,
            message:
                "curl/wget piped directly to shell; use a pinned and verified installer instead."
                    .to_string(),
            line_content: line.trim().to_string(),
            rule_id: Some("pipe-to-shell".to_string()),
            severity: Severity::Error,
        });
    }

    violations
}

fn is_pinned_raw_github_url(line: &str) -> bool {
    let before_pipe = line.split('|').next().unwrap_or(line);
    let mut urls = REMOTE_URL_RE.find_iter(before_pipe);

    let Some(url) = urls.next() else {
        return false;
    };

    urls.next().is_none() && RAW_GITHUB_FULL_COMMIT_RE.is_match(url.as_str())
}

fn check_pipe_to_interpreter(line: &str, line_num: usize) -> Vec<Violation> {
    let mut violations = Vec::new();

    if CURL_PIPE_INTERPRETER_RE.is_match(line) {
        violations.push(Violation {
            line_num,
            message: "curl/wget piped directly to a scripting interpreter; use a pinned and verified installer instead."
                .to_string(),
            line_content: line.trim().to_string(),
            rule_id: Some("pipe-to-interpreter".to_string()),
            severity: Severity::Error,
        });
    }

    violations
}

fn check_eval_curl(line: &str, line_num: usize) -> Vec<Violation> {
    let mut violations = Vec::new();

    if CURL_EVAL_RE.is_match(line) {
        violations.push(Violation {
            line_num,
            message: "curl/wget inside eval — eval executes in current shell context, not a subshell. Prefer downloading and inspecting first."
                .to_string(),
            line_content: line.trim().to_string(),
            rule_id: Some("eval-curl".to_string()),
            severity: Severity::Warning,
        });
    }

    violations
}

fn print_violations(path: &Path, violations: &[Violation]) {
    let has_errors = violations.iter().any(|v| v.severity == Severity::Error);
    let path_prefix = if has_errors { "✗" } else { "⚠" };
    let path_color = if has_errors {
        path_prefix.red()
    } else {
        path_prefix.yellow()
    };
    println!("{} {}", path_color, path.display().to_string().white());
    for violation in violations {
        let prefix = match violation.severity {
            Severity::Error => "✗".red(),
            Severity::Warning => "⚠".yellow(),
        };
        println!(
            "  {} {} {}",
            format!("Line {}:", violation.line_num).yellow(),
            prefix,
            violation.message
        );
        println!("  {} {}", ">".blue(), violation.line_content);
    }
    println!();
}

#[cfg(test)]
#[allow(clippy::needless_raw_string_hashes, clippy::similar_names)]
mod tests {
    use super::*;

    fn shell_comment_style() -> CommentStyle {
        CommentStyle {
            prefix: "#",
            suffix: "",
        }
    }

    fn markdown_comment_style() -> CommentStyle {
        CommentStyle {
            prefix: "<!--",
            suffix: "-->",
        }
    }

    fn plain_context() -> LintContext {
        LintContext { is_markdown: false }
    }

    fn markdown_context() -> LintContext {
        LintContext { is_markdown: true }
    }

    // ===== curl | bash tests =====

    #[test]
    fn test_curl_pipe_bash_violation() {
        let violations = check_pipe_to_shell("curl https://example.com/install.sh | bash", 1);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_id.as_deref(), Some("pipe-to-shell"));
    }

    #[test]
    fn test_curl_pipe_sh_violation() {
        let violations = check_pipe_to_shell("curl -sSL https://example.com | sh", 1);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_wget_pipe_bash_violation() {
        let violations = check_pipe_to_shell("wget -qO- https://example.com | bash", 1);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_curl_pipe_sudo_bash_violation() {
        let violations = check_pipe_to_shell("curl https://example.com | sudo bash", 1);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_curl_pipe_zsh_violation() {
        let violations = check_pipe_to_shell("curl -L https://example.com | zsh", 1);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_raw_github_full_commit_pipe_bash_allowed() {
        let violations = check_pipe_to_shell(
            "curl -fsSL https://raw.githubusercontent.com/org/repo/0123456789abcdef0123456789abcdef01234567/install.sh | bash",
            1,
        );
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_raw_github_short_commit_pipe_bash_violation() {
        let violations = check_pipe_to_shell(
            "curl -fsSL https://raw.githubusercontent.com/org/repo/0123456/install.sh | bash",
            1,
        );
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_raw_github_tag_pipe_bash_violation() {
        let violations = check_pipe_to_shell(
            "curl -fsSL https://raw.githubusercontent.com/org/repo/v1.0.0/install.sh | bash",
            1,
        );
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_raw_github_full_commit_with_extra_url_pipe_bash_violation() {
        let violations = check_pipe_to_shell(
            "curl -fsSL https://example.com/install.sh https://raw.githubusercontent.com/org/repo/0123456789abcdef0123456789abcdef01234567/install.sh | bash",
            1,
        );
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_env_version_pipe_bash_violation() {
        let violations =
            check_pipe_to_shell("curl -fsSL https://def.no/haxx.sh | VERSION=v1.0 bash", 1);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_curl_no_pipe_allowed() {
        let violations = check_pipe_to_shell("curl -o install.sh https://example.com", 1);
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_curl_redirect_allowed() {
        let violations = check_pipe_to_shell("curl https://example.com > file.txt", 1);
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_echo_curl_string_not_flag() {
        // "curl" inside a string literal shouldn't trigger
        let violations = check_pipe_to_shell("echo 'use curl https://example.com | bash'", 1);
        // This is a tricky case - the regex will match because the curl and bash are in the line
        // But we rely on is_comment_or_placeholder and file context to reduce FPs
        // In practice, echo strings explaining the pattern are rare in shell scripts
        assert_eq!(violations.len(), 1);
    }

    // ===== curl | python/perl/ruby tests =====

    #[test]
    fn test_curl_pipe_python_violation() {
        let violations =
            check_pipe_to_interpreter("curl -s https://example.com/setup.py | python", 1);
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].rule_id.as_deref(),
            Some("pipe-to-interpreter")
        );
    }

    #[test]
    fn test_curl_pipe_python3_violation() {
        let violations = check_pipe_to_interpreter("curl https://example.com | python3 -", 1);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_wget_pipe_perl_violation() {
        let violations = check_pipe_to_interpreter("wget -O - https://example.com | perl", 1);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_curl_pipe_ruby_violation() {
        let violations = check_pipe_to_interpreter("curl https://example.com | ruby", 1);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_curl_pipe_node_violation() {
        let violations = check_pipe_to_interpreter("curl https://example.com | node", 1);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_curl_pipe_lua_violation() {
        let violations = check_pipe_to_interpreter("curl -s https://example.com | lua", 1);
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_curl_pipe_grep_allowed() {
        let violations = check_pipe_to_interpreter("curl https://example.com | grep pattern", 1);
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_pipe_to_non_interpreter_allowed() {
        let violations = check_pipe_to_interpreter("curl https://api.example.com | jq '.data'", 1);
        assert_eq!(violations.len(), 0);
    }

    // ===== eval-curl tests =====

    #[test]
    fn test_eval_dollar_paren_curl_violation() {
        let violations = check_eval_curl("eval \"$(curl -sSL https://example.com/install.sh)\"", 1);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_id.as_deref(), Some("eval-curl"));
        assert_eq!(violations[0].severity, Severity::Warning);
    }

    #[test]
    fn test_eval_backtick_curl_violation() {
        let violations = check_eval_curl("eval \"`curl -sSL https://example.com/install.sh`\"", 1);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_id.as_deref(), Some("eval-curl"));
    }

    #[test]
    fn test_bare_dollar_paren_no_eval_allowed() {
        // $(curl ...) without eval is not execution — could be variable assignment
        let violations = check_eval_curl("export FOO=\"$(curl https://example.com)\"", 1);
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_bare_backtick_no_eval_allowed() {
        // `curl ...` without eval is not necessarily RCE
        let violations = check_eval_curl("`curl -s https://example.com/script`", 1);
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_bash_minus_c_without_eval_allowed() {
        // bash -c with $(curl) is dangerous but eval-curl focuses on eval, pipe-to-shell catches the common case
        let violations = check_eval_curl("bash -c \"$(curl https://example.com)\"", 1);
        assert_eq!(violations.len(), 0);
    }

    // ===== Markdown code block tests =====

    #[test]
    fn test_markdown_bash_block_curl_violation() {
        let content = r#"
# Install

```bash
curl -sSL https://example.com | bash
```
"#;
        let violations = check_file(content, &markdown_context(), &markdown_comment_style());
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule_id.as_deref(), Some("pipe-to-shell"));
    }

    #[test]
    fn test_markdown_sh_block_curl_violation() {
        let content = r#"
```sh
wget -qO- https://example.com | sh
```
"#;
        let violations = check_file(content, &markdown_context(), &markdown_comment_style());
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_markdown_unlabeled_block_skipped() {
        let content = r#"
```
curl https://example.com | bash
```
"#;
        let violations = check_file(content, &markdown_context(), &markdown_comment_style());
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_markdown_text_block_skipped() {
        let content = r#"
```text
curl https://example.com | bash
```
"#;
        let violations = check_file(content, &markdown_context(), &markdown_comment_style());
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_markdown_console_block_curl_violation() {
        let content = r#"
```console
$ curl -sSL https://example.com | bash
```
"#;
        let violations = check_file(content, &markdown_context(), &markdown_comment_style());
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_markdown_example_outside_code_block_not_linted() {
        let content = r#"
## Don't do this

- `curl https://example.com | bash`
"#;
        let violations = check_file(content, &markdown_context(), &markdown_comment_style());
        // Inline code and list items are skipped by is_comment_or_placeholder
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_markdown_table_example_not_linted() {
        let content = r#"
| Rule | Example |
| --- | --- |
| pipe-to-shell | `curl https://example.com | bash` |
"#;
        let violations = check_file(content, &markdown_context(), &markdown_comment_style());
        assert_eq!(violations.len(), 0);
    }

    // ===== Ignore directive tests =====

    #[test]
    fn test_ignore_directive_skips_next_line() {
        let content = "# hermit: ignore\ncurl https://example.com | bash\n";
        let violations = check_file(content, &plain_context(), &shell_comment_style());
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_ignore_directive_specific_rule() {
        let content = "# hermit: ignore[pipe-to-shell]\ncurl https://example.com | bash\n";
        let violations = check_file(content, &plain_context(), &shell_comment_style());
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_ignore_directive_only_specific_rule() {
        let content = "# hermit: ignore[pipe-to-shell]\ncurl https://example.com | python\n";
        let violations = check_file(content, &plain_context(), &shell_comment_style());
        // pipe-to-shell skipped, but pipe-to-interpreter still fires
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].rule_id.as_deref(),
            Some("pipe-to-interpreter")
        );
    }

    #[test]
    fn test_inline_ignore_end_of_line() {
        let content = "curl https://example.com | bash  # hermit: ignore\n";
        let violations = check_file(content, &plain_context(), &shell_comment_style());
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_inline_ignore_only_that_line() {
        let content =
            "curl https://example.com | bash  # hermit: ignore\ncurl https://example.com | bash\n";
        let violations = check_file(content, &plain_context(), &shell_comment_style());
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_inline_ignore_markdown_html_comment() {
        let content = "curl https://example.com | bash  <!-- hermit: ignore -->\n";
        let violations = check_file(content, &plain_context(), &markdown_comment_style());
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_inline_ignore_specific_rule() {
        let content = "curl https://example.com | bash  # hermit: ignore[pipe-to-shell]\ncurl https://example.com | python\n";
        let violations = check_file(content, &plain_context(), &shell_comment_style());
        // First line's pipe-to-shell ignored, second line's pipe-to-interpreter fires
        assert_eq!(violations.len(), 1);
        assert_eq!(
            violations[0].rule_id.as_deref(),
            Some("pipe-to-interpreter")
        );
    }

    // ===== Shell script tests =====

    #[test]
    fn test_shell_comment_skipped() {
        let content = "# curl https://example.com | bash\necho hello\n";
        let violations = check_file(content, &plain_context(), &shell_comment_style());
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn test_shell_dockerfile_run_curl_violation() {
        let content = "RUN curl -sSL https://example.com | bash\n";
        let violations = check_file(content, &plain_context(), &shell_comment_style());
        assert_eq!(violations.len(), 1);
    }

    #[test]
    fn test_shell_curl_no_pipe_allowed() {
        let content = "curl -o /tmp/install.sh https://example.com && bash /tmp/install.sh\n";
        let violations = check_file(content, &plain_context(), &shell_comment_style());
        assert_eq!(violations.len(), 0);
    }

    // ===== File type detection tests =====

    #[test]
    fn test_shell_extensions_checked() {
        for file_name in ["install.sh", "install.bash", "install.zsh", "install.fish"] {
            assert!(should_check_file(Path::new(file_name)));
        }
    }

    #[test]
    fn test_makefiles_checked() {
        for file_name in ["Makefile", "makefile", "GNUmakefile", "rules.mk"] {
            assert!(should_check_file(Path::new(file_name)));
        }
    }

    #[test]
    fn test_dockerfiles_checked() {
        for file_name in ["Dockerfile", "Dockerfile.prod", "dev.dockerfile"] {
            assert!(should_check_file(Path::new(file_name)));
        }
    }

    #[test]
    fn test_github_workflows_checked() {
        assert!(should_check_file(Path::new(".github/workflows/ci.yml")));
    }

    #[test]
    fn test_should_lint_markdown_code_block_for_shell_languages() {
        assert!(should_lint_markdown_code_block("```bash"));
        assert!(should_lint_markdown_code_block("```sh"));
        assert!(should_lint_markdown_code_block("```console"));
        assert!(should_lint_markdown_code_block("```dockerfile"));
        assert!(!should_lint_markdown_code_block("```"));
        assert!(!should_lint_markdown_code_block("```text"));
    }

    // ===== Submodule tests =====

    #[test]
    fn test_parse_gitmodules_paths() {
        let content = r#"
[submodule "vendor/foo"]
    path = vendor/foo
    url = https://example.com/foo.git
[submodule "deps/bar"]
    path = "deps/bar"
    url = https://example.com/bar.git
"#;

        assert_eq!(
            parse_gitmodules_paths_from_content(content),
            vec![PathBuf::from("vendor/foo"), PathBuf::from("deps/bar")]
        );
    }

    #[test]
    fn test_declared_submodule_path_detected() {
        let pruner = SubmodulePruner {
            root: PathBuf::from("/repo"),
            gitmodules_paths: vec![PathBuf::from("deps/foo")],
        };

        assert!(pruner.is_declared_submodule_path(Path::new("/repo/deps/foo")));
        assert!(!pruner.is_declared_submodule_path(Path::new("/repo/deps/foo/src")));
        assert!(!pruner.is_declared_submodule_path(Path::new("/repo/deps/bar")));
    }

    #[test]
    fn test_gitdir_target_submodule_detection() {
        assert!(gitdir_target_is_submodule("../.git/modules/deps/foo"));
        assert!(gitdir_target_is_submodule("/repo/.git/modules/deps/foo"));
        assert!(!gitdir_target_is_submodule("/repo/.git/worktrees/feature"));
        assert!(!gitdir_target_is_submodule("/repo/.git"));
    }

    // ===== GitHub Actions workflow tests =====

    #[test]
    fn test_gha_run_step_curl_violation() {
        let content = r#"
jobs:
  deploy:
    steps:
      - run: curl -sSL https://example.com | bash
"#;
        let violations = check_file(content, &plain_context(), &shell_comment_style());
        assert_eq!(violations.len(), 1);
    }
}
