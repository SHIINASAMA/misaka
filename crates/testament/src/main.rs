use clap::{Parser, Subcommand};
use testament::run_manager::{create_run, run_root, runs_dir};
use testament::scenario::{scenarios, Context};
use testament::types::Manifest;

#[derive(Parser)]
#[command(name = "testament")]
#[command(about = "Misaka Network external test harness")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 启动 N 个 Sister (v0 工具)
    Up {
        #[arg(long, default_value_t = 1)]
        sisters: u32,
        #[arg(long)]
        json: bool,
    },
    /// 查看某 run 的 manifest
    Status {
        run_id: String,
        #[arg(long)]
        json: bool,
    },
    /// 查看某 run 的日志
    Logs { run_id: String },
    /// 停止某 run
    Down { run_id: String },
    /// 运行一个场景
    Run {
        scenario: String,
        #[arg(long)]
        json: bool,
    },
    /// 运行所有内置场景 (T01-T04)
    Verify {
        #[arg(long)]
        json: bool,
    },
    /// 清理所有运行目录
    Clean,
}

fn main() {
    let cli = Cli::parse();
    let code = match cli.command {
        Command::Verify { json } => verify(json),
        Command::Run { scenario, json } => run_one(&scenario, json),
        Command::Up { sisters, json } => up(sisters, json),
        Command::Status { run_id, json } => status(&run_id, json),
        Command::Logs { run_id } => logs(&run_id),
        Command::Down { run_id } => down(&run_id),
        Command::Clean => clean(),
    };
    std::process::exit(code);
}

fn verify(json: bool) -> i32 {
    let (run_id, layout) = match create_run() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("testament: cannot create run: {}", e);
            return 2;
        }
    };
    if !json {
        println!("[testament] run {} — verifying scenarios", run_id);
    }

    let mut worst = 0;
    let mut suite = testament::types::SuiteReport {
        run_id: run_id.clone(),
        scenarios: Vec::new(),
        passed: 0,
        failed: 0,
        infra_failed: 0,
        skipped: 0,
        exit_code: 0,
    };
    let definitions = scenarios();
    let mut manifest_sisters = Vec::new();
    for def in definitions {
        let mut scenario_layout = layout.clone();
        scenario_layout.sisters_dir = layout.sisters_dir.join(def.name);
        if let Err(e) = std::fs::create_dir_all(&scenario_layout.sisters_dir) {
            eprintln!("testament: create scenario directory: {}", e);
            worst = worst.max(2);
            continue;
        }
        let mut ctx = Context::new(run_id.clone(), scenario_layout);
        let result = (def.run)(&mut ctx);
        let report = ctx.report(def.name, result);

        // 每个场景单独写到自己的 report 文件里
        let scenario_report_path = layout.sisters_dir.join(def.name).join("report.json");
        let _ = testament::reporter::write_report(&scenario_report_path, &report);

        let code = testament::reporter::exit_code_for(&report);
        suite.count(&report);
        if !json {
            println!(
                "[testament]   {} -> {}",
                def.name,
                match report.result.as_str() {
                    "passed" => "passed",
                    "skipped" => "skipped",
                    "failed" => "FAILED",
                    "infra_failed" => "INFRA-FAILED",
                    other => other,
                }
            );
        }
        if code > worst {
            worst = code;
        }
        if code != 0 && !json {
            eprintln!("  {}", report.assertion.clone().unwrap_or_default());
        }
        suite.scenarios.push(report);
        ctx.teardown();
        manifest_sisters.extend(ctx.manifest.sisters.clone());
    }
    suite.exit_code = worst;

    // 写聚合 suite report 到 run 根目录的 report.json (保留向后兼容的 §21 路径)
    if let Err(e) = testament::reporter::write_suite_report(&layout.report_path, &suite) {
        eprintln!("testament: write suite report: {}", e);
        worst = worst.max(2);
    }
    let manifest = Manifest {
        run_id: run_id.clone(),
        sisters: manifest_sisters,
    };
    if let Err(e) = testament::run_manager::write_manifest(&layout, &manifest) {
        eprintln!("testament: write manifest: {}", e);
        worst = worst.max(2);
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&suite).unwrap_or_else(|e| {
                format!("{{\"error\":\"failed to encode reports: {}\"}}", e)
            })
        );
    } else {
        println!("[testament] done; exit {}", worst);
    }
    worst
}

fn run_one(scenario: &str, json: bool) -> i32 {
    let (run_id, layout) = match create_run() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("testament: {}", e);
            return 2;
        }
    };
    let mut ctx = Context::new(run_id, layout.clone());
    let Some(def) = scenarios().into_iter().find(|d| d.name == scenario) else {
        eprintln!("testament: unknown scenario {:?}", scenario);
        return 2;
    };
    let result = (def.run)(&mut ctx);
    let report = ctx.report(def.name, result);
    let mut code = testament::reporter::exit_code_for(&report);
    if let Err(e) = testament::reporter::write_report(&layout.report_path, &report) {
        eprintln!("testament: write report: {}", e);
        code = code.max(2);
    }
    ctx.teardown();
    if let Err(e) = testament::run_manager::write_manifest(&layout, &ctx.manifest) {
        eprintln!("testament: write manifest: {}", e);
        code = code.max(2);
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|e| {
                format!("{{\"error\":\"failed to encode report: {}\"}}", e)
            })
        );
    } else {
        println!("[testament] {} -> {}", def.name, report.result);
        if code != 0 {
            eprintln!("{}", report.assertion.unwrap_or_default());
        }
    }
    code
}

fn up(sisters: u32, _json: bool) -> i32 {
    let (run_id, layout) = match create_run() {
        Ok(x) => x,
        Err(e) => {
            eprintln!("testament: {}", e);
            return 2;
        }
    };
    let mut ctx = Context::new(run_id.clone(), layout.clone());
    for i in 1..=sisters {
        let alias = format!("s{}", i);
        if let Err(e) = ctx.start_sister(&alias, &alias, &[]) {
            eprintln!("testament: {}: {}", alias, e);
            ctx.teardown();
            return 3;
        }
    }
    if let Err(e) = testament::run_manager::write_manifest(&layout, &ctx.manifest) {
        eprintln!("testament: write manifest: {}", e);
        ctx.teardown();
        return 2;
    }
    if _json {
        let m = serde_json::to_string_pretty(&ctx.manifest).unwrap_or_default();
        println!("{}", m);
    } else {
        println!("[testament] run {} up with {} sisters", run_id, sisters);
        for e in &ctx.manifest.sisters {
            println!(
                "  {}  id={:?}  pid={:?}  listen={}",
                e.alias, e.id, e.pid, e.listen_addr
            );
        }
    }
    // v0: up 启动独立进程；通过 manifest 中的 PID 由 down 负责停止。
    0
}

fn status(run_id: &str, _json: bool) -> i32 {
    let path = run_root(run_id).join("manifest.json");
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            println!("{}", s);
            0
        }
        Err(_) => {
            eprintln!("testament: no run {:?} (or no manifest)", run_id);
            2
        }
    }
}

fn logs(run_id: &str) -> i32 {
    let sisters_dir = run_root(run_id).join("sisters");
    if !sisters_dir.exists() {
        eprintln!("testament: no run {:?}", run_id);
        return 2;
    }
    if let Ok(rd) = std::fs::read_dir(&sisters_dir) {
        for entry in rd.flatten() {
            let dir = entry.path();
            let name = dir
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            println!("=== {} stdout ===", name);
            println!(
                "{}",
                std::fs::read_to_string(dir.join("stdout.log")).unwrap_or_default()
            );
            println!("=== {} stderr ===", name);
            println!(
                "{}",
                std::fs::read_to_string(dir.join("stderr.log")).unwrap_or_default()
            );
        }
    }
    0
}

fn down(run_id: &str) -> i32 {
    let root = run_root(run_id);
    if !root.exists() {
        eprintln!("testament: no run {:?}", run_id);
        return 2;
    }

    let manifest_path = root.join("manifest.json");
    if let Ok(contents) = std::fs::read_to_string(&manifest_path) {
        if let Ok(manifest) = serde_json::from_str::<Manifest>(&contents) {
            stop_manifest_sisters(&manifest);
        }
    }

    match std::fs::remove_dir_all(&root) {
        Ok(()) => {
            println!("[testament] removed run {}", run_id);
            0
        }
        Err(e) => {
            eprintln!("testament: remove run {}: {}", run_id, e);
            2
        }
    }
}

fn stop_manifest_sisters(manifest: &Manifest) {
    for sister in &manifest.sisters {
        let Some(pid) = sister.pid else { continue };
        match std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status()
        {
            Ok(status) if !status.success() => eprintln!(
                "[testament] sister {} (pid {}) already exited or could not be stopped",
                sister.alias, pid
            ),
            Err(e) => eprintln!(
                "[testament] stop sister {} (pid {}): {}",
                sister.alias, pid, e
            ),
            Ok(_) => {}
        }
    }
}

fn clean() -> i32 {
    if let Ok(runs) = std::fs::read_dir(runs_dir()) {
        for run in runs.flatten() {
            let manifest_path = run.path().join("manifest.json");
            if let Ok(contents) = std::fs::read_to_string(manifest_path) {
                if let Ok(manifest) = serde_json::from_str::<Manifest>(&contents) {
                    stop_manifest_sisters(&manifest);
                }
            }
        }
    }
    match std::fs::remove_dir_all(".testament") {
        Ok(()) => {
            println!("[testament] cleaned all runs");
            0
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            println!("[testament] cleaned all runs");
            0
        }
        Err(e) => {
            eprintln!("testament: clean: {}", e);
            2
        }
    }
}
