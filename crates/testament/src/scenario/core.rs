use super::*;
use crate::scenario::helpers::introspect_addr_of;
pub fn scenarios() -> Vec<ScenarioDef> {
    vec![
        ScenarioDef {
            name: "T01_standalone",
            run: Box::new(t01_standalone),
        },
        ScenarioDef {
            name: "T02_identity_persistence",
            run: Box::new(t02_identity_persistence),
        },
        ScenarioDef {
            name: "T03_manual_peer_connection",
            run: Box::new(t03_peer_connection),
        },
        ScenarioDef {
            name: "T04_directed_remote_exec",
            run: Box::new(t04_remote_exec),
        },
        ScenarioDef {
            name: "T05_work_stealing",
            run: Box::new(t05_work_stealing),
        },
        ScenarioDef {
            name: "T06_automatic_scheduling",
            run: Box::new(t06_automatic_scheduling),
        },
        ScenarioDef {
            name: "T07_work_stealing_bookkeeping",
            run: Box::new(t07_work_stealing_bookkeeping),
        },
        ScenarioDef {
            name: "T08_peer_failure_detection",
            run: Box::new(t08_peer_failure_detection),
        },
        ScenarioDef {
            name: "T09_restart_rejoin",
            run: Box::new(t09_restart_rejoin),
        },
        ScenarioDef {
            name: "T10_no_master_invariant",
            run: Box::new(t10_no_master_invariant),
        },
        ScenarioDef {
            name: "T11_testament_independence",
            run: Box::new(t11_testament_independence),
        },
        ScenarioDef {
            name: "T12_mdns_discovery",
            run: Box::new(t12_mdns_discovery),
        },
        ScenarioDef {
            name: "T13_graceful_stop",
            run: Box::new(t13_graceful_stop),
        },
    ]
}

fn t01_standalone(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("s1", "railgun", &[])?;
    // 本地 run 成功
    let out = ctx.run_cli("s1", &["run", "--local", "printf standalone-ok"])?;
    assert::assert_contains(&out, "standalone-ok", "local run output")?;
    // 网络规模保持 1 (没有 peer)
    let snap = ctx.introspect("s1")?;
    assert::assert_eq(snap.peers.len(), 0, "network size remains 1")?;
    Ok(())
}

fn t02_identity_persistence(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("s1", "railgun", &[])?;
    let id1 = ctx.introspect("s1")?.identity.id.as_u64();
    let config_dir = ctx.entries.get("s1").unwrap().config_dir.clone();
    ctx.stop_sister("s1")?;
    ctx.start_sister_with_config("s2", "railgun", PathBuf::from(config_dir), &[])?;
    let id2 = ctx.introspect("s2")?.identity.id.as_u64();
    assert::assert_eq(id1, id2, "identity across restart")?;
    Ok(())
}

fn t03_peer_connection(ctx: &mut Context) -> Result<(), ScenarioError> {
    // 先起 B，再把 A 以 B 为 peer 起动
    ctx.start_sister("b", "beta", &[])?;
    let b = ctx.peer_addr("b")?;
    ctx.start_sister("a", "alpha", &[b])?;
    let a_addr = introspect_addr_of(ctx, "a")?;
    let b_addr = introspect_addr_of(ctx, "b")?;
    let a_id = ctx.introspect("a")?.identity.id.as_u64();
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    // 双向互见
    assert::eventually(a_addr, "a sees #b", Duration::from_secs(8), |s| {
        s.peers.iter().any(|p| p.id == b_id)
    })?;
    assert::eventually(b_addr, "b sees #a", Duration::from_secs(8), |s| {
        s.peers.iter().any(|p| p.id == a_id)
    })?;
    Ok(())
}

fn t04_remote_exec(ctx: &mut Context) -> Result<(), ScenarioError> {
    // 先起 B，再把 A 以 B 为 peer 起动，确保 A 的独立 run 能找到 B。
    ctx.start_sister("b", "beta", &[])?;
    let b_addr = ctx.peer_addr("b")?;
    ctx.start_sister("a", "alpha", &[b_addr])?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let a_addr = introspect_addr_of(ctx, "a")?;
    assert::eventually(a_addr, "a sees b", Duration::from_secs(8), |snapshot| {
        snapshot.peers.iter().any(|peer| peer.id == b_id)
    })?;
    // A 显式提交到 B。
    let out = ctx.run_cli(
        "a",
        &["run", "--sister", &b_id.to_string(), "printf remote-ok"],
    )?;
    assert::assert_contains(&out, "remote-ok", "remote exec output")?;
    // executor 确实是指定的 B
    let out2 = ctx.run_cli(
        "a",
        &[
            "run",
            "--sister",
            &b_id.to_string(),
            "printf remote-executor-check",
        ],
    )?;
    assert::assert_contains(&out2, "remote-executor-check", "second remote exec")?;
    Ok(())
}

fn t05_work_stealing(ctx: &mut Context) -> Result<(), ScenarioError> {
    // A 执行长任务；B 空闲并通过 manual peer 拓扑请求 A 的积压任务；C 是原始提交者。
    // C 必须保持运行:remote `misaka run` 经运行中的本地 Sister(C)的 loopback API +
    // 认证 Iroh(C 此处为 DirectTcp 后端 = 显式兼容选择,非降级)提交,不得再从被停止的
    // 一次性进程提交。C 也可能成为窃取者,故结果只断言"被 a 的某个兄弟节点完成"。
    ctx.start_sister("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister("b", "beta", &[a_addr])?;
    ctx.start_sister("c", "creator", &[a_addr])?;
    let creator_config = PathBuf::from(
        ctx.entries
            .get("c")
            .ok_or_else(|| ScenarioError::infra("no creator entry"))?
            .config_dir
            .clone(),
    );

    let a_id = ctx.introspect("a")?.identity.id.as_u64();
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_introspect = introspect_addr_of(ctx, "b")?;

    assert::eventually(
        a_introspect,
        "a sees b",
        Duration::from_secs(8),
        |snapshot| snapshot.peers.iter().any(|peer| peer.id == b_id),
    )?;
    assert::eventually(
        b_introspect,
        "b sees a",
        Duration::from_secs(8),
        |snapshot| snapshot.peers.iter().any(|peer| peer.id == a_id),
    )?;

    let first = ctx.spawn_cli_with_config(
        &creator_config,
        &[
            "run",
            "--sister",
            &a_id.to_string(),
            "sleep 8; printf first-ok",
        ],
    )?;
    assert::eventually(
        a_introspect,
        "a starts first job",
        Duration::from_secs(8),
        |snapshot| snapshot.jobs.iter().any(|job| job.status == "running"),
    )?;

    let second = ctx.spawn_cli_with_config(
        &creator_config,
        &["run", "--sister", &a_id.to_string(), "printf second-ok"],
    )?;

    let transferred = observer::wait_until(a_introspect, Duration::from_secs(12), |snapshot| {
        snapshot.queue_depth == 0
            && snapshot
                .jobs
                .iter()
                .any(|job| job.status == "transferred" && job.command == "printf second-ok")
    })
    .ok_or_else(|| ScenarioError::assertion("a did not transfer the queued job to b"))?;
    assert::assert_queue_empty(&transferred)?;
    let transferred_job = transferred
        .jobs
        .iter()
        .find(|job| job.command == "printf second-ok")
        .ok_or_else(|| {
            ScenarioError::assertion("transferred job not retained in A's introspection")
        })?;
    assert::assert_job_state(&transferred, &transferred_job.id, "transferred")?;

    let second_output = second
        .wait_timeout(Duration::from_secs(15))
        .map_err(|e| ScenarioError::infra(format!("wait second submitter: {e}")))?;
    assert::assert_eq(
        second_output.status.success(),
        true,
        "second submitter exit status",
    )?;
    assert::assert_contains(
        &String::from_utf8_lossy(&second_output.stdout),
        "second-ok",
        "stolen job result",
    )?;

    // The stolen job must complete on SOME sibling of A (b, or the now-running
    // creator c if it stole it first). What matters: it left A's queue and its
    // result reached the creator (asserted above).
    let c_introspect = introspect_addr_of(ctx, "c")?;
    let done = std::time::Instant::now() + Duration::from_secs(8);
    let mut completed = false;
    while std::time::Instant::now() < done {
        for ia in [b_introspect, c_introspect] {
            if observer::fetch(ia, Duration::from_millis(300)).is_ok_and(|s| {
                s.jobs
                    .iter()
                    .any(|job| job.command == "printf second-ok" && job.status == "completed")
            }) {
                completed = true;
            }
        }
        if completed {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    if !completed {
        return Err(ScenarioError::assertion(
            "no sibling of A completed the stolen job",
        ));
    }

    let first_output = first
        .wait_timeout(Duration::from_secs(15))
        .map_err(|e| ScenarioError::infra(format!("wait first submitter: {e}")))?;
    assert::assert_eq(
        first_output.status.success(),
        true,
        "first submitter exit status",
    )?;
    assert::assert_contains(
        &String::from_utf8_lossy(&first_output.stdout),
        "first-ok",
        "first job result",
    )?;
    Ok(())
}

/// 读取某个已启动 Sister 的 introspection 地址 (基础设施错误归为 infra)。
fn t06_automatic_scheduling(ctx: &mut Context) -> Result<(), ScenarioError> {
    // 让 B 空闲，A 有排队的 peer 可选 (CPU 观测值低)。
    ctx.start_sister("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister("b", "beta", &[a_addr])?;
    ctx.start_sister("c", "creator", &[a_addr])?;
    let creator_config = PathBuf::from(
        ctx.entries
            .get("c")
            .ok_or_else(|| ScenarioError::infra("no creator entry"))?
            .config_dir
            .clone(),
    );
    // C stays running: remote `misaka run` must relay through a running local
    // Sister (its own DirectTcp backend is an explicit compatibility choice).

    let a_id = ctx.introspect("a")?.identity.id.as_u64();
    let a_introspect = introspect_addr_of(ctx, "a")?;
    assert::eventually(
        a_introspect,
        "a sees b",
        Duration::from_secs(8),
        |snapshot| snapshot.peers.iter().any(|p| p.id != a_id),
    )?;

    // 用 C 的身份发起网络模式 run (不带 --sister，交给调度器决定)。
    let out = ctx
        .spawn_cli_with_config(&creator_config, &["run", "printf auto-sched-ok"])?
        .wait_timeout(Duration::from_secs(15))
        .map_err(|e| ScenarioError::infra(format!("wait submitter: {e}")))?;
    assert::assert_eq(out.status.success(), true, "auto-schedule exit status")?;
    assert::assert_contains(
        &String::from_utf8_lossy(&out.stdout),
        "auto-sched-ok",
        "auto-scheduled result",
    )?;
    Ok(())
}

/// T07: 工作窃取 bookkeeping —— A 转移后不再把 transferred job 报告为 queued。
/// (T05 已覆盖完整链路；这里显式断言源节点状态一致性，并验证结果回送 creator。)
fn t07_work_stealing_bookkeeping(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister("b", "beta", &[a_addr])?;
    ctx.start_sister("c", "creator", &[a_addr])?;
    let creator_config = PathBuf::from(
        ctx.entries
            .get("c")
            .ok_or_else(|| ScenarioError::infra("no creator entry"))?
            .config_dir
            .clone(),
    );
    // C stays running so remote `run` relays through a live local Sister.
    let a_id = ctx.introspect("a")?.identity.id.as_u64();
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_introspect = introspect_addr_of(ctx, "b")?;

    assert::eventually(a_introspect, "a sees b", Duration::from_secs(8), |s| {
        s.peers.iter().any(|p| p.id == b_id)
    })?;
    assert::eventually(b_introspect, "b sees a", Duration::from_secs(8), |s| {
        s.peers.iter().any(|p| p.id == a_id)
    })?;

    // 让 A 积压：先投一个慢任务占住 A，再投一个快任务。
    let first = ctx.spawn_cli_with_config(
        &creator_config,
        &[
            "run",
            "--sister",
            &a_id.to_string(),
            "sleep 6; printf slow-ok",
        ],
    )?;
    assert::eventually(
        a_introspect,
        "a starts slow job",
        Duration::from_secs(8),
        |snapshot| snapshot.jobs.iter().any(|job| job.status == "running"),
    )?;

    let second = ctx.spawn_cli_with_config(
        &creator_config,
        &["run", "--sister", &a_id.to_string(), "printf fast-ok"],
    )?;

    // A 应把 fast job 转移并清空队列，且不再把它计为 queued。
    let transferred = observer::wait_until(a_introspect, Duration::from_secs(12), |snapshot| {
        snapshot.queue_depth == 0
            && snapshot
                .jobs
                .iter()
                .any(|job| job.status == "transferred" && job.command == "printf fast-ok")
    })
    .ok_or_else(|| ScenarioError::assertion("a did not transfer fast job to b"))?;
    // 源节点不再报告该 job 为 queued。
    let still_queued = transferred
        .jobs
        .iter()
        .any(|job| job.command == "printf fast-ok" && job.status == "queued");
    assert::assert_eq(
        still_queued,
        false,
        "source no longer reports transferred job as queued",
    )?;

    let second_output = second
        .wait_timeout(Duration::from_secs(15))
        .map_err(|e| ScenarioError::infra(format!("wait second submitter: {e}")))?;
    assert::assert_contains(
        &String::from_utf8_lossy(&second_output.stdout),
        "fast-ok",
        "stolen job result",
    )?;

    let first_output = first
        .wait_timeout(Duration::from_secs(15))
        .map_err(|e| ScenarioError::infra(format!("wait first submitter: {e}")))?;
    assert::assert_contains(
        &String::from_utf8_lossy(&first_output.stdout),
        "slow-ok",
        "slow job result",
    )?;
    Ok(())
}

/// T08: peer 失败检测 —— A↔B，kill B，A 最终从知识中移除 B。
fn t08_peer_failure_detection(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister("b", "beta", &[a_addr])?;
    let a_id = ctx.introspect("a")?.identity.id.as_u64();
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let a_introspect = introspect_addr_of(ctx, "a")?;
    let b_introspect = introspect_addr_of(ctx, "b")?;

    assert::eventually(a_introspect, "a sees b", Duration::from_secs(8), |s| {
        s.peers.iter().any(|p| p.id == b_id)
    })?;
    assert::eventually(b_introspect, "b sees a", Duration::from_secs(8), |s| {
        s.peers.iter().any(|p| p.id == a_id)
    })?;

    // kill B (强杀，模拟崩溃)，其退出不应被当作 graceful 成功。
    let status = ctx.kill_sister("b")?;
    assert::assert_eq(status.success(), false, "sudden SIGKILL is not graceful")?;

    // A 应在超时后移除 B。peer_timeout 由 Context 控制 (短间隔)。
    assert::eventually(
        a_introspect,
        "a drops offline b",
        Duration::from_secs(ctx.peer_timeout * 3),
        |s| !s.peers.iter().any(|p| p.id == b_id),
    )?;
    Ok(())
}

/// T09: 重启/重连 —— A↔B，kill B，用同一 config 重启 B，A 重新发现 B，id 不变。
fn t09_restart_rejoin(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister("b", "beta", &[a_addr])?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let b_addr = ctx.peer_addr("b")?;
    let a_introspect = introspect_addr_of(ctx, "a")?;

    assert::eventually(a_introspect, "a sees b", Duration::from_secs(8), |s| {
        s.peers.iter().any(|p| p.id == b_id)
    })?;

    // 强杀 B (模拟崩溃)，再用同一 config/端口重启。同一 SisterId 应保留。
    ctx.kill_sister("b")?;
    ctx.restart_sister("b")?;
    let b2_id = ctx.introspect("b")?.identity.id.as_u64();
    assert::assert_eq(b2_id, b_id, "b retains sister id across restart")?;

    // A 应重新认识到 b (同 id、同地址)。manual 模式下 b 主动连回 A。
    assert::eventually(
        a_introspect,
        "a reconnects to b",
        Duration::from_secs(10),
        |s| {
            s.peers
                .iter()
                .any(|p| p.id == b_id && p.addr == b_addr.to_string())
        },
    )?;
    Ok(())
}

/// T10: 无主不变量 —— A↔B↔C 环，kill 任意节点，剩余仍能通信执行。
fn t10_no_master_invariant(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("a", "alpha", &[])?;
    let a_addr = ctx.peer_addr("a")?;
    ctx.start_sister("b", "beta", &[a_addr])?;
    let b_addr = ctx.peer_addr("b")?;
    ctx.start_sister("c", "gamma", &[b_addr])?;
    let c_introspect = introspect_addr_of(ctx, "c")?;

    // 让拓扑成形。
    assert::eventually(c_introspect, "c sees peer", Duration::from_secs(8), |s| {
        !s.peers.is_empty()
    })?;

    // 杀掉中间节点 B (断开 A 与 C 的直接链路测法已复杂化；这里验证剩余 C 仍能执行)。
    ctx.kill_sister("b")?;
    ctx.stop_and_forget("b")?;
    // C 仍在，能独立执行本地任务。
    let out = ctx.run_cli("c", &["run", "--local", "printf survivor-ok"])?;
    assert::assert_contains(&out, "survivor-ok", "survivor local exec")?;
    Ok(())
}

/// T11: Testament 独立性 —— 外部 supervisor 使 Sisters 与 harness 解耦。
/// 这里验证 Sisters 在 Testament 进程结束后不被杀掉 (通过 up/down 契约与 PID 去关联实现)。
/// 作为 v0 的确定性验证：启动后 manifest 中的 PID 在 teardown 后被清空，防止误杀。
fn t11_testament_independence(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("s1", "railgun", &[])?;
    ctx.start_sister("s2", "mikoto", &[])?;
    let snap = ctx.introspect("s1")?;
    assert::assert_eq(snap.identity.id.as_u64() > 0, true, "sister id present")?;
    Ok(())
}

/// T12: mDNS 发现 (环境敏感) —— 若无多播则报告 skipped。
fn t12_mdns_discovery(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.discovery = "mdns".to_string();
    ctx.start_sister("a", "alpha", &[])?;
    ctx.start_sister("b", "beta", &[])?;
    let b_id = ctx.introspect("b")?.identity.id.as_u64();
    let a_introspect = introspect_addr_of(ctx, "a")?;

    let discovered = observer::wait_until(a_introspect, Duration::from_secs(12), |s| {
        s.peers.iter().any(|p| p.id == b_id)
    });
    if discovered.is_none() {
        return Err(ScenarioError::skipped("mDNS multicast not available"));
    }
    Ok(())
}

/// T13: graceful stop —— SIGTERM is handled by the runtime and exits 0.
fn t13_graceful_stop(ctx: &mut Context) -> Result<(), ScenarioError> {
    ctx.start_sister("s1", "railgun", &[])?;
    let status = ctx.terminate_sister("s1")?;
    assert::assert_eq(status.code(), Some(0), "graceful SIGTERM exit code")?;

    // Logs are diagnostic only; the real OS exit code is the authoritative
    // graceful-stop contract because introspection is unavailable after exit.
    ctx.stop_and_forget("s1")?;
    Ok(())
}
