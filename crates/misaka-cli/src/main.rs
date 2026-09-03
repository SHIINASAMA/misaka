use clap::{Parser, Subcommand};

use misaka_runtime::error::MisakaError;
use misaka_runtime::identity_store::IdentityStore;
use misaka_runtime::node::SisterNode;
use misaka_runtime::peer_store::PeerStore;
use misaka_runtime::runtime::{default_encryption_key, SisterRuntime};
use std::net::SocketAddr;

#[derive(Parser)]
#[command(name = "misaka")]
#[command(about = "Misaka Network - decentralized computing network")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// 启动一个 Sister 节点
    Start {
        /// 监听端口
        #[arg(long, default_value_t = 31700)]
        port: u16,

        /// 已知的 peer 地址，可重复指定 (Phase 1 临时替代 mDNS)
        #[arg(long)]
        peer: Vec<String>,

        /// 设置昵称
        #[arg(long)]
        nickname: Option<String>,

        /// 发现模式 (mdns | manual | off)
        #[arg(long, default_value = "mdns")]
        discovery: String,

        /// 心跳/状态广播间隔 (秒)
        #[arg(long, default_value_t = 10)]
        heartbeat: u64,

        /// 判定 peer 离线的时长 (秒)
        #[arg(long, default_value_t = 60)]
        peer_timeout: u64,

        /// 只读 introspection 端口 (0 = 禁用)
        #[arg(long, default_value_t = 0)]
        introspect: u16,
    },

    /// 修改本机 Sister 的昵称
    Nickname {
        /// 新的昵称
        nickname: String,
    },

    /// 查看本机信息与附近 Sister
    Status,

    /// 提交一个任务 (用 Network 自动选执行者；--local 强制本机)
    Run {
        /// 要执行的命令
        command: String,

        /// 强制本地执行 (不派发到别的 Sister)
        #[arg(long)]
        local: bool,

        /// 指定目标 Sister ID
        #[arg(long)]
        sister: Option<u64>,
    },
}

#[tokio::main]
async fn main() -> Result<(), MisakaError> {
    let cli = Cli::parse();
    match cli.command {
        Command::Start {
            port,
            peer,
            nickname,
            discovery,
            heartbeat,
            peer_timeout,
            introspect,
        } => {
            // 加载或生成身份 (持久化)
            let identity = IdentityStore::load_or_init(nickname.clone(), port)
                .map_err(|e| MisakaError::Other(e.to_string()))?;
            if nickname.clone().is_some() {
                println!("[Misaka] nickname updated: {}", identity.nickname);
            }

            println!("{}", identity.display_name());
            println!("  Device : {}", identity.hostname);
            println!("  Platform: {}", identity.platform);
            println!("  Version: {}", identity.version);

            let discovery_mode = match discovery.as_str() {
                "manual" => misaka_runtime::config::DiscoveryMode::Manual,
                "off" => misaka_runtime::config::DiscoveryMode::Off,
                _ => misaka_runtime::config::DiscoveryMode::Mdns,
            };
            let config = misaka_runtime::config::RuntimeConfig {
                listen_port: port,
                heartbeat_interval: std::time::Duration::from_secs(heartbeat),
                peer_timeout: std::time::Duration::from_secs(peer_timeout),
                discovery: discovery_mode,
                introspection_addr: if introspect != 0 {
                    Some(format!("127.0.0.1:{}", introspect).parse().unwrap())
                } else {
                    None
                },
                ..Default::default()
            };
            let runtime = SisterRuntime::new(
                identity,
                default_encryption_key(),
                config,
                peer.iter()
                    .filter_map(|p| p.parse::<SocketAddr>().ok())
                    .collect(),
            )
            .await?;
            runtime.run().await?;
        }

        Command::Nickname { nickname } => {
            let identity = IdentityStore::update_nickname(nickname)
                .map_err(|e| MisakaError::Other(e.to_string()))?;
            println!("[Misaka] nickname updated to {}", identity.nickname);
        }

        Command::Status => {
            let identity = IdentityStore::load()
                .map_err(|e| MisakaError::Other(e.to_string()))?
                .ok_or_else(|| {
                    MisakaError::Other("Not running. Run 'misaka start' first.".into())
                })?;

            // 本机实时资源
            let mut state = misaka_runtime::state::LocalState::new();
            state.refresh(&mut sysinfo::System::new());
            let mem_gb = |b: u64| b as f64 / 1024.0 / 1024.0 / 1024.0;

            println!("Misaka Network\n");
            println!("This Sister");
            println!("────────────────────────────────");
            println!(
                "{}  ({} {})",
                identity.display_name(),
                identity.hostname,
                identity.platform
            );
            println!("  Port     : {}", identity.listen_port);
            println!("  CPU      : {:.1}%", state.cpu_usage);
            println!(
                "  Memory   : {:.1} / {:.1} GB",
                mem_gb(state.memory_used),
                mem_gb(state.memory_total)
            );
            println!("  Queued   : {} job(s)", state.queued_jobs);

            // 附近 Sister (来自 peers.json)
            let nearby = PeerStore::load_from_file();
            println!("\nNearby Sisters");
            println!("────────────────────────────────");
            if nearby.is_empty() {
                println!("  (none discovered yet)");
            } else {
                for bp in &nearby {
                    let online = check_online(bp.addr.parse::<SocketAddr>().ok());
                    let mark = if online { "●" } else { "○" };
                    println!(
                        "{mark} #{}  \"{}\"  @ {}  {}",
                        bp.id,
                        bp.nickname,
                        bp.addr,
                        if online { "online" } else { "offline" }
                    );
                }
            }
        }

        Command::Run {
            command,
            local,
            sister,
        } => {
            let identity = IdentityStore::load()
                .map_err(|e| MisakaError::Other(e.to_string()))?
                .ok_or_else(|| {
                    MisakaError::Other("Not running. Run 'misaka start' first.".into())
                })?;
            let config = misaka_runtime::config::RuntimeConfig {
                listen_port: identity.listen_port,
                ..Default::default()
            };
            let node = SisterNode::new(identity, default_encryption_key(), config);

            if local {
                println!("[Misaka] run --local: {}", command);
                // 独立进程：不启动完整 runtime，直接同步执行并输出结果
                let result = node.run_local_sync(&command).await;
                print_result(&result);
            } else if let Some(sid) = sister {
                println!("[Misaka] run --sister #{}: {}", sid, command);
                let result = node.submit_to_sister(sid, &command).await?;
                print_result(&result);
            } else {
                println!("[Misaka] run (network): {}", command);
                let result = node.submit_job(&command).await?;
                print_result(&result);
            }
        }
    }

    Ok(())
}

fn print_result(result: &misaka_core::protocol::JobResultData) {
    println!("────────────────────────────────");
    println!(
        "Job {} completed by #{}{}",
        result.job_id,
        result.executor,
        if result.success {
            " (success)"
        } else {
            " (failed)"
        }
    );
    if !result.output.is_empty() {
        println!("Output:\n{}", result.output);
    }
}

/// 快速探测某个地址是否在线 (对 mDNS 发现的 peer 做轻量握手)。
fn check_online(addr: Option<SocketAddr>) -> bool {
    let Some(addr) = addr else { return false };
    // 阻塞式 TCP 连接尝试，超时 800ms
    use std::net::TcpStream;
    use std::time::Duration;
    TcpStream::connect_timeout(&addr, Duration::from_millis(800)).is_ok()
}
