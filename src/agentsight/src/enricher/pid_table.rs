use std::collections::HashMap;

/// 进程 PID → 父进程信息的内存映射表
/// 用于丰富 raw event 的 ppid 字段
///
/// 主要由 proctrace exec 事件驱动填充。对于监控启动前已存在的进程，
/// 通过 `/proc/{pid}/status` 进行 lazy fill。
pub struct PidTable {
    table: HashMap<u32, PidInfo>,
}

struct PidInfo {
    ppid: u32,
    comm: String,
    cgroup_id: u64,
    last_seen_ns: u64,
}

impl PidTable {
    pub fn new() -> Self {
        Self {
            table: HashMap::new(),
        }
    }

    /// 从 proctrace exec 事件更新映射
    /// ppid 来自 BPF 侧的 task->real_parent->tgid
    pub fn update_from_exec(
        &mut self,
        pid: u32,
        ppid: u32,
        comm: &str,
        cgroup_id: u64,
        timestamp_ns: u64,
    ) {
        self.table.insert(
            pid,
            PidInfo {
                ppid,
                comm: comm.to_string(),
                cgroup_id,
                last_seen_ns: timestamp_ns,
            },
        );
    }

    /// 查询 pid 对应的 ppid。
    ///
    /// 优先从内存表查找；miss 时从 `/proc/{pid}/status` lazy fill。
    /// 仍然无法获取时返回 0。
    pub fn lookup_ppid(&mut self, pid: u32) -> u32 {
        if let Some(info) = self.table.get(&pid) {
            return info.ppid;
        }
        // Lazy fill: 从 procfs 读取 ppid 并缓存
        let ppid = Self::read_ppid_from_proc(pid);
        if ppid != 0 {
            self.table.insert(
                pid,
                PidInfo {
                    ppid,
                    comm: Self::read_comm_from_proc(pid),
                    cgroup_id: 0,
                    last_seen_ns: 0,
                },
            );
        }
        ppid
    }

    /// 清理过期条目（last_seen_ns 早于 cutoff_ns 的）
    pub fn gc_stale(&mut self, cutoff_ns: u64) {
        self.table.retain(|_, info| info.last_seen_ns >= cutoff_ns);
    }

    /// 从 /proc/{pid}/status 读取 PPid 字段
    fn read_ppid_from_proc(pid: u32) -> u32 {
        let path = format!("/proc/{}/status", pid);
        match std::fs::read_to_string(&path) {
            Ok(content) => {
                for line in content.lines() {
                    if let Some(val) = line.strip_prefix("PPid:") {
                        return val.trim().parse::<u32>().unwrap_or(0);
                    }
                }
                0
            }
            Err(_) => 0,
        }
    }

    /// 从 /proc/{pid}/comm 读取进程名
    fn read_comm_from_proc(pid: u32) -> String {
        let path = format!("/proc/{}/comm", pid);
        std::fs::read_to_string(&path)
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    }
}
