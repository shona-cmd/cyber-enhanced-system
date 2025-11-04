"""
NaashonSecureIoT - System Performance Optimizer for MTAC Deployment
Ensures OS, Python, GPU, and network settings are tuned for max throughput
& security.

Author: Grok (programmer mode)
Target: Ubuntu 22.04+ / Raspberry Pi OS / MTAC Edge Nodes
"""

import os
import sys
import psutil
import torch
import subprocess
from typing import List, Tuple


class PerformanceTuner:

    def __init__(self):
        self.recommendations = []
        self.critical_issues = []

    def check_cpu(self) -> Tuple[bool, str]:
        freq = psutil.cpu_freq()
        if freq.current < 2000:
            return False, f"Low CPU freq: {freq.current} MHz (recommend >= 2.0 GHz)"
        return True, "CPU frequency optimal"

    def check_ram(self) -> Tuple[bool, str]:
        mem = psutil.virtual_memory()
        total_gb = mem.total / (1024**3)
        if total_gb < 4:
            return False, f"Low RAM: {total_gb:.1f} GB (recommend >= 4GB)"
        return True, "RAM sufficient"

    def check_gpu(self) -> Tuple[bool, str]:
        if torch.cuda.is_available():
            name = torch.cuda.get_device_name(0)
            mem = torch.cuda.get_device_properties(0).total_memory / (
                1024**3)
            return True, f"GPU: {name} ({mem:.1f} GB)"
        return False, "No CUDA GPU detected (fallback to CPU)"

    def check_python(self) -> Tuple[bool, str]:
        if sys.version_info < (3, 8):
            return False, f"Python {sys.version.split()[0]} (require >= 3.8)"
        return True, f"Python {sys.version.split()[0]}"

    def check_torch_optim(self) -> List[str]:
        fixes = []
        if not torch.backends.mps.is_available() and not torch.cuda.is_available():
            fixes.append("export PYTORCH_ENABLE_MPS_FALLBACK=1")  # Apple Silicon
        if torch.cuda.is_available():
            fixes.append("torch.backends.cudnn.benchmark = True")
        return fixes

    def check_network(self) -> Tuple[bool, str]:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "8.8.8.8"],
                capture_output=True,
                timeout=3)
            if result.returncode == 0:
                return True, "Internet stable"
            return False, "No internet (required for threat intel)"
        except Exception:
            return False, "Network check failed"

    def check_iommu(self) -> Tuple[bool, str]:
        if os.path.exists("/proc/cmdline") and "iommu=pt" in open(
                "/proc/cmdline").read():
            return True, "IOMMU passthrough enabled (secure DMA)"
        return False, "IOMMU not enabled (recommend for edge isolation)"

    def apply_optimizations(self):
        sysctl_settings = \'\'
        # NaashonSecureIoT Performance Tuning
        net.core.somaxconn = 65535
        net.core.netdev_max_backlog = 5000
        net.ipv4.tcp_max_syn_backlog = 4096
        net.ipv4.tcp_syncookies = 1
        net.ipv4.tcp_fin_timeout = 15
        vm.swappiness = 1
        vm.overcommit_memory = 1
        fs.file-max = 2097152
        \'\';
        with open("/etc/sysctl.d/99-naashon-secure.conf", "w") as f:
            f.write(sysctl_settings)
        subprocess.run(["sysctl", "--load=/etc/sysctl.d/99-naashon-secure.conf"])
        self.recommendations.append("Applied sysctl optimizations")

    def generate_report(self) -> str:
        report = "# NaashonSecureIoT Performance Audit Report\n\n"
        checks = [
            self.check_cpu(),
            self.check_ram(),
            self.check_gpu(),
            self.check_python(),
            self.check_network(),
            self.check_iommu(),
        ]

        report += "## System Health\n"
        for ok, msg in checks:
            status = "PASS" if ok else "FAIL"
            report += f"- [{status}] {msg} {{}}\n"
            if not ok:
                self.critical_issues.append(msg)

        report += "\n## Torch Optimizations\n"
        for fix in self.check_torch_optim():
            report += f"```bash\n{fix}\n```\n"
            self.recommendations.append(fix)

        if not self.critical_issues:
            report += "\n**All critical checks passed. System ready for production.**\n"
        else:
            report += (
                f"\n**{len(self.critical_issues)} critical issue(s) "
                "detected. Fix before deployment.**\n"
            )

        return report

    def harden_system(self):
        \"\"\"Apply security + performance hardening\"\"\"
        commands = [
            "apt update && apt install -y linux-headers-$(uname -r) build-essential",
            "sysctl -w net.ipv4.conf.all.rp_filter=1",
            "sysctl -w net.ipv4.conf.default.rp_filter=1",
            "ufw allow 5000/tcp",  # Flask dashboard
            "ufw allow 1883/tcp",  # MQTT
            "ufw --force enable",
        ]
        for cmd in commands:
            subprocess.run(cmd, shell=True)
        self.recommendations.append("Firewall + kernel hardening applied")


# === AUTO-TUNE SCRIPT ===
if __name__ == "__main__":
    tuner = PerformanceTuner()
    print(tuner.generate_report())

    if input("\nApply optimizations? (y/n): ").lower() == "y":
        tuner.apply_optimizations()
        tuner.harden_system()
        print("\nOptimizations applied. Reboot recommended.")
        print("```bash\nsudo reboot\n```")
