#!/usr/bin/env python3
import psutil
import time
import os
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime

class PerformanceMonitor:
    def __init__(self, pid, output_dir="performance_test"):
        self.pid = pid
        self.output_dir = output_dir
        self.cpu_usage = []
        self.memory_usage = []
        self.timestamps = []
        os.makedirs(output_dir, exist_ok=True)
        
    def collect_metrics(self, duration_hours=24, interval=60):
        """收集性能指标"""
        process = psutil.Process(self.pid)
        start_time = time.time()
        end_time = start_time + duration_hours * 3600
        
        print(f"开始监控进程 {self.pid}")
        print(f"计划监控时长: {duration_hours}小时")
        
        try:
            while time.time() < end_time:
                # 收集CPU和内存使用率
                cpu_percent = process.cpu_percent()
                mem_percent = process.memory_percent()
                
                self.cpu_usage.append(cpu_percent)
                self.memory_usage.append(mem_percent)
                self.timestamps.append(time.time() - start_time)
                
                # 每小时输出一次状态
                if len(self.timestamps) % (3600/interval) == 0:
                    hours = (time.time() - start_time) / 3600
                    print(f"运行时间: {hours:.1f}小时")
                    print(f"CPU使用率: {cpu_percent:.1f}%")
                    print(f"内存使用率: {mem_percent:.1f}%")
                
                time.sleep(interval)
                
        except Exception as e:
            print(f"监控过程中出错: {e}")
        finally:
            self.generate_report()
    
    def generate_report(self):
        """生成性能报告和图表"""
        # 创建图表
        plt.figure(figsize=(15, 10))
        
        # CPU使用率
        plt.subplot(211)
        plt.plot(np.array(self.timestamps)/3600, self.cpu_usage)
        plt.title('CPU使用率随时间变化')
        plt.xlabel('时间 (小时)')
        plt.ylabel('CPU使用率 (%)')
        plt.grid(True)
        
        # 内存使用率
        plt.subplot(212)
        plt.plot(np.array(self.timestamps)/3600, self.memory_usage)
        plt.title('内存使用率随时间变化')
        plt.xlabel('时间 (小时)')
        plt.ylabel('内存使用率 (%)')
        plt.grid(True)
        
        plt.tight_layout()
        plt.savefig(f"{self.output_dir}/performance_report.png")
        
        # 生成统计报告
        with open(f"{self.output_dir}/performance_stats.txt", "w") as f:
            f.write(f"性能测试报告 - {datetime.now()}\n")
            f.write("="*50 + "\n\n")
            f.write(f"测试时长: {self.timestamps[-1]/3600:.1f}小时\n")
            f.write(f"CPU使用率 (平均): {np.mean(self.cpu_usage):.2f}%\n")
            f.write(f"CPU使用率 (最大): {np.max(self.cpu_usage):.2f}%\n")
            f.write(f"内存使用率 (平均): {np.mean(self.memory_usage):.2f}%\n")
            f.write(f"内存使用率 (最大): {np.max(self.memory_usage):.2f}%\n")

def main():
    # 启动嗅探器
    import subprocess
    sniffer = subprocess.Popen(["python3", "main.py", "-i", "ens5f0"], 
                             stdout=subprocess.PIPE)
    
    # 开始性能监控
    monitor = PerformanceMonitor(sniffer.pid)
    try:
        monitor.collect_metrics(duration_hours=24)
    finally:
        sniffer.terminate()

if __name__ == "__main__":
    main() 