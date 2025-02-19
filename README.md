# Kernel Process Monitor 🚧  

## Overview  
This project is a **work in progress** and aims to develop a **Linux kernel module** that monitors key process metrics at the kernel level. The module collects per-process **CPU usage, memory faults, scheduler statistics**, and other essential system metrics. The collected data is exposed to **user-space programs** via the **proc-file system**, enabling further analysis and monitoring.  

## Features  
- **Tracks per-process resource consumption** including:  
  - **CPU usage**  
  - **Memory faults**  
  - **Process uptime**  
  - **Scheduler statistics**  
- **Proc-file system integration** for real-time user-space access.  
- **Character device interface** for additional monitoring capabilities.  
- Python-based analytics tools to process and visualize collected data.  

## Status  
🚧 **This project is actively under development.** 🚧  
New features, optimizations, and improvements are continuously being worked on.  

## Requirements  
- **Linux Kernel Version**: `5.15.165`  
- **Development Tools**:  
  - `gcc` (for compiling kernel modules)  
  - `make` (for build automation)  
  - `python3` (for analytics tools)  
- **Kernel Headers** matching the system kernel version.  

## Installation & Usage  

### 1. Clone the repository  
```sh
git clone <repository-url>
cd kernel-process-monitor
```

### 2. Build the Kernel Module  
```sh
make
```

### 3. Load the Module  
```sh
sudo insmod process_monitor.ko
```

### 4. Verify Module is Loaded  
```sh
lsmod | grep process_monitor
```

### 5. Access Process Metrics via Proc-File System  
```sh
cat /proc/process_monitor
```

### 6. Unload the Module  
```sh
sudo rmmod process_monitor
```

### 7. Clean Up Build Files  
```sh
make clean
```

## Analytics Tools  
Once the kernel module is running and exposing process data, Python scripts can be used for further **processing, visualization, and logging**. More details on analytics tools will be provided as development progresses.  

## Roadmap  
- [x] Implement basic CPU and memory tracking.  
- [x] Integrate proc-file system for user-space access.  
- [ ] Enhance data collection efficiency.  
- [ ] Implement more visualization tools in Python.  
- [ ] Add support for monitoring additional kernel-level statistics.  