/*
 | Project: ElaraOS
 | Descriptions: Modern Operating System based on Linux kernel, with philosophy "NO LEGACY"
 | Authors: CodeLibraty Foundation, The Elara Project, Rejzi-dich
 |
 | Component: userland/base-utils - fast, stable and modern utilities of the command line for ElaraOS
 |
 | License: SPDX-License-Identifier: GPL-3.0-or-later
 | Website: https://codelibraty.vercel.app/elara-group
 | CopyRight: CodeLibraty Foundation, The Elara Project
 */

use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write, BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process;
use std::time::SystemTime;
use chrono::{DateTime, Local};
use toml::Value;

// Структура для системной информации
#[derive(Debug)]
struct SystemConfig {
    name: String,
    version: String,
    codename: String,
    hostname: String,
}

fn parse_system_config() -> io::Result<SystemConfig> {
    let content = fs::read_to_string("/System/Data/Info.toml")?;
    let toml_value: Value = toml::from_str(&content)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    
    let system = toml_value.get("system")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Missing [system] section"))?;
    
    Ok(SystemConfig {
        name: system.get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("ElaraOS")
            .to_string(),
        version: system.get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        codename: system.get("codename")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string(),
        hostname: system.get("hostname")
            .and_then(|v| v.as_str())
            .unwrap_or("localhost")
            .to_string(),
    })
}

// Utilities
fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut val = bytes as f64;
    let mut unit = 0;

    while val >= 1024.0 && unit < UNITS.len() - 1 {
        val /= 1024.0;
        unit += 1;
    }

    if unit == 0 {
        format!("{} {}", val as u64, UNITS[unit])
    } else {
        format!("{:.2} {}", val, UNITS[unit])
    }
}

fn format_permissions(mode: u32) -> String {
    let file_type = if mode & libc::S_IFDIR != 0 { 'd' }
    else if mode & libc::S_IFLNK != 0 { 'l' }
    else { '-' };

    let perms = [
        if mode & 0o400 != 0 { 'r' } else { '-' },
        if mode & 0o200 != 0 { 'w' } else { '-' },
        if mode & 0o100 != 0 { 'x' } else { '-' },
        if mode & 0o040 != 0 { 'r' } else { '-' },
        if mode & 0o020 != 0 { 'w' } else { '-' },
        if mode & 0o010 != 0 { 'x' } else { '-' },
        if mode & 0o004 != 0 { 'r' } else { '-' },
        if mode & 0o002 != 0 { 'w' } else { '-' },
        if mode & 0o001 != 0 { 'x' } else { '-' },
    ];

    format!("{}{}", file_type, perms.iter().collect::<String>())
}

fn get_basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

// command: here (ls)
struct DirEntry {
    name: String,
    is_dir: bool,
    mode: u32,
    size: u64,
    modified: SystemTime,
    uid: u32,
    gid: u32,
}

fn cmd_here(args: &[String]) -> io::Result<()> {
    let mut path = PathBuf::from(".");
    let mut show_hidden = false;
    let mut show_long = false;
    let mut show_details = false;
    let mut recursive = false;

    for arg in args {
        match arg.as_str() {
            "-a" | "--all" => show_hidden = true,
            "-l" | "--long" => show_long = true,
            "-d" | "--details" => {
                show_details = true;
                show_long = true;
            },
            "-r" | "--recursive" => recursive = true,
            "-h" | "--help" => {
                println!("Usage: here [OPTIONS] [PATH]");
                println!("List directory contents\n");
                println!("Options:");
                println!("  -a, --all        Show hidden files");
                println!("  -l, --long       Long format with permissions");
                println!("  -d, --details    Show all details (size, owner, time)");
                println!("  -r, --recursive  List subdirectories recursively");
                println!("  -h, --help       Show this help");
                return Ok(());
            },
            _ if !arg.starts_with('-') => path = PathBuf::from(arg),
            _ => {}
        }
    }

    list_directory(&path, show_hidden, show_long, show_details, recursive)?;
    Ok(())
}

fn list_directory(path: &Path, show_hidden: bool, show_long: bool, show_details: bool, recursive: bool) -> io::Result<()> {
    let mut entries = Vec::new();

    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();

        if !show_hidden && name.starts_with('.') {
            continue;
        }

        let metadata = entry.metadata()?;
        let is_dir = metadata.is_dir();

        let (mode, uid, gid) = {
            use std::os::unix::fs::MetadataExt;
            (metadata.mode(), metadata.uid(), metadata.gid())
        };

        entries.push(DirEntry {
            name,
            is_dir,
            mode,
            size: metadata.len(),
                     modified: metadata.modified()?,
                     uid,
                     gid,
        });
    }

    // Сортировка: сначала директории, потом файлы
    entries.sort_by(|a, b| {
        match (a.is_dir, b.is_dir) {
            (true, false) => std::cmp::Ordering::Less,
                    (false, true) => std::cmp::Ordering::Greater,
                    _ => a.name.cmp(&b.name),
        }
    });

    if show_details {
        println!("{:<10} {:<8} {:<8} {:<10} {:<16} {}",
                 "MODE", "OWNER", "GROUP", "SIZE", "MODIFIED", "NAME");
        println!("{}", "─".repeat(73));
    }

    for entry in &entries {
        if show_details {
            let mode_str = format_permissions(entry.mode);
            let size_str = if entry.is_dir { "-".to_string() } else { format_size(entry.size) };
            let dt: DateTime<Local> = entry.modified.into();
            let time_str = dt.format("%Y-%m-%d %H:%M").to_string();

            println!("{:<10} {:<8} {:<8} {:<10} {:<16} {}",
                     mode_str, entry.uid, entry.gid, size_str, time_str,
                     if entry.is_dir { format!("\x1b[1;34m{}/\x1b[0m", entry.name) }
                     else { entry.name.clone() });
        } else if show_long {
            let mode_str = format_permissions(entry.mode);
            println!("{:<10} {}", mode_str,
                     if entry.is_dir { format!("\x1b[1;34m{}/\x1b[0m", entry.name) }
                     else { entry.name.clone() });
        } else {
            if entry.is_dir {
                println!("\x1b[1;34m{}/\x1b[0m", entry.name);
            } else {
                println!("{}", entry.name);
            }
        }
    }

    if recursive {
        for entry in &entries {
            if entry.is_dir {
                let subpath = path.join(&entry.name);
                println!("\n{}:", subpath.display());
                list_directory(&subpath, show_hidden, show_long, show_details, false)?;
            }
        }
    }

    Ok(())
}

// command: where (pwd)
fn cmd_where(_args: &[String]) -> io::Result<()> {
    let cwd = env::current_dir()?;
    println!("{}", cwd.display());
    Ok(())
}

// command: to (cd)
fn cmd_to(args: &[String]) -> io::Result<()> {
    let path = if args.is_empty() {
        env::var("HOME").unwrap_or_else(|_| "/".to_string())
    } else {
        let arg = &args[0];

        // Обработка множественных точек (.. ... ....)
        if arg.starts_with('.') && arg.chars().all(|c| c == '.') {
            let dots = arg.len();
            if dots > 1 {
                let mut path = env::current_dir()?;
                for _ in 1..dots {
                    if !path.pop() {
                        break;
                    }
                }
                path.to_string_lossy().to_string()
            } else {
                arg.clone()
            }
        } else {
            arg.clone()
        }
    };

    env::set_current_dir(&path)?;
    let cwd = env::current_dir()?;
    println!("{}", cwd.display());
    Ok(())
}


// commands: mkfile, mkdir, rmfile, rmdir
fn cmd_mkfile(args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: mkfile <file> [file...]");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no files specified"));
    }

    for file in args {
        OpenOptions::new()
        .create(true)
        .write(true)
        .open(file)?;
    }

    Ok(())
}

fn cmd_mkdir(args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: mkdir <directory> [directory...]");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no directories specified"));
    }

    for dir in args {
        fs::create_dir(dir)?;
    }

    Ok(())
}

fn cmd_rmfile(args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: rmfile <file> [file...]");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no files specified"));
    }

    for file in args {
        fs::remove_file(file)?;
    }

    Ok(())
}

fn cmd_rmdir(args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: rmdir <directory> [directory...]");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no directories specified"));
    }

    for dir in args {
        let path = Path::new(dir);

        if !path.is_dir() {
            eprintln!("{}: Not a directory", dir);
            continue;
        }

        let is_empty = fs::read_dir(path)?.next().is_none();

        if is_empty {
            fs::remove_dir(path)?;
        } else {
            print!("Directory '{}' is not empty. Remove? (Yes/No): ", dir);
            io::stdout().flush()?;

            let mut response = String::new();
            io::stdin().read_line(&mut response)?;

            if response.trim() == "Yes" {
                fs::remove_dir_all(path)?;
            }
        }
    }

    Ok(())
}


// command: show (cat)
fn cmd_show(args: &[String]) -> io::Result<()> {
    let mut show_line_numbers = false;
    let mut show_ends = false;
    let mut show_nonprinting = false;
    let mut squeeze_blank = false;
    let mut files = Vec::new();

    for arg in args {
        match arg.as_str() {
            "-n" | "--number" => show_line_numbers = true,
            "-E" | "--show-ends" => show_ends = true,
            "-A" | "--show-all" => {
                show_nonprinting = true;
                show_ends = true;
            },
            "-s" | "--squeeze-blank" => squeeze_blank = true,
            "-h" | "--help" => {
                println!("Usage: show [OPTIONS] [FILE...]");
                println!("Concatenate and print files\n");
                println!("Options:");
                println!("  -n, --number         Number all output lines");
                println!("  -E, --show-ends      Display $ at end of each line");
                println!("  -A, --show-all       Show all non-printing characters");
                println!("  -s, --squeeze-blank  Suppress repeated empty lines");
                println!("  -h, --help           Show this help");
                return Ok(());
            },
            _ => files.push(arg),
        }
    }

    if files.is_empty() {
        show_content(io::stdin().lock(), show_line_numbers, show_ends, show_nonprinting, squeeze_blank)?;
    } else {
        for file in files {
            let f = File::open(file)?;
            show_content(BufReader::new(f), show_line_numbers, show_ends, show_nonprinting, squeeze_blank)?;
        }
    }

    Ok(())
}

fn show_content<R: BufRead>(reader: R, number: bool, ends: bool, nonprint: bool, squeeze: bool) -> io::Result<()> {
    let mut line_num = 1;
    let mut prev_blank = false;

    for line in reader.lines() {
        let line = line?;
        let is_blank = line.is_empty();

        if squeeze && prev_blank && is_blank {
            continue;
        }

        if number {
            print!("{:6}  ", line_num);
            line_num += 1;
        }

        if nonprint {
            for ch in line.chars() {
                if ch.is_control() && ch != '\t' {
                    if ch as u8 == 127 {
                        print!("^?");
                    } else if ch as u8 == 9 {
                        print!("^I");
                    } else {
                        print!("^{}", (ch as u8 + 64) as char);
                    }
                } else {
                    print!("{}", ch);
                }
            }
        } else {
            print!("{}", line);
        }

        if ends {
            print!("$");
        }
        println!();

        prev_blank = is_blank;
    }

    Ok(())
}


// commands: copy, move, rename
fn cmd_copy(args: &[String]) -> io::Result<()> {
    if args.len() < 2 {
        eprintln!("Usage: copy <source> <destination>");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "insufficient arguments"));
    }

    fs::copy(&args[0], &args[1])?;
    Ok(())
}

fn cmd_move(args: &[String]) -> io::Result<()> {
    if args.len() < 2 {
        eprintln!("Usage: move <source> <destination>");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "insufficient arguments"));
    }

    fs::rename(&args[0], &args[1])?;
    Ok(())
}

fn cmd_rename(args: &[String]) -> io::Result<()> {
    if args.len() < 2 {
        eprintln!("Usage: rename <old_name> <new_name>");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "insufficient arguments"));
    }

    fs::rename(&args[0], &args[1])?;
    Ok(())
}


// commands: info, print, clear
fn cmd_info(args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: info <file> [file...]");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no files specified"));
    }

    for (i, file) in args.iter().enumerate() {
        let metadata = fs::metadata(file)?;
        let dt: DateTime<Local> = metadata.modified()?.into();

        #[cfg(unix)]
        let (mode, uid, gid) = {
            use std::os::unix::fs::MetadataExt;
            (metadata.mode(), metadata.uid(), metadata.gid())
        };

        #[cfg(not(unix))]
        let (mode, uid, gid) = (0, 0, 0);

        println!(" ╭─ File");
        println!(" │  ├─ Name: {}", file);
        print!(" │  ├─ Type: ");
        if metadata.is_dir() { println!("Directory"); }
        else if metadata.is_symlink() { println!("Symbolic link"); }
        else { println!("Regular file"); }
        println!(" │  ├─ Size: {} bytes", metadata.len());
        println!(" │  ├─ Permissions: {:04o}", mode & 0o7777);
        println!(" │  ├─ Owner: UID={} GID={}", uid, gid);
        println!(" │  └─ Modified: {}", dt.format("%Y-%m-%d %H:%M:%S"));

        if i < args.len() - 1 {
            println!();
        }
    }

    Ok(())
}

fn cmd_print(args: &[String]) -> io::Result<()> {
    println!("{}", args.join(" "));
    Ok(())
}

fn cmd_clear(_args: &[String]) -> io::Result<()> {
    print!("\x1b[H\x1b[2J");
    io::stdout().flush()?;
    Ok(())
}


// commands: whereis, sleep, write
fn cmd_whereis(args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: whereis <command>");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no command specified"));
    }

    let path_env = env::var("PATH").unwrap_or_default();

    for dir in path_env.split(':') {
        let full_path = Path::new(dir).join(&args[0]);
        if full_path.exists() && full_path.is_file() {
            println!("{}", full_path.display());
            return Ok(());
        }
    }

    Err(io::Error::new(io::ErrorKind::NotFound, "command not found"))
}

fn cmd_sleep(args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: sleep <seconds>");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no duration specified"));
    }

    let seconds: u64 = args[0].parse()
    .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid number"))?;

    std::thread::sleep(std::time::Duration::from_secs(seconds));
    Ok(())
}

fn cmd_write(args: &[String]) -> io::Result<()> {
    if args.len() < 2 {
        eprintln!("Usage: write <text> <file>");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "insufficient arguments"));
    }

    let mut file = File::create(&args[1])?;
    writeln!(file, "{}", args[0])?;
    Ok(())
}

// commands: sysinfo, who-user
fn cmd_sysinfo(_args: &[String]) -> io::Result<()> {
    // Чтение системной информации из TOML
    let config = parse_system_config().unwrap_or(SystemConfig {
        name: "ElaraOS".to_string(),
        version: "unknown".to_string(),
        codename: "unknown".to_string(),
        hostname: "unknown".to_string(),
    });

    println!(" ╭─ Operating System: {} {} ({})", config.name, config.version, config.codename);
    println!(" ├─ Hostname: {}", config.hostname);

    // Чтение информации о системе из /System/Processes
    if let Ok(version) = fs::read_to_string("/System/Processes/version") {
        let parts: Vec<&str> = version.split_whitespace().collect();
        if parts.len() >= 3 {
            println!(" ├─ Kernel");
            println!(" │  ├─ Name: {}", parts[0]);
            println!(" │  ├─ Version: {}", parts[2]);
            println!(" │  └─ Architecture: x86_64");
        }
    }

    // Uptime
    if let Ok(uptime_str) = fs::read_to_string("/System/Processes/uptime") {
        if let Some(uptime) = uptime_str.split_whitespace().next() {
            if let Ok(seconds) = uptime.parse::<f64>() {
                let secs = seconds as u64;
                let days = secs / 86400;
                let hours = (secs % 86400) / 3600;
                let mins = (secs % 3600) / 60;

                print!(" ├─ Uptime: ");
                if days > 0 {
                    println!("{} days, {} hours, {} minutes", days, hours, mins);
                } else if hours > 0 {
                    println!("{} hours, {} minutes", hours, mins);
                } else {
                    println!("{} minutes, {} seconds", mins, secs % 60);
                }
            }
        }
    }

    // Memory info
    if let Ok(meminfo) = fs::read_to_string("/System/Processes/meminfo") {
        let mut total = 0u64;
        let mut free = 0u64;
        let mut cached = 0u64;

        for line in meminfo.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let val = parts[1].parse::<u64>().unwrap_or(0) * 1024;
                match parts[0] {
                    "MemTotal:" => total = val,
                    "MemFree:" => free = val,
                    "Cached:" => cached = val,
                    _ => {}
                }
            }
        }

        let used = total - free;
        let usage = if total > 0 { (used * 100) / total } else { 0 };

        println!(" ├─ Memory");
        println!(" │  ├─ Total: {}", format_size(total));
        println!(" │  ├─ Used: {} ({}%)", format_size(used), usage);
        println!(" │  ├─ Free: {}", format_size(free));
        println!(" │  └─ Cached: {}", format_size(cached));
    }

    println!(" ╰─ System Information");

    Ok(())
}

fn cmd_who_user(args: &[String]) -> io::Result<()> {
    let username = if args.is_empty() {
        env::var("USER").unwrap_or_else(|_| "unknown".to_string())
    } else {
        args[0].clone()
    };

    println!(" ╭─ Identity");
    println!(" │  ├─ Username: {}", username);
    println!(" │  ├─ UID: {}", unsafe { libc::getuid() });
    println!(" │  └─ GID: {}", unsafe { libc::getgid() });
    println!(" ├─ Directories");
    println!(" │  ├─ Home: {}", env::var("HOME").unwrap_or_else(|_| "/Home".to_string()));
    println!(" │  └─ Shell: {}", env::var("SHELL").unwrap_or_else(|_| "/System/Binary/sh".to_string()));
    println!(" ╰─ Permissions");
    println!("    └─ Administrator: {}", if unsafe { libc::getuid() } == 0 { "Yes" } else { "No" });

    Ok(())
}

// commands: processes, stop
fn cmd_processes(_args: &[String]) -> io::Result<()> {
    println!("{:<8} {:<8} {:<20} {}", "PID", "UID", "STATE", "CMD");
    println!("{}", "-".repeat(72));

    for entry in fs::read_dir("/System/Processes")? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if name_str.chars().all(|c| c.is_ascii_digit()) {
            let status_path = entry.path().join("status");
            if let Ok(status) = fs::read_to_string(status_path) {
                let mut proc_name = String::new();
                let mut state = String::new();
                let mut uid = 0;

                for line in status.lines() {
                    if line.starts_with("Name:") {
                        proc_name = line.split_whitespace().nth(1).unwrap_or("").to_string();
                    } else if line.starts_with("State:") {
                        state = line.split_whitespace().nth(1).unwrap_or("").to_string();
                    } else if line.starts_with("Uid:") {
                        uid = line.split_whitespace().nth(1).unwrap_or("0").parse().unwrap_or(0);
                    }
                }

                println!("{:<8} {:<8} {:<20} {}", name_str, uid, state, proc_name);
            }
        }
    }

    Ok(())
}

fn cmd_stop(args: &[String]) -> io::Result<()> {
    if args.is_empty() {
        eprintln!("Usage: stop <pid> [pid...]");
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "no PIDs specified"));
    }

    for pid_str in args {
        let pid: i32 = pid_str.parse()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid PID"))?;

        unsafe {
            if libc::kill(pid, libc::SIGTERM) != 0 {
                eprintln!("Failed to kill process {}", pid);
            }
        }
    }

    Ok(())
}

// commands: turnoff, reboot
fn cmd_turnoff(_args: &[String]) -> io::Result<()> {
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_POWER_OFF);
    }
    Ok(())
}

fn cmd_reboot(_args: &[String]) -> io::Result<()> {
    unsafe {
        libc::sync();
        libc::reboot(libc::RB_AUTOBOOT);
    }
    Ok(())
}


// Entry point
fn main() {
    let args: Vec<String> = env::args().collect();
    let program = get_basename(&args[0]);
    let cmd_args = if args.len() > 1 { &args[1..] } else { &[] };

    let result = match program {
        "here"      => cmd_here(cmd_args),
        "where"     => cmd_where(cmd_args),
        "to"        => cmd_to(cmd_args),
        "mkfile"    => cmd_mkfile(cmd_args),
        "mkdir"     => cmd_mkdir(cmd_args),
        "rmfile"    => cmd_rmfile(cmd_args),
        "rmdir"     => cmd_rmdir(cmd_args),
        "show"      => cmd_show(cmd_args),
        "copy"      => cmd_copy(cmd_args),
        "move"      => cmd_move(cmd_args),
        "rename"    => cmd_rename(cmd_args),
        "processes" => cmd_processes(cmd_args),
        "stop"      => cmd_stop(cmd_args),
        "info"      => cmd_info(cmd_args),
        "print"     => cmd_print(cmd_args),
        "clear"     => cmd_clear(cmd_args),
        "whereis"   => cmd_whereis(cmd_args),
        "sleep"     => cmd_sleep(cmd_args),
        "sysinfo"   => cmd_sysinfo(cmd_args),
        "who-user"  => cmd_who_user(cmd_args),
        "turnoff"   => cmd_turnoff(cmd_args),
        "reboot"    => cmd_reboot(cmd_args),
        "write"     => cmd_write(cmd_args),
        _ => {
            eprintln!("{}: unknown command", program);
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!("{}: {}", program, e);
        process::exit(1);
    }
}
