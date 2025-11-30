/*
 | Project: ElaraOS
 | Description: Modern Operating System based on Linux kernel, with philosophy "NO LEGACY"
 | Authors: CodeLibraty Foundation, The Elara Project, Rejzi-dich
 |
 | Component: userland/elara-initramfs - fast, stable and modern initramfs generator for ElaraOS
 |
 | License: SPDX-License-Identifier: GPL-3.0-or-later
 | Website: https://codelibraty.vercel.app/elara-group
 | Copyright: CodeLibraty Foundation, The Elara Project
 */

use std::ffi::CString;
use std::fs;
use std::path::Path;
use std::process;

use anyhow::{Context, Result};
use nix::mount::{mount, umount2, MsFlags, MntFlags};
use nix::sys::stat::Mode;
use nix::unistd::{chroot, chdir, close, dup2, setsid};
use nix::fcntl::{open, OFlag};

use libc::ioctl;

const PROC_SRC: &str = "proc";
const SYSFS_SRC: &str = "sysfs";
const DEVTMPFS_SRC: &str = "devtmpfs";

fn main() -> Result<()> {
    // Монтируем временные виртуальные ФС в initramfs
    mount(
        Some(Path::new(PROC_SRC)),
        Path::new("/proc"),
        Some(Path::new("proc")),
        MsFlags::empty(),
        None::<&str>,
    )?;
    mount(
        Some(Path::new(SYSFS_SRC)),
        Path::new("/sys"),
        Some(Path::new("sysfs")),
        MsFlags::empty(),
        None::<&str>,
    )?;
    mount(
        Some(Path::new(DEVTMPFS_SRC)),
        Path::new("/dev"),
        Some(Path::new("devtmpfs")),
        MsFlags::empty(),
        None::<&str>,
    )?;

    println!("[   InitRamFS] Initializing the system");

    // Ждём появления /dev/sda
    loop {
        if Path::new("/dev/sda").exists() {
            println!("[   InitRamFS] Found root device: /dev/sda");
            break;
        }
        println!("[   InitRamFS] Waiting for root device...");
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    // Монтируем корневую ФС
    println!("[   InitRamFS] Mounting root filesystem...");
    if let Err(e) = mount(
        Some(Path::new("/dev/sda")),
        Path::new("/root"),
        Some(Path::new("ext4")),
        MsFlags::empty(),
        None::<&str>,
    ) {
        eprintln!("[   InitRamFS] Failed to mount root filesystem: {}", e);
        drop_to_shell();
    }

    // Создаём каталоги в корне
    create_dir("/root/System/Processes")?;
    create_dir("/root/System/SystemInfo")?;
    create_dir("/root/System/Devices")?;

    // Отмонтируем временные ФС
    println!("[   InitRamFS] Force unmounting virtual filesystems...");
    umount2(Path::new("/proc"), MntFlags::MNT_DETACH)?;
    umount2(Path::new("/sys"), MntFlags::MNT_DETACH)?;
    umount2(Path::new("/dev"), MntFlags::MNT_DETACH)?;

    // Перемонтируем в новые точки внутри /root
    println!("[   InitRamFS] Remounting in System directories...");
    mount(
        Some(Path::new(PROC_SRC)),
        Path::new("/root/System/Processes"),
        Some(Path::new("proc")),
        MsFlags::empty(),
        None::<&str>,
    )?;
    mount(
        Some(Path::new(SYSFS_SRC)),
        Path::new("/root/System/SystemInfo"),
        Some(Path::new("sysfs")),
        MsFlags::empty(),
        None::<&str>,
    )?;
    mount(
        Some(Path::new(DEVTMPFS_SRC)),
        Path::new("/root/System/Devices"),
        Some(Path::new("devtmpfs")),
        MsFlags::empty(),
        None::<&str>,
    )?;
    mount(
        Some(Path::new(DEVTMPFS_SRC)),
        Path::new("/root/System/Running"),
        Some(Path::new("devtmpfs")),
        MsFlags::empty(),
        None::<&str>,
    )?;
    
    // Проверяем наличие runit
    if !Path::new("/root/System/Binary/runit").exists() {
        eprintln!("[   InitRamFS] ERROR: /root/System/Binary/runit not found!");
        drop_to_shell();
    }

    println!("[   InitRamFS] Switching to real system...");

    // chroot и chdir
    chroot("/root")?;
    chdir("/")?;

    // Перенаправляем stdin/stdout/stderr
    close(0)?;
    close(1)?;
    close(2)?;

    let fd = match open_console("/System/Devices/console") {
        Ok(fd) => fd,
        Err(_) => open_console("/dev/console")?,
    };

    dup2(fd, 0)?;
    dup2(fd, 1)?;
    dup2(fd, 2)?;
    if fd > 2 {
        close(fd)?;
    }

    // Создаём новую сессию и устанавливаем controlling TTY
    setsid()?;
    unsafe {
        ioctl(0, libc::TIOCSCTTY, 1i32);
    }

    println!("[   InitRamFS] Starting justrunit...");

    // Запускаем runit
    let runit_path = CString::new("/System/Binary/runit")?;
    let runit_name = CString::new("runit")?;
    nix::unistd::execv(&runit_path, &[runit_name.as_c_str()])?;

    // Если execv вернулся — ошибка
    eprintln!("[   InitRamFS] Failed to execute runit");
    drop_to_shell();
}

fn create_dir(path: &str) -> Result<()> {
    fs::create_dir_all(path).with_context(|| format!("[   InitRamFS] Failed to create directory: {}", path))
}

fn open_console(path: &str) -> Result<i32> {
    open(
        Path::new(path),
        OFlag::O_RDWR,
        Mode::empty(),
    ).with_context(|| format!("[   InitRamFS] Failed to open console: {}", path))
}

fn drop_to_shell() -> ! {
    let sh_path = CString::new("/bin/sh").unwrap();
    let sh_name = CString::new("sh").unwrap();
    let _ = nix::unistd::execv(&sh_path, &[sh_name.as_c_str()]);
    // Если execv не сработал — завершаемся
    eprintln!("[   InitRamFS] FATAL: failed to launch shell");
    process::exit(1);
}