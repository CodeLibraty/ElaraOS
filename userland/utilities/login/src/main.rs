use nix::sys::signal::{self, Signal};
use nix::sys::termios::{self, LocalFlags, SetArg};
use nix::unistd::{self, Gid, Uid};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::io::AsRawFd;
use std::path::Path;
use std::process::{Command, exit};
use std::time::{SystemTime, UNIX_EPOCH};
use std::os::unix::process::CommandExt;
use nix::libc;

const USERS_FILE: &str = "/System/Data/Users/Users.toml";
const AUTH_FILE: &str = "/System/Data/Users/Auth.toml";
const BINARY_PATHS: &str = "/System/Data/Environment/bin-paths";
const LIBRARY_PATHS: &str = "/System/Data/Environment/lib-paths";
const AUTH_LOG: &str = "/System/Logs/auth.log";
const MOTD_FILE: &str = "/System/Configs/motd";

const MAX_ATTEMPTS: u32 = 3;
const USERNAME_MAX: usize = 32;
const PASSWORD_MAX: usize = 256;

#[derive(Debug, Serialize, Deserialize, Clone)]
struct User {
    #[serde(rename = "userName")]
    user_name: String,
    #[serde(rename = "fullName")]
    full_name: String,
    #[serde(rename = "userAge")]
    user_age: u32,
    #[serde(rename = "userProfilePicture")]
    user_profile_picture: String,
    #[serde(rename = "homePath")]
    home_path: String,
    #[serde(rename = "defaultShell")]
    default_shell: String,
    uid: u32,
    gid: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct UsersFile {
    users: Vec<User>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthFile {
    users: HashMap<String, String>,
}

#[derive(Debug)]
enum LoginError {
    UserNotFound,
    WrongPassword,
    Timeout,
    MaxAttempts,
    SystemError(String),
    Io(io::Error),
    Toml(toml::de::Error),
    Nix(nix::errno::Errno),
}

impl std::fmt::Display for LoginError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UserNotFound => write!(f, "User not found"),
            Self::WrongPassword => write!(f, "Wrong password"),
            Self::Timeout => write!(f, "Timeout"),
            Self::MaxAttempts => write!(f, "Maximum number of attempts exceeded"),
            Self::SystemError(msg) => write!(f, "System error: {}", msg),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Toml(e) => write!(f, "TOML parse error: {}", e),
            Self::Nix(e) => write!(f, "System error: {}", e),
        }
    }
}

impl From<io::Error> for LoginError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<toml::de::Error> for LoginError {
    fn from(err: toml::de::Error) -> Self {
        Self::Toml(err)
    }
}

impl From<nix::errno::Errno> for LoginError {
    fn from(err: nix::errno::Errno) -> Self {
        Self::Nix(err)
    }
}

type Result<T> = std::result::Result<T, LoginError>;

fn load_users() -> Result<UsersFile> {
    if !Path::new(USERS_FILE).exists() {
        return Err(LoginError::SystemError(
            "Users file not found".to_string(),
        ));
    }

    let content = fs::read_to_string(USERS_FILE)?;
    let users_file: UsersFile = toml::from_str(&content)?;
    Ok(users_file)
}

fn load_auth() -> Result<AuthFile> {
    if !Path::new(AUTH_FILE).exists() {
        return Err(LoginError::SystemError(
            "Auth file not found".to_string(),
        ));
    }

    let content = fs::read_to_string(AUTH_FILE)?;
    let auth_file: AuthFile = toml::from_str(&content)?;
    Ok(auth_file)
}

fn get_user(username: &str) -> Result<Option<User>> {
    let users_file = load_users()?;
    Ok(users_file
        .users
        .into_iter()
        .find(|u| u.user_name == username))
}

fn get_user_hash(username: &str) -> Result<Option<String>> {
    let auth_file = load_auth()?;
    Ok(auth_file.users.get(username).cloned())
}

fn verify_password(password: &str, hash: &str) -> bool {
    pwhash::sha512_crypt::verify(password, hash)
}

fn log_auth(username: &str, message: &str, success: bool) {
    let _ = fs::create_dir_all("/System/Logs");

    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(AUTH_LOG)
    {
        let now = SystemTime::now();
        let timestamp = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let hostname = unistd::gethostname()
            .ok()
            .and_then(|h| h.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string());

        let status = if success { "SUCCESS" } else { "FAILED" };

        let _ = writeln!(
            file,
            "[{}] {} login {}: user={} from={}",
            timestamp, status, message, username, hostname
        );
    }
}

fn read_password(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;

    let tty_paths = ["/System/Devices/tty"];

    let mut tty_file = None;
    for path in &tty_paths {
        if let Ok(file) = OpenOptions::new().read(true).write(true).open(path) {
            tty_file = Some(file);
            break;
        }
    }

    let tty = tty_file.ok_or_else(|| {
        LoginError::SystemError("Couldn't open TTY device".to_string())
    })?;

    let tty_fd = tty.as_raw_fd();

    let termios_orig = termios::tcgetattr(tty_fd)?;

    let mut termios_new = termios_orig.clone();
    termios_new
        .local_flags
        .remove(LocalFlags::ECHO | LocalFlags::ECHOE | LocalFlags::ECHOK | LocalFlags::ECHONL);

    termios::tcsetattr(tty_fd, SetArg::TCSANOW, &termios_new)?;

    let mut password = String::new();
    let result = io::stdin().read_line(&mut password);

    let _ = termios::tcsetattr(tty_fd, SetArg::TCSANOW, &termios_orig);

    println!();

    result?;

    if password.ends_with('\n') {
        password.pop();
        if password.ends_with('\r') {
            password.pop();
        }
    }

    Ok(password)
}

fn read_line(prompt: &str) -> Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    if input.ends_with('\n') {
        input.pop();
        if input.ends_with('\r') {
            input.pop();
        }
    }

    Ok(input)
}

fn setup_environment(user: &User) -> Result<()> {
    unsafe {
        env::remove_var("PATH");
        env::remove_var("LD_LIBRARY_PATH");
        env::remove_var("HOME");
        env::remove_var("SHELL");
        env::remove_var("USER");
        env::remove_var("LOGNAME");
    }

    unsafe {
        env::set_var("HOME", &user.home_path);
        env::set_var("SHELL", &user.default_shell);
        env::set_var("USER", &user.user_name);
        env::set_var("LOGNAME", &user.user_name);
        env::set_var("PATH", "/System/Binary");
        env::set_var("TERM", "linux");
        env::set_var("UID", user.uid.to_string());
        env::set_var("GID", user.gid.to_string());
    }

    Ok(())
}

fn change_to_user(user: &User) -> Result<()> {
    // Инициализация дополнительных групп
    let username_cstr = std::ffi::CString::new(user.user_name.as_str())
        .map_err(|_| LoginError::SystemError("Invalid username".to_string()))?;

    unsafe {
        if libc::initgroups(username_cstr.as_ptr(), user.gid) != 0 {
            return Err(LoginError::SystemError("initgroups failed".to_string()));
        }
    }

    // Установка GID
    unistd::setgid(Gid::from_raw(user.gid))?;

    // Установка UID
    unistd::setuid(Uid::from_raw(user.uid))?;

    // Переход в домашнюю директорию
    if let Err(e) = env::set_current_dir(&user.home_path) {
        eprintln!(
            "Warning: cannot change to home directory {}: {}",
            user.home_path, e
        );
        if let Err(e2) = env::set_current_dir("/") {
            return Err(LoginError::SystemError(format!(
                "Cannot change to / directory: {}",
                e2
            )));
        }
    }

    Ok(())
}

fn show_motd() {
    if let Ok(file) = File::open(MOTD_FILE) {
        let reader = BufReader::new(file);
        for line in reader.lines() {
            if let Ok(line) = line {
                println!("{}", line);
            }
        }
    }
}

fn setup_signals() -> Result<()> {
    unsafe {
        signal::signal(Signal::SIGINT, signal::SigHandler::SigIgn)?;
        signal::signal(Signal::SIGQUIT, signal::SigHandler::SigIgn)?;
        signal::signal(Signal::SIGTSTP, signal::SigHandler::SigIgn)?;
    }
    Ok(())
}

fn restore_signals() -> Result<()> {
    unsafe {
        signal::signal(Signal::SIGINT, signal::SigHandler::SigDfl)?;
        signal::signal(Signal::SIGQUIT, signal::SigHandler::SigDfl)?;
        signal::signal(Signal::SIGTSTP, signal::SigHandler::SigDfl)?;
    }
    Ok(())
}

fn perform_login() -> Result<()> {
    if unistd::getuid().as_raw() != 0 {
        eprintln!("login: must be run as root");
        exit(1);
    }

    let _ = fs::create_dir_all("/System/Logs");

    setup_signals()?;

    let hostname = unistd::gethostname()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "localhost".to_string());

    let args: Vec<String> = env::args().collect();
    let mut username = if args.len() >= 2 {
        args[1].clone()
    } else {
        String::new()
    };

    let mut attempts = 0;

    while attempts < MAX_ATTEMPTS {
        if username.is_empty() {
            username = read_line(&format!("{} login: ", hostname))?;

            if username.is_empty() {
                continue;
            }

            if username.len() > USERNAME_MAX {
                eprintln!("Login incorrect");
                attempts += 1;
                username.clear();
                std::thread::sleep(std::time::Duration::from_secs(2));
                continue;
            }
        }

        let password = read_password("Password: ")?;

        if password.len() > PASSWORD_MAX {
            eprintln!("Login incorrect");
            log_auth(&username, "password too long", false);
            attempts += 1;
            username.clear();
            std::thread::sleep(std::time::Duration::from_secs(2));
            continue;
        }

        let user = match get_user(&username)? {
            Some(u) => u,
            None => {
                eprintln!("Login incorrect");
                log_auth(&username, "user not found", false);
                attempts += 1;
                username.clear();
                std::thread::sleep(std::time::Duration::from_secs(2));
                continue;
            }
        };

        let hash = match get_user_hash(&username)? {
            Some(h) => h,
            None => {
                eprintln!("Login incorrect");
                log_auth(&username, "no password hash", false);
                attempts += 1;
                username.clear();
                std::thread::sleep(std::time::Duration::from_secs(2));
                continue;
            }
        };

        if !verify_password(&password, &hash) {
            eprintln!("Login incorrect");
            log_auth(&username, "wrong password", false);
            attempts += 1;
            username.clear();
            std::thread::sleep(std::time::Duration::from_secs(2));
            continue;
        }

        // Успешный вход
        log_auth(&username, "login", true);

        let now = SystemTime::now();
        let timestamp = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        println!("Last login: {}", timestamp);
        show_motd();

        setup_environment(&user)?;

        if let Err(e) = change_to_user(&user) {
            eprintln!("login: cannot switch to user: {}", e);
            log_auth(&username, "failed to switch user", false);
            exit(1);
        }

        restore_signals()?;

        // Запуск оболочки
        let shell_path = user.default_shell.clone();

        let err = Command::new(&shell_path).exec();

        eprintln!("login: cannot execute shell: {}", err);
        log_auth(&username, "failed to exec shell", false);
        exit(1);
    }

    Err(LoginError::MaxAttempts)
}

fn main() {
    match perform_login() {
        Ok(_) => {}
        Err(e) => {
            eprintln!("login: {}", e);
            exit(1);
        }
    }
}