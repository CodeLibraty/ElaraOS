use nix::unistd::{self, Gid, Uid};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const USERS_FILE: &str = "/System/Data/Users/Users.toml";
const AUTH_FILE: &str = "/System/Data/Users/Auth.toml";
const GROUPS_FILE: &str = "/System/Data/Users/Groups.toml";
const HOME_BASE: &str = "/Home";
const SHELL_PATH: &str = "/System/Binary/sh";
const SALT_LEN: usize = 16;
const MIN_UID: u32 = 1000;

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

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Group {
    #[serde(rename = "groupName")]
    group_name: String,
    #[serde(rename = "fullName")]
    full_name: String,
    #[serde(rename = "defaultShell")]
    default_shell: String,
    gid: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct GroupsFile {
    groups: Vec<Group>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AuthFile {
    users: HashMap<String, String>,
}

#[derive(Debug)]
enum UserError {
    InvalidArgs,
    AccessDenied(String),
    UserExists(String),
    UserNotFound(String),
    GroupNotFound(String),
    WrongPassword,
    HashGeneration,
    HomeDirectory(String),
    AdminDelete,
    Initialization(String),
    Io(io::Error),
    Nix(nix::errno::Errno),
    Toml(toml::de::Error),
    TomlSer(toml::ser::Error),
}

impl std::fmt::Display for UserError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArgs => write!(f, "Invalid arguments"),
            Self::AccessDenied(msg) => write!(f, "Access denied: {}", msg),
            Self::UserExists(user) => write!(f, "User '{}' already exists", user),
            Self::UserNotFound(user) => write!(f, "User '{}' not found", user),
            Self::GroupNotFound(group) => write!(f, "Group '{}' not found", group),
            Self::WrongPassword => write!(f, "Invalid password"),
            Self::HashGeneration => write!(f, "Hash generation error"),
            Self::HomeDirectory(msg) => write!(f, "Home directory error: {}", msg),
            Self::AdminDelete => write!(f, "Deleting the admin user is prohibited"),
            Self::Initialization(msg) => write!(f, "Initialization error: {}", msg),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Nix(e) => write!(f, "System error: {}", e),
            Self::Toml(e) => write!(f, "TOML parse error: {}", e),
            Self::TomlSer(e) => write!(f, "TOML serialization error: {}", e),
        }
    }
}

impl From<io::Error> for UserError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<nix::errno::Errno> for UserError {
    fn from(err: nix::errno::Errno) -> Self {
        Self::Nix(err)
    }
}

impl From<toml::de::Error> for UserError {
    fn from(err: toml::de::Error) -> Self {
        Self::Toml(err)
    }
}

impl From<toml::ser::Error> for UserError {
    fn from(err: toml::ser::Error) -> Self {
        Self::TomlSer(err)
    }
}

type Result<T> = std::result::Result<T, UserError>;

fn print_usage(program: &str) {
    eprintln!("Usage: {} [OPTION]", program);
    eprintln!("User Management Utility\n");
    eprintln!("Options:");
    eprintln!("  --init                     System initialization");
    eprintln!("  --add <username>           Add a user");
    eprintln!("  --password <username>      Change the password");
    eprintln!("  --delete <username>        Delete a user");
    eprintln!("  --list                     User list");
    eprintln!("  --modify <username>        Modify user properties");
    eprintln!("  --list-groups              Group list");
}

fn generate_salt() -> String {
    use rand::Rng;
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    
    let mut rng = rand::thread_rng();
    (0..SALT_LEN)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

fn generate_hash(password: &str) -> Result<String> {
    let salt = generate_salt();
    let salt_full = format!("$6${}$", salt);
    
    pwhash::sha512_crypt::hash_with(salt_full.as_str(), password)
        .map_err(|_| UserError::HashGeneration)
}

fn verify_password(password: &str, hash: &str) -> bool {
    pwhash::sha512_crypt::verify(password, hash)
}

fn load_users() -> Result<UsersFile> {
    if !Path::new(USERS_FILE).exists() {
        return Ok(UsersFile { users: Vec::new() });
    }
    
    let content = fs::read_to_string(USERS_FILE)?;
    let users_file: UsersFile = toml::from_str(&content)?;
    Ok(users_file)
}

fn save_users(users_file: &UsersFile) -> Result<()> {
    let toml_string = toml::to_string_pretty(users_file)?;
    fs::write(USERS_FILE, toml_string)?;
    fs::set_permissions(USERS_FILE, fs::Permissions::from_mode(0o644))?;
    Ok(())
}

fn load_groups() -> Result<GroupsFile> {
    if !Path::new(GROUPS_FILE).exists() {
        return Ok(GroupsFile { groups: Vec::new() });
    }
    
    let content = fs::read_to_string(GROUPS_FILE)?;
    let groups_file: GroupsFile = toml::from_str(&content)?;
    Ok(groups_file)
}

fn save_groups(groups_file: &GroupsFile) -> Result<()> {
    let toml_string = toml::to_string_pretty(groups_file)?;
    fs::write(GROUPS_FILE, toml_string)?;
    fs::set_permissions(GROUPS_FILE, fs::Permissions::from_mode(0o644))?;
    Ok(())
}

fn load_auth() -> Result<AuthFile> {
    if !Path::new(AUTH_FILE).exists() {
        return Ok(AuthFile {
            users: HashMap::new(),
        });
    }
    
    let content = fs::read_to_string(AUTH_FILE)?;
    let auth_file: AuthFile = toml::from_str(&content)?;
    Ok(auth_file)
}

fn save_auth(auth_file: &AuthFile) -> Result<()> {
    let toml_string = toml::to_string_pretty(auth_file)?;
    fs::write(AUTH_FILE, toml_string)?;
    fs::set_permissions(AUTH_FILE, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn create_directory_recursive(path: &Path) -> Result<()> {
    if path.exists() {
        if path.is_dir() {
            return Ok(());
        } else {
            return Err(UserError::HomeDirectory(
                format!("{} exists and is not a directory", path.display())
            ));
        }
    }
    
    fs::create_dir_all(path).map_err(|e| {
        UserError::HomeDirectory(format!("Failed to create {}: {}", path.display(), e))
    })
}

fn ensure_directory(path: &Path) -> Result<()> {
    create_directory_recursive(path)?;
    
    if let Ok(rel_path) = path.strip_prefix(HOME_BASE) {
        let path_str = rel_path.to_string_lossy();
        
        if !path_str.contains('/') && !path_str.is_empty() {
            create_user_subdirectories(path)?;
        }
    }
    
    Ok(())
}

fn create_user_subdirectories(base_path: &Path) -> Result<()> {
    let user_subdirs = ["Desktop", "Downloads", "Media", "Notes", "Local"];
    let media_subdirs = ["Music", "Pictures", "Videos", "Wallpapers"];
    let local_subdirs = ["Configs", "Backups"];
    
    for subdir in &user_subdirs {
        let subdir_path = base_path.join(subdir);
        if let Err(e) = fs::create_dir(&subdir_path) {
            if e.kind() != io::ErrorKind::AlreadyExists {
                eprintln!("Warning: failed to create {}: {}", subdir_path.display(), e);
            }
        }
        
        if *subdir == "Media" {
            for media_sub in &media_subdirs {
                let media_path = subdir_path.join(media_sub);
                if let Err(e) = fs::create_dir(&media_path) {
                    if e.kind() != io::ErrorKind::AlreadyExists {
                        eprintln!("Warning: failed to create {}: {}", media_path.display(), e);
                    }
                }
            }
        }
        
        if *subdir == "Local" {
            for local_sub in &local_subdirs {
                let local_path = subdir_path.join(local_sub);
                if let Err(e) = fs::create_dir(&local_path) {
                    if e.kind() != io::ErrorKind::AlreadyExists {
                        eprintln!("Warning: failed to create {}: {}", local_path.display(), e);
                    }
                }
            }
        }
    }
    
    Ok(())
}

fn get_next_uid() -> Result<u32> {
    let users_file = load_users()?;
    
    if users_file.users.is_empty() {
        return Ok(MIN_UID);
    }
    
    let max_uid = users_file
        .users
        .iter()
        .map(|u| u.uid)
        .max()
        .unwrap_or(MIN_UID - 1);
    
    Ok(max_uid + 1)
}

fn user_exists(username: &str) -> Result<bool> {
    let users_file = load_users()?;
    Ok(users_file.users.iter().any(|u| u.user_name == username))
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
        UserError::Io(io::Error::new(
            io::ErrorKind::NotFound,
            "Couldn't open TTY device"
        ))
    })?;
    
    let tty_fd = tty.as_raw_fd();
    
    let termios_orig = nix::sys::termios::tcgetattr(tty_fd)
        .map_err(|e| UserError::Io(io::Error::new(
            io::ErrorKind::Other, 
            format!("Couldn't get terminal settings: {}", e)
        )))?;
    
    let mut termios_new = termios_orig.clone();
    termios_new.local_flags.remove(nix::sys::termios::LocalFlags::ECHO);
    
    nix::sys::termios::tcsetattr(
        tty_fd,
        nix::sys::termios::SetArg::TCSANOW,
        &termios_new
    ).map_err(|e| UserError::Io(io::Error::new(
        io::ErrorKind::Other,
        format!("Couldn't disable echo: {}", e)
    )))?;
    
    let mut password = String::new();
    let result = io::stdin().read_line(&mut password);
    
    let _ = nix::sys::termios::tcsetattr(
        tty_fd,
        nix::sys::termios::SetArg::TCSANOW,
        &termios_orig
    );
    
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

fn remove_directory_recursive(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            
            if path.is_dir() {
                remove_directory_recursive(&path)?;
            } else {
                fs::remove_file(&path)?;
            }
        }
        fs::remove_dir(path)?;
    } else {
        fs::remove_file(path)?;
    }
    
    Ok(())
}

fn is_directory_empty(path: &Path) -> Result<bool> {
    if !path.is_dir() {
        return Ok(false);
    }
    
    let mut count = 0;
    for entry in fs::read_dir(path)? {
        let _ = entry?;
        count += 1;
        if count > 0 {
            break;
        }
    }
    
    Ok(count == 0)
}

fn init_system() -> Result<()> {
    let data_dir = Path::new("/System/Data/Users");
    create_directory_recursive(data_dir)?;
    
    let mut need_init = false;
    
    if !Path::new(USERS_FILE).exists() {
        let empty_users = UsersFile { users: Vec::new() };
        save_users(&empty_users)?;
        need_init = true;
    }
    
    if !Path::new(AUTH_FILE).exists() {
        let empty_auth = AuthFile {
            users: HashMap::new(),
        };
        save_auth(&empty_auth)?;
        need_init = true;
    }
    
    if !Path::new(GROUPS_FILE).exists() {
        let empty_groups = GroupsFile { groups: Vec::new() };
        save_groups(&empty_groups)?;
        need_init = true;
    }
    
    if need_init && !user_exists("admin")? {
        let hash = generate_hash("admin")?;
        
        let mut users_file = load_users()?;
        users_file.users.push(User {
            user_name: "admin".to_string(),
            full_name: "admin root superuser".to_string(),
            user_age: 9999,
            user_profile_picture: "None".to_string(),
            home_path: "/Home/Admin".to_string(),
            default_shell: SHELL_PATH.to_string(),
            uid: 0,
            gid: 0,
        });
        save_users(&users_file)?;
        
        let mut auth_file = load_auth()?;
        auth_file.users.insert("admin".to_string(), hash);
        save_auth(&auth_file)?;
        
        let mut groups_file = load_groups()?;
        groups_file.groups.push(Group {
            group_name: "admin".to_string(),
            full_name: "group FUCKING administrators".to_string(),
            default_shell: SHELL_PATH.to_string(),
            gid: 0,
        });
        save_groups(&groups_file)?;
        
        let admin_home = Path::new("/Home/Admin");
        if ensure_directory(admin_home).is_ok() {
            let _ = unistd::chown(admin_home, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)));
            let _ = fs::set_permissions(admin_home, fs::Permissions::from_mode(0o700));
        }
        
        println!("The system is initialized. The user admin has been created (password: admin)");
    }
    
    Ok(())
}

fn add_user(username: &str) -> Result<()> {
    if !Path::new(USERS_FILE).exists() || !Path::new(AUTH_FILE).exists() {
        println!("No configuration files were found. Initialization is underway...");
        init_system()?;
    }
    
    if user_exists(username)? {
        return Err(UserError::UserExists(username.to_string()));
    }
    
    print!("Enter full name: ");
    io::stdout().flush()?;
    let mut full_name = String::new();
    io::stdin().read_line(&mut full_name)?;
    let full_name = full_name.trim().to_string();
    
    print!("Enter age: ");
    io::stdout().flush()?;
    let mut age_input = String::new();
    io::stdin().read_line(&mut age_input)?;
    let user_age: u32 = age_input.trim().parse().unwrap_or(0);
    
    let password = read_password("Enter the password: ")?;
    let password2 = read_password("Confirm the password: ")?;
    
    if password != password2 {
        return Err(UserError::WrongPassword);
    }
    
    let hash = generate_hash(&password)?;
    let uid = get_next_uid()?;
    let gid = uid;
    
    let mut users_file = load_users()?;
    users_file.users.push(User {
        user_name: username.to_string(),
        full_name,
        user_age,
        user_profile_picture: "None".to_string(),
        home_path: format!("{}/{}", HOME_BASE, username),
        default_shell: SHELL_PATH.to_string(),
        uid,
        gid,
    });
    save_users(&users_file)?;
    
    let mut auth_file = load_auth()?;
    auth_file.users.insert(username.to_string(), hash);
    save_auth(&auth_file)?;
    
    let mut groups_file = load_groups()?;
    groups_file.groups.push(Group {
        group_name: username.to_string(),
        full_name: format!("group {}", username),
        default_shell: SHELL_PATH.to_string(),
        gid,
    });
    save_groups(&groups_file)?;
    
    let homedir = PathBuf::from(HOME_BASE).join(username);
    ensure_directory(&homedir)?;
    
    let _ = unistd::chown(&homedir, Some(Uid::from_raw(uid)), Some(Gid::from_raw(gid)));
    let _ = fs::set_permissions(&homedir, fs::Permissions::from_mode(0o755));
    
    println!("User '{}' has been successfully created (UID: {})", username, uid);
    Ok(())
}

fn change_password(username: &str) -> Result<()> {
    if !Path::new(AUTH_FILE).exists() {
        println!("No configuration files were found. Initialization is underway...");
        init_system()?;
    }
    
    if !user_exists(username)? {
        return Err(UserError::UserNotFound(username.to_string()));
    }
    
    let current_uid = unistd::getuid().as_raw();
    
    if current_uid != 0 {
        let old_password = read_password("Enter your current password: ")?;
        
        let hash = get_user_hash(username)?
            .ok_or(UserError::UserNotFound(username.to_string()))?;
        
        if !verify_password(&old_password, &hash) {
            return Err(UserError::WrongPassword);
        }
    }
    
    let password = read_password("Enter a new password: ")?;
    let password2 = read_password("Confirm the new password: ")?;
    
    if password != password2 {
        return Err(UserError::WrongPassword);
    }
    
    let new_hash = generate_hash(&password)?;
    
    let mut auth_file = load_auth()?;
    auth_file.users.insert(username.to_string(), new_hash);
    save_auth(&auth_file)?;
    
    println!("The password for the user '{}' has been successfully changed", username);
    Ok(())
}

fn delete_user(username: &str) -> Result<()> {
    if !Path::new(USERS_FILE).exists() {
        return Err(UserError::AccessDenied("Configuration files not found".to_string()));
    }
    
    if !user_exists(username)? {
        return Err(UserError::UserNotFound(username.to_string()));
    }
    
    if username == "admin" {
        return Err(UserError::AdminDelete);
    }
    
    let mut users_file = load_users()?;
    users_file.users.retain(|u| u.user_name != username);
    save_users(&users_file)?;
    
    let mut auth_file = load_auth()?;
    auth_file.users.remove(username);
    save_auth(&auth_file)?;
    
    let mut groups_file = load_groups()?;
    groups_file.groups.retain(|g| g.group_name != username);
    save_groups(&groups_file)?;
    
    let homedir = PathBuf::from(HOME_BASE).join(username);
    
    if homedir.exists() {
        if is_directory_empty(&homedir)? {
            fs::remove_dir(&homedir)?;
        } else {
            print!("The home directory is not empty. Delete it? (yes/no): ");
            io::stdout().flush()?;
            
            let mut response = String::new();
            io::stdin().read_line(&mut response)?;
            
            if response.trim() == "yes" {
                remove_directory_recursive(&homedir)?;
            }
        }
    }
    
    println!("User '{}' has been successfully deleted", username);
    Ok(())
}

fn modify_user(username: &str) -> Result<()> {
    let mut users_file = load_users()?;
    
    let user_index = users_file
        .users
        .iter()
        .position(|u| u.user_name == username)
        .ok_or_else(|| UserError::UserNotFound(username.to_string()))?;
    
    println!("\nModify user '{}'. Leave empty to keep current value.\n", username);
    
    // Клонируем текущие значения для отображения
    let current_full_name = users_file.users[user_index].full_name.clone();
    let current_age = users_file.users[user_index].user_age;
    let current_profile_pic = users_file.users[user_index].user_profile_picture.clone();
    let current_shell = users_file.users[user_index].default_shell.clone();
    
    print!("Full name [{}]: ", current_full_name);
    io::stdout().flush()?;
    let mut full_name = String::new();
    io::stdin().read_line(&mut full_name)?;
    let full_name = full_name.trim();
    if !full_name.is_empty() {
        users_file.users[user_index].full_name = full_name.to_string();
    }
    
    print!("Age [{}]: ", current_age);
    io::stdout().flush()?;
    let mut age_input = String::new();
    io::stdin().read_line(&mut age_input)?;
    let age_input = age_input.trim();
    if !age_input.is_empty() {
        if let Ok(age) = age_input.parse::<u32>() {
            users_file.users[user_index].user_age = age;
        }
    }
    
    print!("Profile picture path [{}]: ", current_profile_pic);
    io::stdout().flush()?;
    let mut profile_pic = String::new();
    io::stdin().read_line(&mut profile_pic)?;
    let profile_pic = profile_pic.trim();
    if !profile_pic.is_empty() {
        users_file.users[user_index].user_profile_picture = profile_pic.to_string();
    }
    
    print!("Default shell [{}]: ", current_shell);
    io::stdout().flush()?;
    let mut shell = String::new();
    io::stdin().read_line(&mut shell)?;
    let shell = shell.trim();
    if !shell.is_empty() {
        users_file.users[user_index].default_shell = shell.to_string();
    }
    
    save_users(&users_file)?;
    
    println!("\nUser '{}' has been successfully modified", username);
    Ok(())
}

fn list_users() -> Result<()> {
    let users_file = load_users()
        .map_err(|_| UserError::AccessDenied("Couldn't open the users file".to_string()))?;
    
    println!("{:<16} {:<8} {:<8} {:<32} {:<24}", "USERNAME", "UID", "GID", "FULL NAME", "HOME");
    println!("{}", "-".repeat(100));
    
    for user in &users_file.users {
        println!(
            "{:<16} {:<8} {:<8} {:<32} {:<24}",
            user.user_name, user.uid, user.gid, user.full_name, user.home_path
        );
    }
    
    Ok(())
}

fn list_groups() -> Result<()> {
    let groups_file = load_groups()
        .map_err(|_| UserError::AccessDenied("Couldn't open the groups file".to_string()))?;
    
    println!("{:<16} {:<8} {:<32}", "GROUP NAME", "GID", "FULL NAME");
    println!("{}", "-".repeat(60));
    
    for group in &groups_file.groups {
        println!(
            "{:<16} {:<8} {:<32}",
            group.group_name, group.gid, group.full_name
        );
    }
    
    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    if args.len() < 2 {
        print_usage(&args[0]);
        std::process::exit(1);
    }
    
    let result = match args[1].as_str() {
        "--init" => init_system(),
        "--add" => {
            if args.len() < 3 {
                eprintln!("Error: the user's name is not specified");
                std::process::exit(1);
            }
            add_user(&args[2])
        }
        "--password" => {
            if args.len() < 3 {
                eprintln!("Error: the user's name is not specified");
                std::process::exit(1);
            }
            change_password(&args[2])
        }
        "--delete" => {
            if args.len() < 3 {
                eprintln!("Error: the user's name is not specified");
                std::process::exit(1);
            }
            delete_user(&args[2])
        }
        "--modify" => {
            if args.len() < 3 {
                eprintln!("Error: the user's name is not specified");
                std::process::exit(1);
            }
            modify_user(&args[2])
        }
        "--list" => list_users(),
        "--list-groups" => list_groups(),
        _ => {
            eprintln!("Error: Unknown option '{}'", args[1]);
            print_usage(&args[0]);
            std::process::exit(1);
        }
    };
    
    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}