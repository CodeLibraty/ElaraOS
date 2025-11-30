use std::fs::{self, File, Metadata};
use std::io::{self, BufRead, BufReader};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process;

const PASSWD_FILE: &str = "/System/Configs/Users/passwd";
const GROUP_FILE: &str = "/System/Configs/Users/group";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct UserInfo {
    name: String,
    uid: u32,
}

#[derive(Debug)]
struct GroupInfo {
    name: String,
    gid: u32,
}

struct UserDatabase {
    users: Vec<UserInfo>,
}

impl UserDatabase {
    fn load() -> Result<Self> {
        let file = File::open(PASSWD_FILE)?;
        let reader = BufReader::new(file);
        let mut users = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if let Some(user) = Self::parse_passwd_line(&line) {
                users.push(user);
            }
        }

        Ok(Self { users })
    }

    fn parse_passwd_line(line: &str) -> Option<UserInfo> {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            let name = parts[0].to_string();
            let uid = parts[2].parse().ok()?;
            Some(UserInfo { name, uid })
        } else {
            None
        }
    }

    fn get_username(&self, uid: u32) -> String {
        self.users
            .iter()
            .find(|u| u.uid == uid)
            .map(|u| u.name.clone())
            .unwrap_or_else(|| uid.to_string())
    }

    fn get_uid(&self, username: &str) -> Option<u32> {
        self.users
            .iter()
            .find(|u| u.name == username)
            .map(|u| u.uid)
            .or_else(|| username.parse().ok())
    }
}

struct GroupDatabase {
    groups: Vec<GroupInfo>,
}

impl GroupDatabase {
    fn load() -> Result<Self> {
        let file = File::open(GROUP_FILE)?;
        let reader = BufReader::new(file);
        let mut groups = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if let Some(group) = Self::parse_group_line(&line) {
                groups.push(group);
            }
        }

        Ok(Self { groups })
    }

    fn parse_group_line(line: &str) -> Option<GroupInfo> {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() >= 3 {
            let name = parts[0].to_string();
            let gid = parts[2].parse().ok()?;
            Some(GroupInfo { name, gid })
        } else {
            None
        }
    }

    fn get_groupname(&self, gid: u32) -> String {
        self.groups
            .iter()
            .find(|g| g.gid == gid)
            .map(|g| g.name.clone())
            .unwrap_or_else(|| gid.to_string())
    }

    fn get_gid(&self, groupname: &str) -> Option<u32> {
        self.groups
            .iter()
            .find(|g| g.name == groupname)
            .map(|g| g.gid)
            .or_else(|| groupname.parse().ok())
    }
}

#[derive(Debug)]
enum Mode {
    Numeric(u32),           // "755"
    Symbolic(String),       // "rwxr-xr--"
    Descriptive(String),    // "owner:read-write,group:read,other:read"
}

impl Mode {
    fn parse(s: &str) -> Result<Self> {
        let s = s.trim();

        // 1. Числовой (восьмеричный)
        if let Ok(val) = u32::from_str_radix(s, 8) {
            if val <= 0o7777 {
                return Ok(Mode::Numeric(val));
            }
        }

        // 2. Символьный (rwx...)
        if s.len() == 9 && s.chars().all(|c| matches!(c, 'r' | 'w' | 'x' | '-')) {
            return Ok(Mode::Symbolic(s.to_string()));
        }

        // 3. Описательный (owner:read-write,...)
        if s.contains(':') && (s.contains("read") || s.contains("write") || s.contains("exec")) {
            return Ok(Mode::Descriptive(s.to_string()));
        }

        Err("Invalid mode format. Use numeric (755), symbolic (rwxr-xr--), or descriptive (owner:read-write,group:read,other:read)".into())
    }

    fn to_permissions(&self) -> u32 {
        match self {
            Mode::Numeric(val) => *val,
            Mode::Symbolic(s) => Self::symbolic_to_numeric(s),
            Mode::Descriptive(s) => Self::descriptive_to_numeric(s)
                .unwrap_or_else(|e| {
                    eprintln!("Warning: failed to parse descriptive mode: {}", e);
                    0o644 // fallback
                }),
        }
    }

    fn descriptive_to_numeric(desc: &str) -> Result<u32> {
        let mut mode = 0u32;

        for part in desc.split(',') {
            let part = part.trim();
            if part.is_empty() { continue; }

            let (target, perms) = part
                .split_once(':')
                .ok_or("Invalid descriptive format: expected 'target:perms'")?;

            let perms = perms.trim();
            let bits = Self::perms_to_bits(perms)?;

            match target.trim().to_lowercase().as_str() {
                "owner" | "user" => mode |= (bits as u32) << 6,
                "group" => mode |= (bits as u32) << 3,
                "other" | "others" => mode |= bits as u32,
                _ => return Err(format!("Unknown target: '{}'. Use 'owner', 'group', 'other'", target).into()),
            }
        }

        Ok(mode)
    }

    fn perms_to_bits(perms: &str) -> Result<u8> {
        let mut bits = 0u8;
        let perms_lower = perms.to_lowercase();

        if perms_lower.contains("read") {
            bits |= 0o4;
        }
        if perms_lower.contains("write") {
            bits |= 0o2;
        }
        if perms_lower.contains("exec") || perms_lower.contains("execute") {
            bits |= 0o1;
        }

        // Проверка на недопустимые слова
        let valid_tokens = ["read", "write", "exec", "execute"];
        for token in perms_lower.split(|c: char| !c.is_alphabetic()) {
            if !token.is_empty() && !valid_tokens.iter().any(|&v| token == v) {
                return Err(format!("Unknown permission: '{}'. Use 'read', 'write', 'exec'", token).into());
            }
        }

        Ok(bits)
    }

    fn symbolic_to_numeric(s: &str) -> u32 {
        let chars: Vec<char> = s.chars().collect();
        let mut mode = 0u32;

        // Owner
        if chars[0] == 'r' { mode |= 0o400; }
        if chars[1] == 'w' { mode |= 0o200; }
        if chars[2] == 'x' { mode |= 0o100; }

        // Group
        if chars[3] == 'r' { mode |= 0o040; }
        if chars[4] == 'w' { mode |= 0o020; }
        if chars[5] == 'x' { mode |= 0o010; }

        // Others
        if chars[6] == 'r' { mode |= 0o004; }
        if chars[7] == 'w' { mode |= 0o002; }
        if chars[8] == 'x' { mode |= 0o001; }

        mode
    }
}

trait Command {
    fn execute(&self, args: &[String]) -> Result<()>;
    fn name(&self) -> &'static str;
    fn help(&self) -> &'static str;
}

struct ChmodCommand;

impl Command for ChmodCommand {
    fn name(&self) -> &'static str { "permission" }
    
    fn help(&self) -> &'static str {
        "Usage: change permission <mode> <file>\n  Change file permissions"
    }

    fn execute(&self, args: &[String]) -> Result<()> {
        if args.len() != 2 {
            return Err("Usage: change permission <mode> <file>".into());
        }

        let mode = Mode::parse(&args[0])?;
        let path = Path::new(&args[1]);
        
        let permissions = std::fs::Permissions::from_mode(mode.to_permissions());
        fs::set_permissions(path, permissions)?;
        
        println!("Changed permissions of '{}' to {:o}", args[1], mode.to_permissions());
        Ok(())
    }
}

struct ChownCommand {
    user_db: UserDatabase,
}

impl Command for ChownCommand {
    fn name(&self) -> &'static str { "owner" }
    
    fn help(&self) -> &'static str {
        "Usage: change owner <user> <file>\n  Change file owner"
    }

    fn execute(&self, args: &[String]) -> Result<()> {
        if args.len() != 2 {
            return Err("Usage: change owner <user> <file>".into());
        }

        let uid = self.user_db.get_uid(&args[0])
            .ok_or_else(|| format!("User '{}' not found", args[0]))?;
        
        let path = Path::new(&args[1]);
        let metadata = fs::metadata(path)?;
        let gid = metadata.gid();

        nix::unistd::chown(path, Some(nix::unistd::Uid::from_raw(uid)), 
                          Some(nix::unistd::Gid::from_raw(gid)))?;
        
        println!("Changed owner of '{}' to {}", args[1], args[0]);
        Ok(())
    }
}

struct ChangeGroupCommand {
    group_db: GroupDatabase,
}

impl Command for ChangeGroupCommand {
    fn name(&self) -> &'static str { "group" }
    
    fn help(&self) -> &'static str {
        "Usage: change group <group> <file>\n  Change file group"
    }

    fn execute(&self, args: &[String]) -> Result<()> {
        if args.len() != 2 {
            return Err("Usage: change group <group> <file>".into());
        }

        let gid = self.group_db.get_gid(&args[0])
            .ok_or_else(|| format!("Group '{}' not found", args[0]))?;
        
        let path = Path::new(&args[1]);
        let metadata = fs::metadata(path)?;
        let uid = metadata.uid();

        nix::unistd::chown(path, Some(nix::unistd::Uid::from_raw(uid)), 
                          Some(nix::unistd::Gid::from_raw(gid)))?;
        
        println!("Changed group of '{}' to {}", args[1], args[0]);
        Ok(())
    }
}

struct LsCommand {
    user_db: UserDatabase,
    group_db: GroupDatabase,
}

impl Command for LsCommand {
    fn name(&self) -> &'static str { "ls" }
    
    fn help(&self) -> &'static str {
        "Usage: change ls <path>\n  List file information"
    }

    fn execute(&self, args: &[String]) -> Result<()> {
        if args.is_empty() {
            return Err("Usage: change ls <path>".into());
        }

        let path = Path::new(&args[0]);
        let metadata = fs::metadata(path)?;
        
        let mode = metadata.permissions().mode();
        let uid = metadata.uid();
        let gid = metadata.gid();
        let size = metadata.len();
        
        let username = self.user_db.get_username(uid);
        let groupname = self.group_db.get_groupname(gid);
        
        println!("{} {} {} {} {}", 
                 Self::format_permissions(mode),
                 username,
                 groupname,
                 size,
                 args[0]);
        
        Ok(())
    }
}

impl LsCommand {
    fn format_permissions(mode: u32) -> String {
        let mut perms = String::with_capacity(10);
        
        perms.push(if metadata_is_dir(mode) { 'd' } else { '-' });
        perms.push(if mode & 0o400 != 0 { 'r' } else { '-' });
        perms.push(if mode & 0o200 != 0 { 'w' } else { '-' });
        perms.push(if mode & 0o100 != 0 { 'x' } else { '-' });
        perms.push(if mode & 0o040 != 0 { 'r' } else { '-' });
        perms.push(if mode & 0o020 != 0 { 'w' } else { '-' });
        perms.push(if mode & 0o010 != 0 { 'x' } else { '-' });
        perms.push(if mode & 0o004 != 0 { 'r' } else { '-' });
        perms.push(if mode & 0o002 != 0 { 'w' } else { '-' });
        perms.push(if mode & 0o001 != 0 { 'x' } else { '-' });
        
        perms
    }
}

fn metadata_is_dir(mode: u32) -> bool {
    mode & 0o170000 == 0o040000
}

struct Application {
    commands: Vec<Box<dyn Command>>,
}

impl Application {
    fn new() -> Result<Self> {
        let user_db = UserDatabase::load()?;
        let group_db = GroupDatabase::load()?;

        let commands: Vec<Box<dyn Command>> = vec![
            Box::new(ChmodCommand),
            Box::new(ChownCommand { user_db: UserDatabase::load()? }),
            Box::new(ChangeGroupCommand { group_db: GroupDatabase::load()? }),
            Box::new(LsCommand { 
                user_db: UserDatabase::load()?, 
                group_db: GroupDatabase::load()? 
            }),
        ];

        Ok(Self { commands })
    }

    fn run(&self, args: Vec<String>) -> Result<()> {
        if args.len() < 2 {
            self.print_usage();
            return Ok(());
        }

        let cmd_name = &args[1];
        let cmd_args = &args[2..];

        for command in &self.commands {
            if command.name() == cmd_name {
                return command.execute(cmd_args);
            }
        }

        eprintln!("Unknown command: {}", cmd_name);
        self.print_usage();
        Err("Invalid command".into())
    }

    fn print_usage(&self) {
        println!("Elara Change Utility");
        println!("\nAvailable commands:");
        for command in &self.commands {
            println!("  {}", command.help());
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    
    let app = match Application::new() {
        Ok(app) => app,
        Err(e) => {
            eprintln!("Failed to initialize application: {}", e);
            process::exit(1);
        }
    };

    if let Err(e) = app.run(args) {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
