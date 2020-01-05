use structopt::StructOpt;
use argon2::{self, Config};
use rusqlite::{Connection, NO_PARAMS, params};
use std::env;
use std::fs;
use std::borrow::{BorrowMut, Borrow};
use rand::prelude::*;
use rand::{self, Rng, SeedableRng, CryptoRng};
use rand_chacha;
use rand_chacha::ChaChaRng;
use std::thread;
use std::time::Duration;
use indicatif::{ProgressBar, ProgressStyle};
use console::{self, style };

#[derive(Debug, StructOpt)]
#[structopt(name = "userpass",
    about = "a simple tool to create and update users and passwords. Passwords are hashed and salted",
    author="ryan lee martin",
    after_help = "All hope is lost to all ye who enter")]
enum UserPass {
    ///Add a new user/password combination
    ///
    ///Passwords are hashed and salted with a random salt.
    ///Unique salts are generated for every user using the
    ///ChaCha 256bit cipher.
    Add {
        #[structopt(long = "user", short = "u")]
        user: String,
        #[structopt(long = "pass", short = "p")]
        pass: String,

    },
    ///update an existing user with a new password
    Update {
        #[structopt(long = "user", short = "u")]
        user: String,
        #[structopt(long = "pass", short = "p")]
        pass: String,
    },
    ///checks if you've entered the correct password for user.
    Verify {
        #[structopt(long = "user", short = "u")]
        user: String,
        #[structopt(long = "pass", short = "p")]
        pass: String,

    },
    ///checks to see if user has an active account.
    IsActive {
        #[structopt(long = "user", short = "u")]
        user: String,
    },
    //enables a user, if disabled.
    Enable {
        #[structopt(long = "user", short = "u")]
        user: String,
    },
    //disables a user, if enabled.
    Disable {
        #[structopt(long = "user", short = "u")]
        user: String,
    },
    Delete {
        #[structopt(long = "user", short = "u")]
        user: String,
    }
}

#[derive(Debug)]
pub struct UserAccount {}

//struct Salt([u8;32]);


impl UserAccount {
    fn get_conn() -> Result<Connection, rusqlite::Error> {
        let db_path = env::var("AUTH_DB").unwrap();
        Connection::open(db_path)
    }
    pub fn exists(name: &str) -> Result<bool, rusqlite::Error> {
        let conn = UserAccount::get_conn()?;

        let user_count = conn.query_row(&format!("Select count(*) from users where name = '{}'", name), NO_PARAMS,
                                        |row| {
                                            let x: i32 = row.get(0)?;
                                            Ok(x)
                                        })?;

        match user_count {
            0 => Ok(false),
            _ => Ok(true)
        }
    }

    pub fn save(name: &str, password: &str) -> bool {
        if UserAccount::exists(name).unwrap() { return false; }

        let (hash, salt) = UserAccount::hash_password(password, None);

        let conn = UserAccount::get_conn().unwrap();
        conn.execute(&format!("Insert into users (name, password, salt, active) VALUES (?,?,?,?)"), params![name, hash, salt.to_vec(),true]);

        true
    }

    pub fn delete(name: &str) -> Result<bool, rusqlite::Error> {

        if !UserAccount::exists(name).unwrap() { return Ok(false); }
        let conn = UserAccount::get_conn().unwrap();
        let delete_count = conn.execute(&format!("Delete from users where name=?"), params![name])?;

        match delete_count {
            0 => Ok(false),
            _ => Ok(true)
        }
    }
    pub fn reset_password(name: &str, new_password: &str) -> bool {
        if !UserAccount::exists(name).unwrap() { return false; }

        let (hash, salt) = UserAccount::hash_password(new_password, None);

        let conn = UserAccount::get_conn().expect("Could not get db connection");
        conn.execute(&format!("Update users set password=?, salt=? where name=?"), params![hash,salt.to_vec(),name]);

        true
    }

    ///Takes your weak ass password then salts and hashes it into something secure.
    ///Returns a tuple containing the hash and the generated salt array.
    fn hash_password(pwd: &str, salt: Option<&[u8; 32]>) -> (String, [u8; 32]) {
        let salted = match salt {
            None => UserAccount::gen_salt(),
            Some(s) => *s
        };

        let config = Config::default();
        let pwd = pwd.as_bytes();
        let hash = argon2::hash_encoded(&pwd, &salted, &config).unwrap();

        (hash, salted)
    }

    ///compares the provided password against the users stored password.
    ///returns true if password is correct, otherwise false.
    pub fn verify(name: &str, pwd: &str) -> bool {
        let conn = UserAccount::get_conn().unwrap();

        let cur_pwd = conn.query_row("select password from users where name=?", params![name], |row| {
            let p: String = row.get(0)?;
            Ok(p)
        });

        println!("current {:?}", cur_pwd);

        argon2::verify_encoded(&cur_pwd.unwrap(), pwd.as_bytes()).expect("Could not verify account")
    }

    pub fn is_active(name: &str) -> bool {
        let conn = UserAccount::get_conn().unwrap();
        let is_active = conn.query_row("Select active from users where name=?", params![name], |row| {
            let is_active: bool = row.get(0).unwrap_or_else(|_| { false });
            Ok(is_active)
        });

        is_active.unwrap_or_else(|_| { false })
    }

    pub fn update_active_state(name: &str, is_active: bool) -> bool {
        let conn = UserAccount::get_conn().unwrap();
        let res = conn.execute("Update users set active=? where name=?", params![is_active, name]);
        let res = res.unwrap_or_else(|_| { 0 });
        if res > 0 { true } else { false }
    }


    //generate a crytpo safe salt array
    fn gen_salt() -> [u8; 32] {

        //TODO: check if this run of the mill rando is ok for generating the seed value
        let mut seed = [0u8; 32];

        for i in seed.iter_mut() {
            *i = rand::random()
        }

        let mut rng = ChaChaRng::from_seed(seed);
        let mut salt_bytes = [0u8; 32];
        for i in salt_bytes.iter_mut() { *i = rng.gen(); }

        salt_bytes
    }
}


fn main() {
    env::set_var("AUTH_DB", "/media/d-rezzer/data/dev/eyemetric/sex_offender/app/auth.db");

    let mut opt: UserPass = UserPass::from_args();

    let pb = ProgressBar::new_spinner();
    pb.enable_steady_tick(120);
    pb.set_style(
        ProgressStyle::default_spinner()
            .tick_strings(&[
                "▹▹▹▹▹",
                "▸▹▹▹▹",
                "▹▸▹▹▹",
                "▹▹▸▹▹",
                "▹▹▹▸▹",
                "▹▹▹▹▸",
                "▪▪▪▪▪",
            ])
            .template("{spinner:.blue} {msg}"),

    );

    match opt.borrow_mut() {
        UserPass::Add { user, pass } => {

            pb.set_message("Creating account..");
            thread::sleep(Duration::from_millis(500)); //just to make it look like something is happening.
            if UserAccount::save(user, pass) {
                pb.finish_with_message("Done!");
            } else {
                pb.finish_with_message(&format!("{} already exists. Did you mean to use the update command?", user));
            }
        },
        UserPass::Update { user, pass } => {

            pb.set_message(&format!("Updating {}", user));

            if UserAccount::reset_password(user, pass) {
                pb.finish_with_message(&format!("{} password updated", style(user).cyan()));
            } else {
                pb.finish_with_message(&format!("could not find {} account. Did you mean to use the add command?", style(user).green()));
            }
        },
        UserPass::Verify { user, pass } => {
            if UserAccount::verify(user, pass) {
                pb.finish_with_message(&format!("{} password is verified", user));
            } else {
                pb.finish_with_message(&format!("Password {} for {} is incorrect!", pass, user));
            }
        },
        UserPass::IsActive { user } => {
           pb.set_message("Checking active status...");
            if UserAccount::is_active(user) {
                pb.finish_with_message(&format!("{} IS active", user));
            } else {
                pb.finish_with_message(&format!("{} is NOT active", user));
            }
        },
        UserPass::Enable { user } => {

            pb.set_message("Enabling account...");
            UserAccount::update_active_state(user, true);
            pb.finish_with_message(&format!("account for {} is enabled", user));
        },
        UserPass::Disable { user } => {
            pb.set_message("Disabling account...");
            UserAccount::update_active_state(user, false);
            pb.finish_with_message(&format!("account for {} is disabled", user));
        },
        UserPass::Delete { user } => {
            pb.set_message("Deleting account...");

            match UserAccount::delete(user) {
                Ok(deleted) => {
                    if deleted {
                        pb.finish_with_message(&format!("account for {} has been deleted.", user));
                    }

                    else {
                        pb.finish_with_message(&format!("Could not find account for {}", user));
                    }
                },
                Err(e) =>  {
                    println!("Couldn't perform delete: {}", e);
                }
            }


        }
    }

    /*
            let test_seed = [
                0, 1, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7,
                0, 0, 0,
            ];
    */
}
