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


#[derive(Debug, StructOpt)]
#[structopt(name = "userpass", about = "a simple tool to create and update users and passwords. Passwords are hashed and salted")]
enum SearchAuth {
    Add {
        #[structopt(long = "user", short = "u")]
        user: String,
        #[structopt(long = "pass", short = "p")]
        pass: String,
        #[structopt(long = "salt", short = "s")]
        salt: String,

    },
    Update {
        #[structopt(long = "user", short = "u")]
        user: String,
        #[structopt(long = "pass", short = "p")]
        pass: String,
    },
    Verify {
        #[structopt(long = "user", short = "u")]
        user: String,
        #[structopt(long = "pass", short = "p")]
        pass: String,

    },
    IsActive {
        #[structopt(long = "user", short = "u")]
        user: String,
    },
    Enable {
        #[structopt(long = "user", short = "u")]
        user: String,
    },
    Disable {
        #[structopt(long = "user", short = "u")]
        user: String,
    },
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

    pub fn reset_password(name: &str, new_password: &str) -> bool {
        if !UserAccount::exists(name).unwrap() { return false; }

        let (hash, salt) = UserAccount::hash_password(new_password, None);

        let conn = UserAccount::get_conn().expect("Could not get db connection");
        conn.execute(&format!("Update users set password=?, salt=? where name=?"), params![hash,salt.to_vec(),name]);

        true
    }

    ///Takes your weak ass password then salts and hashes it into something secure.
    ///Returns a tuple containing the hash and the generated salt array.
    pub fn hash_password(pwd: &str, salt: Option<&[u8; 32]>) -> (String, [u8; 32]) {
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

        is_active.unwrap()
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

    let mut opt: SearchAuth = SearchAuth::from_args();

    match opt.borrow_mut() {
        SearchAuth::Add { user, pass, salt } => {
            println!("You want to add something, Cool brah");
            let did_work = UserAccount::save(user, pass);
            if did_work {
                println!("Good work buddy");
            } else {
                println!("no mass");
            }
        }
        SearchAuth::Update { user, pass } => {
            println!("You want to update something");
            let did_work = UserAccount::reset_password(user, pass);
            if did_work {
                println!("Good work buddy");
            } else {
                println!("no mass");
            }
        }
        SearchAuth::Verify { user, pass } => {
            println!("You want to verify your password brah? Noice.");
            let did_work = UserAccount::verify(user, pass);
            if did_work {
                println!("Bro, noice yo verified!");
            } else {
                println!("not cool brah, you wanna piece of me?!");
            }
        }
        SearchAuth::IsActive { user } => {
            println!("You wanna be active bro?");
            let is_active = UserAccount::is_active(user);
            if is_active { println!("Good news! You are active"); }
            else { println!("Bro, do you even work out?"); }
        }
        SearchAuth::Enable { user } => {
            UserAccount::update_active_state(user, true);
            println!("Noice! Account enabled");
        }
        SearchAuth::Disable { user } => {
            UserAccount::update_active_state(user, false);
            println!("Sorry bro, Account disabled");
        }
    }

    /*
            let test_seed = [
                0, 1, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7,
                0, 0, 0,
            ];
    */
}
