
use argon2::{self, Config};
use rusqlite::{Connection, NO_PARAMS, params};
use rand::prelude::*;
use rand::{self, Rng, SeedableRng, CryptoRng};
use rand_chacha;
use rand_chacha::ChaChaRng;
use std::env;
#[derive(Debug)]
pub struct UserAccount {}

//struct Salt([u8;32]);

static AUTH_DB: &'static str = "AUTH_DB";

impl UserAccount {
    fn get_conn() -> Result<Connection, rusqlite::Error> {

        let db_path = env::var(AUTH_DB).unwrap();
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
    pub fn verify(name: &str, pwd: &str) -> Result<bool, rusqlite::Error> {
        let conn = UserAccount::get_conn().unwrap();

        let cur_pwd = conn.query_row("select password from users where name=?", params![name], |row| {
            let p: String = row.get(0)?;
            Ok(p)
        })?;

        //println!("current {:?}", cur_pwd);

        Ok(argon2::verify_encoded(&cur_pwd, pwd.as_bytes()).expect("Could not verify account"))
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

