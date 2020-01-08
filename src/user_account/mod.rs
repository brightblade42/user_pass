use argon2::{self, Config};
use rusqlite::{Connection, NO_PARAMS, params};
use rand::prelude::*;
use rand::{self, Rng, SeedableRng, CryptoRng};
use rand_chacha;
use rand_chacha::ChaChaRng;
use std::env;
///Interacts with a sqlite database to manage a set of user accounts.
///Provides simple static methods to create,delete, update users and
/// ensure all passwords are hashed+salted.
///
#[derive(Debug)]
pub struct UserAccount {}

//struct Salt([u8;32]);
///Currently an environment variable called AUTH_DB containing a path to a sqlite db
///is needed. Boo.
pub static AUTH_DB: &'static str = "AUTH_DB";

impl UserAccount {
    ///takes a user name, checks if it exists and returns Result<bool, Error>.
    /// ```
    /// use user_pass::user_account::UserAccount;
    ///
    /// let name = "han_solo";
    /// match UserAccount::exists(name) {
    ///     Ok(exists) => {
    ///         if exists { println!("{} exists", name); }
    ///         else  { println!("{} does NOT exist", name); }
    ///     },
    ///     Err(e) => {
    ///         println!("There was a problem accessing the data: {:?}",e);
    ///     }
    /// }
    ///
    /// ```
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

    ///takes a name and password (plain text), hashes and salts the password
    /// and saves them to the db.
    /// User names must be unique.
    /// Passwords are never saved in plain text and can't be recovered.
    ///
    /// Returns true if save was successful, false if user already exists.
    /// ```
    /// use user_pass::user_account::UserAccount;
    ///
    /// let name = "han_solo";
    /// let pwd = "chewy";
    /// let is_saved = UserAccount::save(name, pwd);
    /// if is_saved {
    ///     println!("{} was saved.", name);
    ///
    ///     assert!(is_saved);
    /// }
    /// else {
    ///     println!("{} was saved.", name);
    ///     assert!(!is_saved);
    /// }
    /// ```
    pub fn save(name: &str, password: &str) -> bool {
        if UserAccount::exists(name).unwrap() { return false; }

        let (hash, salt) = UserAccount::hash_password(password, None);

        let conn = UserAccount::get_conn().unwrap();
        conn.execute(&format!("Insert into users (name, password, salt, active) VALUES (?,?,?,?)"), params![name, hash, salt.to_vec(),true]);

        true
    }

    ///takes a name and deletes the account if it exists.
    /// returns true if account was deleted and false if account doesn't exist
    /// ```
    /// use user_pass::user_account::UserAccount;
    ///
    /// let name = "han_solo";
    /// let is_deleted = UserAccount::delete(name).expect("could not delete account");
    /// if is_deleted {
    ///     assert!(is_deleted);
    /// } else {
    ///     assert!(!is_deleted);
    /// }
    ///
    /// ```
    ///
    pub fn delete(name: &str) -> Result<bool, rusqlite::Error> {

        if !UserAccount::exists(name).unwrap() { return Ok(false); }
        let conn = UserAccount::get_conn().unwrap();
        let delete_count = conn.execute(&format!("Delete from users where name=?"), params![name])?;

        match delete_count {
            0 => Ok(false),
            _ => Ok(true)
        }
    }
    ///takes an existing user name and resets its password with the new one.
    ///returns true if succeeded, false if account doesn't exist in which case
    ///there's nothing update and you should use save.
    /// ```
    /// use user_pass::user_account::UserAccount;
    ///
    /// let name = "han_solo";
    /// let password = "chewbacca";
    /// let is_reset = UserAccount::reset_password(name, password);
    /// if is_reset {
    ///     assert!(is_reset);
    /// } else {
    ///     assert!(!is_reset);
    /// }
    ///
    pub fn reset_password(name: &str, new_password: &str) -> bool {
        if !UserAccount::exists(name).unwrap() { return false; }

        let (hash, salt) = UserAccount::hash_password(new_password, None);

        let conn = UserAccount::get_conn().expect("Could not get db connection");
        conn.execute(&format!("Update users set password=?, salt=? where name=?"), params![hash,salt.to_vec(),name]);

        true
    }


    ///compares the provided password against the users stored hashed password.
    ///returns true if password is correct, otherwise false.
    /// ```
    /// use user_pass::user_account::UserAccount;
    ///
    /// let name = "han_solo";
    /// let password = "chewbacca";
    ///
    /// match UserAccount::verify(name, password) {
    ///     Ok(is_verified) => {
    ///         println!("Account is verified");
    ///         if is_verified {
    ///             assert!(is_verified);
    ///         } else {
    ///             assert!(!is_verified);
    ///         }
    ///     },
    ///     Err(e) => {
    ///         println!("There was a problem accessing auth db: {}", e);
    ///     }
    /// }
    ///
    ///
    /// ```
    pub fn verify(name: &str, pwd: &str) -> Result<bool, rusqlite::Error> {
        let conn = UserAccount::get_conn().unwrap();

        let cur_pwd = conn.query_row("select password from users where name=?", params![name], |row| {
            let p: String = row.get(0)?;
            Ok(p)
        })?;

        //println!("current {:?}", cur_pwd);

        Ok(argon2::verify_encoded(&cur_pwd, pwd.as_bytes()).expect("Could not verify account"))
    }

    ///takes a name and checks if the user is active. returns true if it is and false if it ain't.
    /// ```
    /// use user_pass::user_account::UserAccount;
    ///
    /// let name = "han_solo";
    /// let password = "chewbacca";
    ///
    /// let is_active = UserAccount::is_active(name);
    /// ```
    pub fn is_active(name: &str) -> bool {
        let conn = UserAccount::get_conn().unwrap();
        let is_active = conn.query_row("Select active from users where name=?", params![name], |row| {
            let is_active: bool = row.get(0).unwrap_or_else(|_| { false });
            Ok(is_active)
        });

        is_active.unwrap_or_else(|_| { false })
    }

    ///takes a name and updates the account's active status. This is how you enable and disable
    ///an account
    pub fn update_active_state(name: &str, is_active: bool) -> bool {
        let conn = UserAccount::get_conn().unwrap();
        let res = conn.execute("Update users set active=? where name=?", params![is_active, name]);
        let res = res.unwrap_or_else(|_| { 0 });
        if res > 0 { true } else { false }
    }

    ///returns a sqlite database connection.
    fn get_conn() -> Result<Connection, rusqlite::Error> {

        let db_path = env::var(AUTH_DB).unwrap();
        Connection::open(db_path)
    }

    ///Takes your probable weak password, salts and hashes it into something more secure.
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

    ///generate a salt array from a random seed.
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn step_through_account_process() {

        UserAccount::delete("sexy_tomato");
        let name = "sexy_tomato";
        let pass = "grapenuts";

        assert!(UserAccount::save(name, pass));

        match UserAccount::exists(name) {
            Ok(exists) => {

                let is_verified = UserAccount::verify(name, pass).unwrap_or_else(|_| {
                    panic!("could not access account to verify");
                });

                assert!(is_verified); //we just made it so it better be there.

            },
            Err(e) => {
                panic!("The account we just made doesn't exist!");
            }

        }

        assert!(UserAccount::is_active(name));
        assert!(UserAccount::update_active_state(name, false));
        assert!(!UserAccount::is_active(name));
        assert!(UserAccount::update_active_state(name, true));
        assert!(UserAccount::is_active(name));

        UserAccount::delete("sexy_tomato");
    }


}


