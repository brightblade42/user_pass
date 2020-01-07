use structopt::StructOpt;
use std::thread;
use std::time::Duration;
use std::env;
use std::fs;
use indicatif::{ProgressBar, ProgressStyle};
use console::{self, style };
use std::borrow::{BorrowMut, Borrow};
use user_pass::user_account::{UserAccount};

#[derive(Debug, StructOpt)]
#[structopt(name = "userpass",
about = "a simple tool to create and update users and passwords. Passwords are hashed and salted",
author="ryan lee martin",
after_help = "Have a great day!")]
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


fn main() {
    //env::set_var("AUTH_DB", "/media/d-rezzer/data/dev/eyemetric/sex_offender/app/auth.db");

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
            match UserAccount::verify(user, pass) {
                Ok(verified) => {
                    if verified {
                        pb.finish_with_message(&format!("{} password is verified", style(user).cyan()));
                    } else {
                        pb.finish_with_message(&format!("Password {} for {} is incorrect!", style(pass).cyan(), style(user).cyan()));
                    }
                },
                Err(e) => {
                    pb.finish_with_message(&format!("Account for {} not found. Are you sure it exists?", style(user).cyan()));
                }
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
                    } else {
                        pb.finish_with_message(&format!("Could not find account for {}", user));
                    }
                },
                Err(e) => {
                    println!("Couldn't perform delete: {}", e);
                }
            }
        }
    }
}
