use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};
use std::env;
use totp_lite::{totp_custom, Sha1, DEFAULT_STEP};
use base32::Alphabet::Rfc4648;

fn main() {
  let mut args = env::args().skip(1);
  let secret = match args.next() {
    Some(arg) => arg,
    None => input("Enter the secret")
  };

  let length = secret.len();
  if length != 16 && length != 26 && length != 32 {
    println!("Invalid secret");
    return
  }

  let decoded_secret = match base32::decode (
    Rfc4648 { padding: false },
    &secret.to_uppercase()
  ) {
    Some(decoded) => decoded,
    None => {
      println!("Failed to decode secret");
      return
    }
  };

  let seconds: u64 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
  let result = totp_custom::<Sha1>(DEFAULT_STEP, 6, &decoded_secret, seconds);
  println!("{}", result);
}

fn input(prompt: &str) -> String {
  print!("{}: ", prompt);
  io::stdout().flush().unwrap();
  let mut buf = String::new();
  io::stdin().read_line(&mut buf).expect("Failed to read input");
  buf.trim().to_string()
}
