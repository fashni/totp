use std::time::{SystemTime, UNIX_EPOCH};
use std::env;
use arboard::Clipboard;
use rpassword::prompt_password;
use totp_lite::{totp_custom, Sha1, DEFAULT_STEP};
use base32::Alphabet::Rfc4648;

fn main() {
  let mut copy = false;
  let mut quiet = false;

  let mut args = env::args().skip(1);
  while let Some(arg) = args.next() {
    match arg.as_str() {
      "--copy" | "-c" => copy = true,
      "--quiet" | "-q" => quiet = true,
      _ => {
        eprintln!("Unexpected argument: {}", arg);
        return
      }
    }
  }

  if quiet && !copy {
    eprintln!("Nothing to do: either remove --quiet or add --copy");
    return
  }

  let secret = prompt_password("Enter the secret: ")
    .expect("Failed to read secret");
  let length = secret.len();
  if length != 16 && length != 26 && length != 32 {
    eprintln!("Invalid secret");
    return
  }

  let decoded_secret = match base32::decode (
    Rfc4648 { padding: false },
    &secret.to_uppercase()
  ) {
    Some(decoded) => decoded,
    None => {
      eprintln!("Failed to decode secret");
      return
    }
  };

  let seconds: u64 = SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap()
    .as_secs();

  let result = totp_custom::<Sha1>(
    DEFAULT_STEP,
    6,
    &decoded_secret,
    seconds
  );

  if !quiet {
    println!("{}", result);
  }

  if copy {
    add_to_clipboard(&result);
  }
}

fn add_to_clipboard(text: &str) {
  let mut clipboard = Clipboard::new()
    .expect("Failed to access clipboard");
  clipboard.set_text(text)
    .expect("Failed to copy text");
}
