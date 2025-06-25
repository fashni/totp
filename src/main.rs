use std::time::{SystemTime, UNIX_EPOCH};
use std::env;
use arboard::Clipboard;
use rpassword::prompt_password;
use totp_lite::{totp_custom, Sha1, DEFAULT_STEP};
use base32::Alphabet::Rfc4648;

struct Config {
  copy: bool,
  quiet: bool,
}

fn main() {
  let config = match parse_args() {
    Ok(cfg) => cfg,
    Err(e) => {
      eprintln!("{}", e);
      return;
    }
  };

  if config.quiet && !config.copy {
    eprintln!("Nothing to do: either remove --quiet or add --copy");
    return;
  }

  let secret = prompt_password("Enter the secret: ")
    .expect("Failed to read secret");
  let decoded_secret = match decode_secret(&secret) {
    Ok(decoded) => decoded,
    Err(e) => {
      eprintln!("{}", e);
      return;
    }
  };

  let otp = match generate_totp(DEFAULT_STEP, 6, &decoded_secret) {
    Ok(result) => result,
    Err(e) => {
      eprintln!("{}", e);
      return;
    }
  };

  if !config.quiet {
    println!("{}", otp);
  }

  if config.copy {
    if let Err(e) = copy_to_clipboard(&otp){
      eprintln!("{}", e);
    }
  }
}

fn parse_args() -> Result<Config, String> {
  let mut copy = false;
  let mut quiet = false;
  let mut args = env::args().skip(1);

  while let Some(arg) = args.next() {
    match arg.as_str() {
      "--copy" | "-c" => copy = true,
      "--quiet" | "-q" => quiet = true,
      _ => {
        return Err(format!("Unexpected argument: {}", arg))
      }
    }
  }

  Ok(Config { copy, quiet })
}

fn decode_secret(secret: &str) -> Result<Vec<u8>, String> {
  let length = secret.len();
  if length != 16 && length != 26 && length != 32 {
    return Err(format!("Invalid secret"))
  }

  base32::decode (
    Rfc4648 { padding: false },
    &secret.to_uppercase()
  ).ok_or_else(|| "Failed to decode secret".to_string())
}

fn generate_totp(step: u64, digits: u32, secret: &[u8]) -> Result<String, String> {
  match SystemTime::now().duration_since(UNIX_EPOCH) {
    Ok(duration) => Ok(totp_custom::<Sha1>(step, digits, secret, duration.as_secs())),
    Err(e) => Err(format!("SystemTimeError difference: {:?}", e.duration()))
  }
}

fn copy_to_clipboard(text: &str) -> Result<(), String> {
  Clipboard::new()
    .map_err(|_| "Failed to access clipboard".to_string()).unwrap()
    .set_text(text)
    .map_err(|_| "Failed to copy text".to_string())
}
