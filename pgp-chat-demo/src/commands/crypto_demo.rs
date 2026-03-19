//! PGP cryptography demos: key generation, key import, encrypt/decrypt, sign/verify.

use std::io::Result as IoResult;

use pgp_chat_core::crypto::{encrypt, identity::PgpIdentity, sign};
use zeroize::Zeroizing;
use crate::ui::Ui;

// ---------------------------------------------------------------------------
// Identity generation
// ---------------------------------------------------------------------------

/// Prompt for nickname + passphrase, generate a keypair, and display results.
pub fn generate_identity(ui: &Ui) -> IoResult<()> {
    ui.renderer.draw_box_top("Generate PGP Identity")?;

    println!("  This generates a fresh PGP keypair — two mathematically linked keys:\r");
    println!("\r");
    println!("    SECRET key  — kept only on this device, never transmitted\r");
    println!("      Primary:  EdDSA  (signs your outgoing messages)\r");
    println!("      Subkey:   ECDH Curve25519  (decrypts messages sent to you)\r");
    println!("\r");
    println!("    PUBLIC key  — shared automatically with room peers\r");
    println!("      Lets peers encrypt messages only you can read,\r");
    println!("      and verify your signatures without seeing your secret key.\r");
    println!("\r");

    let nickname = ui.prompt("Enter your nickname:")?;
    if nickname.trim().is_empty() {
        ui.error("Nickname cannot be empty.")?;
        ui.wait_for_key("Press any key to return...")?;
        return Ok(());
    }

    println!("\r");
    println!("  A passphrase encrypts your SECRET key on disk so it cannot be used\r");
    println!("  even if someone obtains the key file.  Leave blank for no protection.\r");
    let passphrase = ui.prompt_password("Passphrase for secret key (blank = none):")?;
    if !passphrase.is_empty() {
        let confirm = ui.prompt_password("Confirm passphrase:")?;
        if *passphrase != *confirm {
            ui.error("Passphrases do not match.")?;
            ui.wait_for_key("Press any key to return...")?;
            return Ok(());
        }
    }

    println!("  Generating EdDSA + ECDH keypair for \"{}\"...\r", nickname.trim());

    match PgpIdentity::generate(nickname.trim(), passphrase) {
        Ok(identity) => {
            println!("\r");
            ui.info("Nickname",    identity.nickname())?;
            ui.info("User ID",     identity.user_id())?;
            ui.info("Fingerprint", &identity.fingerprint())?;

            println!("\r\n  Public Key (ASCII-armoured):\r\n");
            match identity.public_key_armored() {
                Ok(armored) => {
                    for line in armored.lines() {
                        println!("  {}\r", line);
                    }
                }
                Err(e) => ui.error(&format!("armour export failed: {e}"))?,
            }

            println!("\r\n  To save your secret key, run:\r");
            println!("  (key export to file is available from the Import/Export menu)\r");

            ui.success("Keypair generated successfully!")?;
        }
        Err(e) => {
            ui.error(&format!("Key generation failed: {e}"))?;
        }
    }

    ui.renderer.draw_box_bottom()?;
    ui.wait_for_key("Press any key to return to the menu...")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Key import from file
// ---------------------------------------------------------------------------

/// Prompt for a file path and passphrase, load an existing PGP secret key.
pub fn import_identity(ui: &Ui) -> IoResult<()> {
    ui.renderer.draw_box_top("Import Existing PGP Secret Key")?;

    // ── Explain what key we need and why ─────────────────────────────────
    println!("  PGP uses TWO related keys:\r");
    println!("\r");
    println!("    SECRET key  (also called private key)\r");
    println!("      - Stays on YOUR device, never shared\r");
    println!("      - Used to SIGN outgoing messages and DECRYPT incoming ones\r");
    println!("      - File starts with:  -----BEGIN PGP PRIVATE KEY BLOCK-----\r");
    println!("\r");
    println!("    PUBLIC key  (shared freely with peers)\r");
    println!("      - Derived from your secret key automatically\r");
    println!("      - Used by OTHERS to encrypt messages only you can read\r");
    println!("      - File starts with:  -----BEGIN PGP PUBLIC KEY BLOCK-----\r");
    println!("\r");
    println!("  >>> We need your SECRET key file here. <<<\r");
    println!("  (The public key is derived from it automatically.)\r");
    println!("\r");
    println!("  Export from GnuPG:  gpg --export-secret-keys --armor you@email > secret.asc\r");
    println!("  Export from GPG4Win / Kleopatra: File > Export Secret Keys\r\n");

    let path = ui.prompt("Path to secret key file (.asc or .gpg):")?;
    if path.trim().is_empty() {
        ui.error("Path cannot be empty.")?;
        ui.wait_for_key("Press any key to return...")?;
        return Ok(());
    }

    let nickname = ui.prompt("Display nickname:")?;
    let nickname = if nickname.trim().is_empty() { "imported" } else { nickname.trim() };

    println!("\r");
    println!("  If your secret key was exported WITH a passphrase, enter it below.\r");
    println!("  If the key has NO passphrase protection, leave the field blank.\r");
    let passphrase = ui.prompt_password("Key passphrase (blank = unprotected):")?;

    let armored = match std::fs::read_to_string(path.trim()) {
        Ok(s)  => s,
        Err(e) => {
            ui.error(&format!("Failed to read file: {e}"))?;
            ui.wait_for_key("Press any key to return...")?;
            return Ok(());
        }
    };

    match PgpIdentity::from_armored_secret_key(nickname, &armored, passphrase) {
        Ok(identity) => {
            println!("\r");
            ui.info("Nickname",    identity.nickname())?;
            ui.info("User ID",     identity.user_id())?;
            ui.info("Fingerprint", &identity.fingerprint())?;
            println!("\r");
            println!("  Your PUBLIC key (derived from the secret key above) will be\r");
            println!("  announced to room peers automatically when you join a chat.\r");
            ui.success("Secret key imported successfully!")?;
        }
        Err(e) => {
            ui.error(&format!("Key import failed: {e}"))?;
            println!("\r");
            println!("  Common causes:\r");
            println!("    - Wrong file: you may have provided the PUBLIC key instead of\r");
            println!("      the SECRET key. Check that the file begins with:\r");
            println!("      -----BEGIN PGP PRIVATE KEY BLOCK-----\r");
            println!("    - Wrong passphrase: the key is passphrase-protected and the\r");
            println!("      passphrase you entered does not match.\r");
            println!("    - Corrupt or partial file: re-export from your keyring.\r");
        }
    }

    ui.renderer.draw_box_bottom()?;
    ui.wait_for_key("Press any key to return to the menu...")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Full crypto demo (generate → encrypt → decrypt → sign → verify)
// ---------------------------------------------------------------------------

pub fn run_crypto_demo(ui: &Ui) -> IoResult<()> {
    ui.renderer.draw_box_top("Encrypt / Sign Demo")?;

    let nickname = ui.prompt("Nickname for this demo:")?;
    let nickname = if nickname.trim().is_empty() { "Alice" } else { nickname.trim() };

    println!("  Generating temporary identity for {}...\r", nickname);
    // Use an empty passphrase for the demo key (ephemeral, not saved)
    let identity = match PgpIdentity::generate(nickname, Zeroizing::new(String::new())) {
        Ok(id) => id,
        Err(e) => {
            ui.error(&format!("{e}"))?;
            ui.wait_for_key("Press any key to return...")?;
            return Ok(());
        }
    };

    ui.info("Fingerprint", &identity.fingerprint())?;

    // ── Encrypt / Decrypt ──────────────────────────────────────────────────
    ui.renderer.draw_box_separator()?;
    println!("  Encrypt / Decrypt round-trip:\r\n");

    let plaintext = b"Hello from pgp-chat! This message is PGP-encrypted.";
    println!("  Plaintext  : {:?}\r", std::str::from_utf8(plaintext).unwrap_or("(binary)"));

    match encrypt::encrypt_for_recipients(plaintext, &[identity.public_key()]) {
        Ok(ciphertext) => {
            ui.info("Ciphertext", &format!("{} bytes (binary PGP packet)", ciphertext.len()))?;

            match encrypt::decrypt_message(&ciphertext, identity.secret_key(), || String::new()) {
                Ok(decrypted) => {
                    ui.info(
                        "Decrypted",
                        std::str::from_utf8(&decrypted).unwrap_or("(binary)"),
                    )?;
                    if decrypted == plaintext {
                        ui.success("Encrypt → decrypt round-trip OK")?;
                    } else {
                        ui.error("Plaintext mismatch after decryption!")?;
                    }
                }
                Err(e) => ui.error(&format!("Decryption failed: {e}"))?,
            }
        }
        Err(e) => ui.error(&format!("Encryption failed: {e}"))?,
    }

    // ── Sign / Verify ──────────────────────────────────────────────────────
    ui.renderer.draw_box_separator()?;
    println!("  Sign / Verify:\r\n");

    let data = b"This data is signed with our EdDSA key.";
    println!("  Data : {:?}\r", std::str::from_utf8(data).unwrap_or("(binary)"));

    match sign::sign_data(data, identity.secret_key(), || String::new()) {
        Ok(sig) => {
            ui.info("Signature", &format!("{} bytes", sig.len()))?;

            match sign::verify_data(data, &sig, identity.public_key()) {
                Ok(true)  => ui.success("Signature valid ✓")?,
                Ok(false) => ui.error("Signature INVALID")?,
                Err(e)    => ui.error(&format!("Verify error: {e}"))?,
            }

            // Tamper test
            let tampered = b"This data has been tampered with.";
            match sign::verify_data(tampered, &sig, identity.public_key()) {
                Ok(false) => ui.success("Tamper detection: tampered data correctly rejected ✓")?,
                Ok(true)  => ui.error("Tamper detection FAILED — signature accepted tampered data!")?,
                Err(_)    => ui.success("Tamper detection: tampered data caused verify error (expected)")?,
            }
        }
        Err(e) => ui.error(&format!("Signing failed: {e}"))?,
    }

    ui.renderer.draw_box_bottom()?;
    ui.wait_for_key("Press any key to return to the menu...")?;
    Ok(())
}
