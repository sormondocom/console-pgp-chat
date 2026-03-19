//! Terminal capability and colour demos.

use std::io::Result;
use pgp_chat_core::terminal::capability::ColorDepth;
use crate::ui::Ui;

/// Show the detected terminal capabilities in a structured table.
pub fn show_capabilities(ui: &Ui) -> Result<()> {
    let cap = ui.renderer.cap();

    ui.renderer.draw_box_top("Terminal Capabilities")?;

    ui.info("Term name",   &cap.term_name)?;
    ui.info("Size",        &format!("{}×{}", cap.width, cap.height))?;
    ui.info("Colour depth", &format!("{:?}", cap.color_depth))?;
    ui.info("Unicode",     if cap.unicode { "yes — box-drawing chars available" } else { "no — using ASCII fallback" })?;

    let level_desc = match cap.color_depth {
        ColorDepth::Monochrome => "VT-100 / dumb terminal — no colour; bold/underline only",
        ColorDepth::Ansi16     => "16 named ANSI colours (8 standard + 8 bright variants)",
        ColorDepth::Ansi256    => "xterm 256-colour palette: 6×6×6 cube + 24-step greyscale",
        ColorDepth::TrueColor  => "24-bit RGB — 16.7 million colours, smooth gradients",
    };
    ui.info("Description", level_desc)?;

    // Explain box-drawing
    println!("\r");
    ui.info("ASCII borders", "+--+  |content|  +--+")?;
    if cap.unicode {
        ui.info("Unicode boxes", "╔══╗  ║content║  ╚══╝  ← your terminal supports these")?;
    } else {
        ui.info("Unicode boxes", "(not supported on this terminal)")?;
    }

    // Show the NO_COLOR and COLORTERM env vars if set
    if let Ok(v) = std::env::var("NO_COLOR") {
        ui.info("NO_COLOR", &format!("set ({:?}) — colours suppressed per no-color.org", v))?;
    }
    if let Ok(v) = std::env::var("COLORTERM") {
        ui.info("COLORTERM", &v)?;
    }

    ui.renderer.draw_box_bottom()?;
    ui.wait_for_key("Press any key to return to the menu...")?;
    Ok(())
}

/// Run the adaptive colour test for the detected depth.
pub fn show_color_test(ui: &Ui) -> Result<()> {
    ui.renderer.draw_color_test()?;
    ui.wait_for_key("Press any key to return to the menu...")?;
    Ok(())
}
