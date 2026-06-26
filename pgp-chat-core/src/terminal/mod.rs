//! Terminal capability detection and adaptive rendering.
//!
//! The rendering pipeline is:
//!
//! ```text
//! TerminalCapability::detect()
//!         │
//!         ▼
//!   ColorPalette::for_depth()   ←── semantic color roles
//!         │
//!         ▼
//!      Renderer::new()          ←── owns capability + palette + border set
//!         │
//!         ▼
//!   draw_box_top / draw_message / draw_color_test / …
//! ```
//!
//! Every draw method produces output through `crossterm` queued commands so
//! that the same code path works on VT-100 monochrome, 16-color ANSI,
//! xterm-256color, and 24-bit true color terminals — including the Windows
//! Console Host and Windows Terminal.

pub mod capability;
pub mod color;
pub mod renderer;

pub use capability::TerminalCapability;
pub use color::ColorPalette;
pub use renderer::Renderer;
