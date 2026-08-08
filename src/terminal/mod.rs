#[path = "struct/terminal_struct.rs"]
mod terminal_struct;

#[path = "impls/local_impl.rs"]
pub(crate) mod local;
#[path = "impls/output_highlight_impl.rs"]
mod output_highlight_impl;
#[path = "impls/render_gate_impl.rs"]
mod render_gate_impl;
#[path = "impls/serial_impl.rs"]
pub(crate) mod serial;
#[path = "impls/telnet_impl.rs"]
pub(crate) mod telnet;
#[path = "impls/term_buffer_impl.rs"]
mod term_buffer_impl;
#[path = "impls/zmodem_impl.rs"]
pub(crate) mod zmodem;

pub(crate) use terminal_struct::{
    BuiltScreen, CompiledOutputRule, CsiState, HistSpan, Line, OutputHighlightPreset, RenderGates,
    TabRenderGate, TermBuffer, TermBufferHandle, TermBuffers,
};
