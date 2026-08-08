use super::terminal_struct::OutputHighlightPreset;

impl OutputHighlightPreset {
    pub(crate) fn from_settings(enabled: bool, preset: &str) -> Self {
        if !enabled {
            Self::Off
        } else if preset == "devops" {
            Self::DevOps
        } else {
            Self::Log
        }
    }
}
