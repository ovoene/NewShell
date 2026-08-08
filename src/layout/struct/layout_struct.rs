/// Split orientation. `Horizontal` places the two children side by side
/// (`first` on the left), `Vertical` stacks them (`first` on top).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dir {
    Horizontal,
    Vertical,
}

/// A node: either a binary split or a leaf pane holding a tab group.
#[derive(Clone, Debug)]
pub enum Node {
    Split {
        id: u64,
        dir: Dir,
        /// Fraction of the long axis given to `first` (0..1).
        ratio: f32,
        first: Box<Node>,
        second: Box<Node>,
    },
    Leaf(Leaf),
}

/// A leaf pane: its tab group (ids, in order) and which tab is active.
#[derive(Clone, Debug)]
pub struct Leaf {
    pub id: u64,
    pub tabs: Vec<String>,
    pub active: String,
}

/// The whole layout plus an id allocator and which leaf currently has focus.
#[derive(Debug)]
pub struct Layout {
    pub root: Node,
    pub focused: u64,
    pub(super) next_id: u64,
}

/// A leaf pane flattened to an absolute rect (content-area coordinates).
#[derive(Clone, Debug, PartialEq)]
pub struct PaneRect {
    pub id: u64,
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
    pub tabs: Vec<String>,
    pub active: String,
    pub focused: bool,
}

/// A draggable splitter between the two children of a `Split` node.
#[derive(Clone, Debug, PartialEq)]
pub struct SplitterRect {
    /// Id of the `Split` node this resizes.
    pub split_id: u64,
    pub x: f32,
    pub y: f32,
    pub w: f32,
    pub h: f32,
    /// True when the handle is vertical (a Horizontal split → drag left/right).
    pub vertical: bool,
    /// Start of the split's axis (x for a Horizontal split, y for a Vertical
    /// one) and its length — the `[start, start+len]` window `set_ratio` maps a
    /// drag position into. Lets the drag handler recover the ratio without
    /// tracking the parent rect separately.
    pub axis_start: f32,
    pub axis_len: f32,
}

pub(crate) struct TerminalWheelHit {
    pub(crate) tab_id: String,
    pub(crate) is_alt: bool,
    pub(crate) col: i32,
    pub(crate) row: i32,
}

#[derive(Clone, Copy)]
pub(crate) struct LogicalRect {
    pub(crate) x: f32,
    pub(crate) y: f32,
    pub(crate) w: f32,
    pub(crate) h: f32,
}
