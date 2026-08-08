use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::sftp::SftpHandle;

pub(crate) type SftpHandles = Arc<Mutex<HashMap<String, SftpHandle>>>;

/// Last terminal cwd followed by each SFTP panel.
pub(crate) type SftpLastCwd = Arc<Mutex<HashMap<String, String>>>;
