//! Mosquitto-compatible authentication (`password_file`) and authorization
//! (`acl_file`).
//!
//! Both file formats and their runtime checks mirror Mosquitto 2.1.4
//! (`plugins/password-file`, `plugins/acl-file`, `libcommon/password_common.c`)
//! so existing Mosquitto configuration can be reused unchanged.

mod ctext;

pub mod acl_file;
pub mod password_file;

pub use acl_file::{Access, AclFile, AclFileError, AclWarning};
pub use password_file::{BasicAuth, HashError, PasswordFile, PasswordFileError, PasswordHash};
