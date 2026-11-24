//! Mosquitto-compatible authentication (`password_file`) and authorization
//! (`acl_file`).
//!
//! Both file formats and their runtime checks mirror Mosquitto 2.1.4
//! (`plugins/password-file`, `plugins/acl-file`, `libcommon/password_common.c`)
//! so existing Mosquitto configuration can be reused unchanged.

mod ctext;
mod dynamic_security;

pub mod acl_file;
pub mod external;
pub mod password_file;

pub use acl_file::{Access, AclFile, AclFileError, AclWarning};
pub use dynamic_security::{
    DYNSEC_CONTROL_TOPIC, DYNSEC_RESPONSE_TOPIC, DynamicSecurity, DynsecRequest, DynsecResult,
};
pub use password_file::{BasicAuth, HashError, PasswordFile, PasswordFileError, PasswordHash};
