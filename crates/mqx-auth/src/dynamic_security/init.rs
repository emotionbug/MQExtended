use super::{
    Acl, AclType, Client, DynamicSecurity, EncodedPassword, Group, Role, Text, insert_membership,
};

impl DynamicSecurity {
    /// `config_init.c: dynsec__config_init`. Without a supplied password,
    /// return the generated credentials for the broker's owner-only `.pw`
    /// file, including the demonstration client (random mode only).
    pub fn initialize(
        admin_password: Option<&[u8]>,
    ) -> Result<(Self, Option<String>), getrandom::Error> {
        let mut state = Self {
            defaults: [false, true, false, true],
            anonymous_group: Some("unauthenticated".into()),
            ..Self::default()
        };
        state.groups.insert("unauthenticated".into(), Group {
            text: Text {
                name: Some("Unauthenticated group".into()),
                description: Some("If unauthenticated access is allowed, this group can be used to define roles for clients that connect without a password.".into()),
            },
            roles: Vec::new(),
        });
        let full = [
            AclType::Send,
            AclType::Receive,
            AclType::SubPattern,
            AclType::UnsubPattern,
        ];
        let observe = [AclType::Receive, AclType::SubPattern, AclType::UnsubPattern];
        for (name, description, topic, types) in [
            (
                "client",
                "Read/write access to the full application topic hierarchy.",
                "#",
                full.as_slice(),
            ),
            (
                "broker-admin",
                "Grants access to administer general broker configuration.",
                "$CONTROL/broker/#",
                &full,
            ),
            (
                "dynsec-admin",
                "Grants access to administer clients/groups/roles.",
                "$CONTROL/dynamic-security/#",
                &full,
            ),
            (
                "super-admin",
                "Grants access to administer all kind of broker controls",
                "$CONTROL/#",
                &full,
            ),
            (
                "sys-notify",
                "Allow bridges to publish connection state messages.",
                "$SYS/broker/connection/%c/state",
                &[AclType::Send],
            ),
            (
                "sys-observe",
                "Observe the $SYS topic hierarchy.",
                "$SYS/#",
                &[AclType::Receive, AclType::SubPattern],
            ),
            (
                "topic-observe",
                "Read only access to the full application topic hierarchy.",
                "#",
                &observe,
            ),
        ] {
            state.roles.insert(
                name.into(),
                Role {
                    text: Text {
                        name: None,
                        description: Some(description.into()),
                    },
                    allow_wildcards: true,
                    acls: types
                        .iter()
                        .map(|&kind| Acl {
                            kind,
                            topic: topic.into(),
                            priority: 0,
                            allow: true,
                        })
                        .collect(),
                },
            );
        }
        let credentials = if let Some(password) = admin_password {
            state.add_initial_client(
                "admin",
                "Admin user",
                password,
                &["super-admin", "sys-observe", "topic-observe"],
            )?;
            None
        } else {
            let admin = random_password()?;
            let demo = random_password()?;
            state.add_initial_client(
                "admin",
                "Admin user",
                admin.as_bytes(),
                &["super-admin", "sys-observe", "topic-observe"],
            )?;
            state.add_initial_client(
                "democlient",
                "Demonstration client with full read/write access to the '#' topic hierarchy.",
                demo.as_bytes(),
                &["client"],
            )?;
            Some(format!("admin {admin}\ndemoclient {demo}\n"))
        };
        Ok((state, credentials))
    }

    fn add_initial_client(
        &mut self,
        name: &str,
        text: &str,
        password: &[u8],
        roles: &[&str],
    ) -> Result<(), getrandom::Error> {
        let mut client = Client {
            text: Text {
                name: Some(text.into()),
                description: None,
            },
            password: Some(EncodedPassword::hash(password)?),
            ..Client::default()
        };
        for role in roles {
            insert_membership(&mut client.roles, role, -1);
        }
        self.clients.insert(name.into(), client);
        Ok(())
    }
}

fn random_password() -> Result<String, getrandom::Error> {
    const ALPHABET: &[u8] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-=_+[]{}@#~,./<>?";
    const CEILING: usize = 256 - (256 % ALPHABET.len());
    let mut password = String::with_capacity(20);
    let mut bytes = [0; 32];
    while password.len() < 20 {
        getrandom::fill(&mut bytes)?;
        for byte in bytes {
            let byte = usize::from(byte);
            if byte < CEILING {
                password.push(char::from(ALPHABET[byte % ALPHABET.len()]));
                if password.len() == 20 {
                    break;
                }
            }
        }
    }
    Ok(password)
}
