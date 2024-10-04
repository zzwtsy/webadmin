/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{str::FromStr, sync::Arc};

use leptos::*;
use leptos_router::use_navigate;
use serde::{Deserialize, Serialize};

use crate::{
    components::{
        form::{
            button::Button,
            input::{InputPassword, InputText, TextArea},
            select::Select,
            Form, FormButtonBar, FormElement, FormItem, FormSection,
        },
        messages::alert::{use_alerts, Alert},
        skeleton::Skeleton,
        Color,
    },
    core::{
        form::FormData,
        http::{self, Error, HttpRequest},
        oauth::use_authorization,
        schema::{Builder, Schemas, SelectType, Source, Transformer, Type, Validator},
    }, i18n::use_i18n,
};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type")]
pub enum EncryptionType {
    PGP {
        algo: Algorithm,
        certs: String,
    },
    SMIME {
        algo: Algorithm,
        certs: String,
    },
    #[default]
    Disabled,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum Algorithm {
    Aes128,
    Aes256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionMethod {
    PGP,
    SMIME,
}

#[component]
pub fn ManageCrypto() -> impl IntoView {
    let i18n = use_i18n();
    let crypto_i18n= i18n.get_keys().account_crypto;
    let auth = use_authorization();
    let alert = use_alerts();
    let show_totp = create_rw_signal(false);
    let fetch_crypto = create_resource(
        move || (),
        move |_| {
            let auth = auth.get_untracked();

            async move {
                HttpRequest::get("/api/account/crypto")
                    .with_authorization(&auth)
                    .send::<EncryptionType>()
                    .await
            }
        },
    );

    let (pending, set_pending) = create_signal(false);

    let data = expect_context::<Arc<Schemas>>()
        .build_form("crypto-at-rest")
        .into_signal();

    let save_changes = create_action(move |(changes, password): &(EncryptionType, String)| {
        let changes = changes.clone();
        let password = password.clone();
        let auth = auth.get();

        async move {
            let is_disable = matches!(changes, EncryptionType::Disabled);
            set_pending.set(true);
            let result = HttpRequest::post("/api/account/crypto")
                .with_basic_authorization(auth.username.as_str(), &password)
                .with_base_url(&auth)
                .with_body(changes)
                .unwrap()
                .send::<Option<u32>>()
                .await
                .map(|_| ());
            set_pending.set(false);

            alert.set(match result {
                Ok(_) => {
                    show_totp.set(false);

                    if !is_disable {
                        Alert::success(crypto_i18n.encryption_at_rest_enabled_message).with_details(i18n.get_keys().account_crypto.enable_encryption_message)
                    } else {
                        Alert::success(crypto_i18n.encryption_at_rest_disabled_message).with_details(i18n.get_keys().account_crypto.disable_encryption_message)
                    }
                    .without_timeout()
                }
                Err(Error::Unauthorized) => Alert::warning(crypto_i18n.incorrect_password_title)
                    .with_details(crypto_i18n.incorrect_password_message),
                Err(Error::TotpRequired) => {
                    show_totp.set(true);
                    return;
                }
                Err(err) => {
                    show_totp.set(false);
                    Alert::from(err)
                }
            });
        }
    });

    view! {
        <Form
            title=crypto_i18n.encryption_at_rest_title
            subtitle=crypto_i18n.encryption_at_rest_subtitle
        >

            <Transition fallback=Skeleton set_pending>

                {move || match fetch_crypto.get() {
                    None => None,
                    Some(Err(http::Error::Unauthorized)) => {
                        use_navigate()("/login", Default::default());
                        Some(view! { <div></div> }.into_view())
                    }
                    Some(Err(err)) => {
                        alert.set(Alert::from(err));
                        Some(view! { <div></div> }.into_view())
                    }
                    Some(Ok(crypto)) => {
                        data.update(|data| {
                            data.from_encryption_params(&crypto);
                        });
                        let has_no_crypto = create_memo(move |_| {
                            data.get().value::<EncryptionMethod>("type").is_none()
                        });
                        Some(
                            view! {
                                <FormSection>
                                    <Show when=move || show_totp.get()>
                                        <FormItem label=crypto_i18n.totp_token_label>
                                            <InputText element=FormElement::new("totp-code", data) />
                                        </FormItem>
                                    </Show>

                                    <Show when=move || !show_totp.get()>
                                        <FormItem label=crypto_i18n.current_password_label>
                                            <InputPassword element=FormElement::new("password", data) />
                                        </FormItem>
                                        <FormItem
                                            label=crypto_i18n.encryption_type_label
                                            tooltip=crypto_i18n.encryption_type_tooltip
                                        >
                                            <Select element=FormElement::new("type", data) />
                                        </FormItem>

                                        <FormItem
                                            label=crypto_i18n.algorithm_label
                                            tooltip=crypto_i18n.algorithm_tooltip
                                            hide=has_no_crypto
                                        >
                                            <Select element=FormElement::new("algo", data) />

                                        </FormItem>

                                        <FormItem
                                            label=crypto_i18n.certificates_label
                                            tooltip=crypto_i18n.certificates_tooltip
                                            hide=has_no_crypto
                                        >
                                            <TextArea element=FormElement::new("certs", data) />
                                        </FormItem>
                                    </Show>

                                </FormSection>
                            }
                                .into_view(),
                        )
                    }
                }}

            </Transition>

            <FormButtonBar>

                <Button
                    text=crypto_i18n.save_changes_button
                    color=Color::Blue
                    on_click=Callback::new(move |_| {
                        data.update(|data| {
                            if let Some(changes) = data.to_encryption_params() {
                                save_changes
                                    .dispatch((
                                        changes,
                                        match (
                                            data.value::<String>("password").unwrap_or_default(),
                                            data.value::<String>("totp-code"),
                                        ) {
                                            (password, Some(totp)) => format!("{}${}", password, totp),
                                            (password, None) => password,
                                        },
                                    ));
                            }
                        });
                    })

                    disabled=pending
                />
            </FormButtonBar>

        </Form>
    }
}

#[allow(clippy::wrong_self_convention)]
impl FormData {
    fn from_encryption_params(&mut self, params: &EncryptionType) {
        match params {
            EncryptionType::PGP { algo, certs } => {
                self.set("type", EncryptionMethod::PGP.as_str());
                self.set("algo", algo.as_str());
                self.set("certs", certs);
            }
            EncryptionType::SMIME { algo, certs } => {
                self.set("type", EncryptionMethod::SMIME.as_str());
                self.set("algo", algo.as_str());
                self.set("certs", certs);
            }
            EncryptionType::Disabled => {
                self.set("type", "");
            }
        }
    }

    fn to_encryption_params(&mut self) -> Option<EncryptionType> {
        if self.validate_form() {
            match self.value::<EncryptionMethod>("type") {
                Some(EncryptionMethod::PGP) => EncryptionType::PGP {
                    algo: self.value("algo").unwrap(),
                    certs: self.value("certs").unwrap(),
                },
                Some(EncryptionMethod::SMIME) => EncryptionType::SMIME {
                    algo: self.value("algo").unwrap(),
                    certs: self.value("certs").unwrap(),
                },
                None => EncryptionType::Disabled,
            }
            .into()
        } else {
            None
        }
    }
}

impl Builder<Schemas, ()> {
    pub fn build_crypto(self) -> Self {
        const METHODS: &[(&str, &str)] = &[
            (EncryptionMethod::PGP.as_str(), "OpenPGP"),
            (EncryptionMethod::SMIME.as_str(), "S/MIME"),
            ("", "Disabled"),
        ];
        const ALGOS: &[(&str, &str)] = &[
            (Algorithm::Aes128.as_str(), "AES-128"),
            (Algorithm::Aes256.as_str(), "AES-256"),
        ];

        self.new_schema("crypto-at-rest")
            .new_field("type")
            .typ(Type::Select {
                source: Source::Static(METHODS),
                typ: SelectType::Single,
            })
            .default("")
            .build()
            .new_field("algo")
            .typ(Type::Select {
                source: Source::Static(ALGOS),
                typ: SelectType::Single,
            })
            .default(Algorithm::Aes256.as_str())
            .display_if_eq(
                "type",
                [
                    EncryptionMethod::PGP.as_str(),
                    EncryptionMethod::SMIME.as_str(),
                ],
            )
            .build()
            .new_field("certs")
            .typ(Type::Text)
            .input_check([], [Validator::Required])
            .display_if_eq(
                "type",
                [
                    EncryptionMethod::PGP.as_str(),
                    EncryptionMethod::SMIME.as_str(),
                ],
            )
            .build()
            .new_field("password")
            .typ(Type::Text)
            .input_check([], [Validator::Required])
            .build()
            .new_field("totp-code")
            .input_check([Transformer::Trim], [])
            .build()
            .build()
    }
}

impl EncryptionMethod {
    pub const fn as_str(&self) -> &'static str {
        match self {
            EncryptionMethod::PGP => "pgp",
            EncryptionMethod::SMIME => "smime",
        }
    }
}

impl FromStr for EncryptionMethod {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pgp" => Ok(EncryptionMethod::PGP),
            "smime" => Ok(EncryptionMethod::SMIME),
            _ => Err(()),
        }
    }
}

impl Algorithm {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Algorithm::Aes128 => "aes128",
            Algorithm::Aes256 => "aes256",
        }
    }
}

impl FromStr for Algorithm {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "aes128" => Ok(Algorithm::Aes128),
            "aes256" => Ok(Algorithm::Aes256),
            _ => Err(()),
        }
    }
}
