/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{sync::Arc, vec};

use leptos::*;
use leptos_router::use_navigate;
use totp_rs::{qrcodegen_image, Algorithm, Secret, TOTP};
use web_time::SystemTime;

use crate::{
    components::{
        form::{
            button::Button,
            input::{InputPassword, InputText},
            Form, FormButtonBar, FormElement, FormItem, FormSection,
        },
        messages::alert::{use_alerts, Alert},
        skeleton::Skeleton,
        Color,
    }, core::{
        http::{self, Error, HttpRequest},
        oauth::use_authorization,
        schema::{Builder, Schemas, Type, Validator},
    }, i18n::use_i18n, pages::account::{AccountAuthRequest, AccountAuthResponse}
};

#[component]
pub fn ManageMfa() -> impl IntoView {
    let i18n = use_i18n();
    let mfa_i18n = i18n.get_keys().account_mfa;
    let auth = use_authorization();
    let alert = use_alerts();
    let (pending, set_pending) = create_signal(false);

    let data = expect_context::<Arc<Schemas>>()
        .build_form("mfa")
        .into_signal();

    let fetch_auth = create_resource(
        move || (),
        move |_| {
            let auth = auth.get_untracked();

            async move {
                HttpRequest::get("/api/account/auth")
                    .with_authorization(&auth)
                    .send::<AccountAuthResponse>()
                    .await
            }
        },
    );

    let update_otp = create_action(
        move |(password, otp_token, request): &(String, Option<String>, AccountAuthRequest)| {
            let password = password.clone();
            let otp_token = otp_token.clone();
            let request = request.clone();
            let auth = auth.get();

            async move {
                set_pending.set(true);
                let result = HttpRequest::post("/api/account/auth")
                    .with_basic_authorization(
                        auth.username.as_str(),
                        otp_token
                            .map(|token| format!("{password}${token}"))
                            .unwrap_or(password),
                    )
                    .with_base_url(&auth)
                    .with_body(vec![request])
                    .unwrap()
                    .send::<()>()
                    .await;
                set_pending.set(false);

                alert.set(match result {
                    Ok(_) => Alert::success(mfa_i18n.two_factor_authentication_updated_message)
                        .with_details(mfa_i18n.update_two_factor_authentication_success_message)
                        .without_timeout(),
                    Err(Error::Unauthorized) => Alert::warning(mfa_i18n.incorrect_password_title)
                        .with_details(mfa_i18n.incorrect_password_message),
                    Err(err) => Alert::from(err),
                });
            }
        },
    );

    view! {
        <Form
            title=mfa_i18n.two_factor_authentication_title
            subtitle=mfa_i18n.two_factor_authentication_manage_description
        >
            <Transition fallback=Skeleton set_pending>

                {move || match fetch_auth.get() {
                    None => None,
                    Some(Err(http::Error::Unauthorized)) => {
                        use_navigate()("/login", Default::default());
                        Some(view! { <div></div> }.into_view())
                    }
                    Some(Err(err)) => {
                        alert.set(Alert::from(err));
                        Some(view! { <div></div> }.into_view())
                    }
                    Some(Ok(response)) => {
                        if !response.otp_auth {
                            let totp = TOTP::new(
                                    Algorithm::SHA1,
                                    6,
                                    1,
                                    30,
                                    Secret::default().to_bytes().unwrap(),
                                    Some("Stalwart Mail".to_string()),
                                    auth.get_untracked().username.to_string(),
                                )
                                .unwrap();
                            let url = totp.get_url();
                            let qr_code = qrcodegen_image::draw_base64(
                                    &format!(
                                        "{url}&image=https%3A%2F%2Fstalw.art%2Fimg%2Ffavicon-32x32.png",
                                    ),
                                )
                                .unwrap();
                            let secret = totp.get_secret_base32();
                            let totp = Arc::new(totp);
                            Some(
                                view! {
                                    <div class="flex flex-col items-center pb-[30px]">
                                        <img
                                            src=format!("data:image/png;base64,{qr_code}")
                                            alt="QR Code"
                                            class="w-64 h-auto"
                                        />
                                        <p class="text-xs">{secret}</p>
                                    </div>

                                    <FormSection>
                                        <FormItem
                                            label=mfa_i18n.password_label
                                            tooltip=mfa_i18n.enable_2fa_password_tooltip
                                        >
                                            <InputPassword element=FormElement::new("password", data) />
                                        </FormItem>
                                        <FormItem
                                            label=mfa_i18n.otp_code_label
                                            tooltip=mfa_i18n.enable_2fa_otp_tooltip
                                        >
                                            <InputText element=FormElement::new("otp-code", data) />
                                        </FormItem>
                                    </FormSection>

                                    <FormButtonBar>

                                        <Button
                                            text=mfa_i18n.enable_2fa_button
                                            color=Color::Blue
                                            on_click=Callback::new(move |_| {
                                                let totp = totp.clone();
                                                data.update(|data| {
                                                    if data.validate_form() {
                                                        let password = data.value::<String>("password").unwrap();
                                                        let otp_code = data.value::<String>("otp-code").unwrap();
                                                        if totp
                                                            .check(
                                                                otp_code.as_str(),
                                                                SystemTime::now()
                                                                    .duration_since(SystemTime::UNIX_EPOCH)
                                                                    .map_or(0, |t| t.as_secs()),
                                                            )
                                                        {
                                                            update_otp
                                                                .dispatch((
                                                                    password,
                                                                    None,
                                                                    AccountAuthRequest::EnableOtpAuth {
                                                                        url: url.clone(),
                                                                    },
                                                                ));
                                                        } else {
                                                            alert
                                                                .set(
                                                                    Alert::warning(mfa_i18n.invalid_otp_code_title)
                                                                        .with_details(mfa_i18n.invalid_otp_code_message),
                                                                );
                                                        }
                                                    }
                                                });
                                            })

                                            disabled=pending
                                        />
                                    </FormButtonBar>
                                }
                                    .into_view(),
                            )
                        } else {
                            Some(
                                view! {
                                    <FormSection>
                                        <FormItem
                                            label=mfa_i18n.password_label
                                            tooltip=mfa_i18n.disable_2fa_password_tooltip
                                        >
                                            <InputPassword element=FormElement::new("password", data) />
                                        </FormItem>
                                        <FormItem
                                            label=mfa_i18n.otp_code_label
                                            tooltip=mfa_i18n.disable_2fa_otp_tooltip
                                        >
                                            <InputText element=FormElement::new("otp-code", data) />
                                        </FormItem>
                                    </FormSection>

                                    <FormButtonBar>

                                        <Button
                                            text=mfa_i18n.disable_2fa_button
                                            color=Color::Red
                                            on_click=Callback::new(move |_| {
                                                data.update(|data| {
                                                    if data.validate_form() {
                                                        update_otp
                                                            .dispatch((
                                                                data.value::<String>("password").unwrap(),
                                                                data.value::<String>("otp-code"),
                                                                AccountAuthRequest::DisableOtpAuth {
                                                                    url: None,
                                                                },
                                                            ));
                                                    }
                                                });
                                            })

                                            disabled=pending
                                        />
                                    </FormButtonBar>
                                }
                                    .into_view(),
                            )
                        }
                    }
                }}

            </Transition>

        </Form>
    }
}

impl Builder<Schemas, ()> {
    pub fn build_mfa(self) -> Self {
        self.new_schema("mfa")
            .new_field("otp-code")
            .typ(Type::Input)
            .input_check([], [Validator::Required])
            .build()
            .new_field("password")
            .typ(Type::Secret)
            .input_check([], [Validator::Required])
            .build()
            .build()
    }
}
