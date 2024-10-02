/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::{collections::HashSet, vec};

use leptos::*;
use leptos_router::{use_navigate, use_params_map};
use serde::{Deserialize, Serialize};

use crate::{
    components::{
        messages::alert::{use_alerts, Alert, Alerts},
        skeleton::Skeleton,
    },
    core::{
        http::{self, HttpRequest},
        oauth::use_authorization,
    },
    pages::{
        queue::reports::{
            arf::ArfReportDisplay, dmarc::DmarcReportDisplay, tls::TlsReportDisplay, Feedback,
            Report, TlsReport,
        },
        reports::IncomingReport,
    },
};

use super::{parse_report_date, ReportType};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
enum ReportWrapper {
    Dmarc(IncomingReport<Report>),
    Tls(IncomingReport<TlsReport>),
    Arf(IncomingReport<Feedback>),
}

#[component]
pub fn IncomingReportDisplay() -> impl IntoView {
    let auth = use_authorization();
    let alert = use_alerts();
    let params = use_params_map();
    let report_type = create_memo(move |_| {
        match params
            .get()
            .get("object")
            .map(|id| id.as_str())
            .unwrap_or_default()
        {
            "dmarc" => ReportType::Dmarc,
            "tls" => ReportType::Tls,
            "arf" => ReportType::Arf,
            _ => ReportType::Dmarc,
        }
    });
    let fetch_report = create_resource(
        move || params.get().get("id").cloned().unwrap_or_default(),
        move |id| {
            let auth = auth.get_untracked();
            let id = id.clone();
            let report_type = report_type.get();

            async move {
                match report_type {
                    ReportType::Dmarc => HttpRequest::get(format!("/api/reports/dmarc/{id}"))
                        .with_authorization(&auth)
                        .send::<IncomingReport<Report>>()
                        .await
                        .map(ReportWrapper::Dmarc),
                    ReportType::Tls => HttpRequest::get(format!("/api/reports/tls/{id}"))
                        .with_authorization(&auth)
                        .send::<IncomingReport<TlsReport>>()
                        .await
                        .map(ReportWrapper::Tls),
                    ReportType::Arf => HttpRequest::get(format!("/api/reports/arf/{id}"))
                        .with_authorization(&auth)
                        .send::<IncomingReport<Feedback>>()
                        .await
                        .map(ReportWrapper::Arf),
                }
            }
        },
    );

    let selected = create_rw_signal::<HashSet<String>>(HashSet::new());
    provide_context(selected);

    view! {
        <Alerts />
        <Transition fallback=Skeleton>

            {move || match fetch_report.get() {
                None => None,
                Some(Err(http::Error::Unauthorized)) => {
                    use_navigate()("/login", Default::default());
                    Some(view! { <div></div> }.into_view())
                }
                Some(Err(http::Error::NotFound)) => {
                    use_navigate()(
                        &format!("/manage/reports/{}", report_type.get().as_str()),
                        Default::default(),
                    );
                    Some(view! { <div></div> }.into_view())
                }
                Some(Err(err)) => {
                    alert.set(Alert::from(err));
                    Some(view! { <div></div> }.into_view())
                }
                Some(Ok(report)) => {
                    match report {
                        ReportWrapper::Tls(report) => {
                            let (report, extra) = report.unwrap_report();
                            Some(
                                view! {
                                    <TlsReportDisplay
                                        report=report
                                        extra=extra
                                        back_url="/manage/reports/tls".to_string()
                                    />
                                }
                                    .into_view(),
                            )
                        }
                        ReportWrapper::Dmarc(report) => {
                            let (report, extra) = report.unwrap_report();
                            Some(
                                view! {
                                    <DmarcReportDisplay
                                        report=report
                                        extra=extra
                                        back_url="/manage/reports/dmarc".to_string()
                                    />
                                }
                                    .into_view(),
                            )
                        }
                        ReportWrapper::Arf(report) => {
                            let (report, extra) = report.unwrap_report();
                            let received = parse_report_date(
                                &params.get().get("id").cloned().unwrap_or_default(),
                            );
                            Some(
                                view! {
                                    <ArfReportDisplay
                                        report=report
                                        received=received
                                        extra=extra
                                        back_url="/manage/reports/arf".to_string()
                                    />
                                }
                                    .into_view(),
                            )
                        }
                    }
                }
            }}

        </Transition>
    }
}

impl<T> IncomingReport<T> {
    pub fn unwrap_report(self) -> (T, Vec<(String, String)>) {
        (
            self.report,
            vec![
                ("Received From".to_string(), self.from),
                ("Recipients".to_string(), self.to.join(", ")),
                ("Subject".to_string(), self.subject),
            ],
        )
    }
}
