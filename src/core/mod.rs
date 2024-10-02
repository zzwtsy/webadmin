/*
 * SPDX-FileCopyrightText: 2020 Stalwart Labs Ltd <hello@stalw.art>
 *
 * SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-SEL
 */

use std::sync::Arc;

use ahash::AHashSet;
use serde::{Deserialize, Serialize};

pub mod expr;
pub mod form;
pub mod http;
pub mod oauth;
pub mod schema;
pub mod url;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessToken {
    pub base_url: Arc<String>,
    pub access_token: Arc<String>,
    pub refresh_token: Arc<String>,
    pub username: Arc<String>,
    pub is_valid: bool,
    pub is_enterprise: bool,
    pub permissions: Permissions,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Permissions(Arc<AHashSet<Permission>>);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Permission {
    // Admin
    Impersonate,
    UnlimitedRequests,
    UnlimitedUploads,
    DeleteSystemFolders,
    MessageQueueList,
    MessageQueueGet,
    MessageQueueUpdate,
    MessageQueueDelete,
    OutgoingReportList,
    OutgoingReportGet,
    OutgoingReportDelete,
    IncomingReportList,
    IncomingReportGet,
    IncomingReportDelete,
    SettingsList,
    SettingsUpdate,
    SettingsDelete,
    SettingsReload,
    IndividualList,
    IndividualGet,
    IndividualUpdate,
    IndividualDelete,
    IndividualCreate,
    GroupList,
    GroupGet,
    GroupUpdate,
    GroupDelete,
    GroupCreate,
    DomainList,
    DomainGet,
    DomainCreate,
    DomainUpdate,
    DomainDelete,
    TenantList,
    TenantGet,
    TenantCreate,
    TenantUpdate,
    TenantDelete,
    MailingListList,
    MailingListGet,
    MailingListCreate,
    MailingListUpdate,
    MailingListDelete,
    RoleList,
    RoleGet,
    RoleCreate,
    RoleUpdate,
    RoleDelete,
    PrincipalList,
    PrincipalGet,
    PrincipalCreate,
    PrincipalUpdate,
    PrincipalDelete,
    BlobFetch,
    PurgeBlobStore,
    PurgeDataStore,
    PurgeLookupStore,
    PurgeAccount,
    FtsReindex,
    Undelete,
    DkimSignatureCreate,
    DkimSignatureGet,
    UpdateSpamFilter,
    UpdateWebadmin,
    LogsView,
    SieveRun,
    Restart,
    TracingList,
    TracingGet,
    TracingLive,
    MetricsList,
    MetricsLive,

    // Generic
    Authenticate,
    AuthenticateOauth,
    EmailSend,
    EmailReceive,

    // Account Management
    ManageEncryption,
    ManagePasswords,

    // JMAP
    JmapEmailGet,
    JmapMailboxGet,
    JmapThreadGet,
    JmapIdentityGet,
    JmapEmailSubmissionGet,
    JmapPushSubscriptionGet,
    JmapSieveScriptGet,
    JmapVacationResponseGet,
    JmapPrincipalGet,
    JmapQuotaGet,
    JmapBlobGet,
    JmapEmailSet,
    JmapMailboxSet,
    JmapIdentitySet,
    JmapEmailSubmissionSet,
    JmapPushSubscriptionSet,
    JmapSieveScriptSet,
    JmapVacationResponseSet,
    JmapEmailChanges,
    JmapMailboxChanges,
    JmapThreadChanges,
    JmapIdentityChanges,
    JmapEmailSubmissionChanges,
    JmapQuotaChanges,
    JmapEmailCopy,
    JmapBlobCopy,
    JmapEmailImport,
    JmapEmailParse,
    JmapEmailQueryChanges,
    JmapMailboxQueryChanges,
    JmapEmailSubmissionQueryChanges,
    JmapSieveScriptQueryChanges,
    JmapPrincipalQueryChanges,
    JmapQuotaQueryChanges,
    JmapEmailQuery,
    JmapMailboxQuery,
    JmapEmailSubmissionQuery,
    JmapSieveScriptQuery,
    JmapPrincipalQuery,
    JmapQuotaQuery,
    JmapSearchSnippet,
    JmapSieveScriptValidate,
    JmapBlobLookup,
    JmapBlobUpload,
    JmapEcho,

    // IMAP
    ImapAuthenticate,
    ImapAclGet,
    ImapAclSet,
    ImapMyRights,
    ImapListRights,
    ImapAppend,
    ImapCapability,
    ImapId,
    ImapCopy,
    ImapMove,
    ImapCreate,
    ImapDelete,
    ImapEnable,
    ImapExpunge,
    ImapFetch,
    ImapIdle,
    ImapList,
    ImapLsub,
    ImapNamespace,
    ImapRename,
    ImapSearch,
    ImapSort,
    ImapSelect,
    ImapExamine,
    ImapStatus,
    ImapStore,
    ImapSubscribe,
    ImapThread,

    // POP3
    Pop3Authenticate,
    Pop3List,
    Pop3Uidl,
    Pop3Stat,
    Pop3Retr,
    Pop3Dele,

    // ManageSieve
    SieveAuthenticate,
    SieveListScripts,
    SieveSetActive,
    SieveGetScript,
    SievePutScript,
    SieveDeleteScript,
    SieveRenameScript,
    SieveCheckScript,
    SieveHaveSpace,

    // API keys
    ApiKeyList,
    ApiKeyGet,
    ApiKeyCreate,
    ApiKeyUpdate,
    ApiKeyDelete,

    // OAuth clients
    OauthClientList,
    OauthClientGet,
    OauthClientCreate,
    OauthClientUpdate,
    OauthClientDelete,

    // OAuth client registration
    OauthClientRegistration,
    OauthClientOverride,

    #[serde(other)]
    Unknown,
}

impl AccessToken {
    pub fn is_logged_in(&self) -> bool {
        !self.access_token.is_empty()
    }

    pub fn permissions(&self) -> &Permissions {
        &self.permissions
    }

    pub fn is_enterprise(&self) -> bool {
        self.is_enterprise
    }

    pub fn default_url(&self) -> &'static str {
        self.permissions.default_url(self.is_enterprise)
    }
}

impl Permissions {
    pub fn new(permissions: AHashSet<Permission>) -> Self {
        Self(Arc::new(permissions))
    }

    pub fn has_access_all(&self, permission: &[Permission]) -> bool {
        permission.iter().all(|p| self.0.contains(p))
    }

    pub fn has_access_any(&self, permission: &[Permission]) -> bool {
        permission.iter().any(|p| self.0.contains(p))
    }

    pub fn has_admin_access(&self) -> bool {
        self.0.iter().any(Permission::is_admin_permission)
    }

    pub fn has_access(&self, permission: Permission) -> bool {
        self.0.contains(&permission)
    }

    pub fn default_url(&self, is_enterprise: bool) -> &'static str {
        if is_enterprise
            && self.0.contains(&Permission::MetricsList)
            && self.0.contains(&Permission::MetricsLive)
        {
            "/manage/dashboard/overview"
        } else {
            for permission in [
                Permission::IndividualList,
                Permission::GroupList,
                Permission::DomainList,
                Permission::TenantList,
                Permission::MailingListList,
                Permission::RoleList,
                Permission::MessageQueueList,
                Permission::OutgoingReportList,
                Permission::IncomingReportList,
                Permission::SieveRun,
                Permission::LogsView,
                Permission::TracingList,
                Permission::TracingLive,
                Permission::ManageEncryption,
                Permission::ManagePasswords,
            ]
            .iter()
            {
                if self.0.contains(permission) {
                    return match permission {
                        Permission::IndividualList => "/manage/directory/accounts",
                        Permission::GroupList => "/manage/directory/groups",
                        Permission::DomainList => "/manage/directory/domains",
                        Permission::TenantList => "/manage/directory/tenants",
                        Permission::MailingListList => "/manage/directory/lists",
                        Permission::RoleList => "/manage/directory/roles",
                        Permission::MessageQueueList => "/manage/queue/messages",
                        Permission::OutgoingReportList => "/manage/queue/reports",
                        Permission::IncomingReportList => "/manage/reports/dmarc",
                        Permission::ManageEncryption => "/account/crypto",
                        Permission::ManagePasswords => "/account/password",
                        Permission::SieveRun => "/manage/spam/train",
                        Permission::LogsView => "/manage/logs",
                        Permission::TracingList => "/manage/tracing/received",
                        Permission::TracingLive => "/manage/tracing/live",
                        _ => unreachable!(),
                    };
                }
            }

            ""
        }
    }
}

impl AsRef<AccessToken> for AccessToken {
    fn as_ref(&self) -> &AccessToken {
        self
    }
}

impl Permission {
    pub fn is_admin_permission(&self) -> bool {
        matches!(
            self,
            Permission::Impersonate
                | Permission::UnlimitedRequests
                | Permission::UnlimitedUploads
                | Permission::DeleteSystemFolders
                | Permission::MessageQueueList
                | Permission::MessageQueueGet
                | Permission::MessageQueueUpdate
                | Permission::MessageQueueDelete
                | Permission::OutgoingReportList
                | Permission::OutgoingReportGet
                | Permission::OutgoingReportDelete
                | Permission::IncomingReportList
                | Permission::IncomingReportGet
                | Permission::IncomingReportDelete
                | Permission::SettingsList
                | Permission::SettingsUpdate
                | Permission::SettingsDelete
                | Permission::SettingsReload
                | Permission::IndividualList
                | Permission::IndividualGet
                | Permission::IndividualUpdate
                | Permission::IndividualDelete
                | Permission::IndividualCreate
                | Permission::GroupList
                | Permission::GroupGet
                | Permission::GroupUpdate
                | Permission::GroupDelete
                | Permission::GroupCreate
                | Permission::DomainList
                | Permission::DomainGet
                | Permission::DomainCreate
                | Permission::DomainUpdate
                | Permission::DomainDelete
                | Permission::TenantList
                | Permission::TenantGet
                | Permission::TenantCreate
                | Permission::TenantUpdate
                | Permission::TenantDelete
                | Permission::MailingListList
                | Permission::MailingListGet
                | Permission::MailingListCreate
                | Permission::MailingListUpdate
                | Permission::MailingListDelete
                | Permission::RoleList
                | Permission::RoleGet
                | Permission::RoleCreate
                | Permission::RoleUpdate
                | Permission::RoleDelete
                | Permission::PrincipalList
                | Permission::PrincipalGet
                | Permission::PrincipalCreate
                | Permission::PrincipalUpdate
                | Permission::PrincipalDelete
                | Permission::BlobFetch
                | Permission::PurgeBlobStore
                | Permission::PurgeDataStore
                | Permission::PurgeLookupStore
                | Permission::PurgeAccount
                | Permission::Undelete
                | Permission::DkimSignatureCreate
                | Permission::DkimSignatureGet
                | Permission::UpdateSpamFilter
                | Permission::UpdateWebadmin
                | Permission::LogsView
                | Permission::SieveRun
                | Permission::Restart
                | Permission::TracingList
                | Permission::TracingGet
                | Permission::TracingLive
                | Permission::MetricsList
                | Permission::MetricsLive
        )
    }
}
