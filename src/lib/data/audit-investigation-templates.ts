// One-click canned filters for the Audit Log Investigator - plain data, same
// convention as mdo-baseline-definitions.ts/asr-rule-definitions.ts, so
// adding a fifth template later never needs new UI code, just a new entry.
//
// Every operation name below is a real, Microsoft-documented Operations
// value (verified against Microsoft Learn's audit log activities reference
// and Entra ID audit event documentation, not guessed) - a template's
// usefulness depends entirely on its operation list actually matching what
// Purview logs, so nothing here is invented.
import { AuditInvestigationTemplate } from "../types";

export const AUDIT_INVESTIGATION_TEMPLATES: AuditInvestigationTemplate[] = [
  {
    id: "bec",
    name: "BEC / Mailbox Compromise",
    description:
      "Inbox rule changes, forwarding, delegation grants, and mail access/send activity - the operations Microsoft's own compromised-mailbox investigation guidance centers on.",
    operations: [
      "New-InboxRule",
      "Set-InboxRule",
      "UpdateInboxRules",
      "Set-Mailbox",
      "Add-MailboxPermission",
      "MailItemsAccessed",
      "Send",
      "SendAs",
      "SendOnBehalf",
    ],
  },
  {
    id: "mass_deletion",
    name: "Mass Deletion",
    description: "Exchange item deletions and SharePoint/OneDrive file and folder deletions.",
    operations: [
      "SoftDelete",
      "HardDelete",
      "MoveToDeletedItems",
      "FileDeleted",
      "FileDeletedFirstStageRecycleBin",
      "FileDeletedSecondStageRecycleBin",
      "FolderDeleted",
      "FolderDeletedFirstStageRecycleBin",
    ],
  },
  {
    id: "external_sharing",
    name: "External Sharing / Possible Exfiltration",
    description: "Anonymous links, external sharing invitations, and access requests on SharePoint/OneDrive content.",
    operations: [
      "SharingInvitationCreated",
      "SharingSet",
      "AnonymousLinkCreated",
      "AnonymousLinkUsed",
      "SecureLinkCreated",
      "AddedToSecureLink",
      "CompanyLinkCreated",
      "AccessRequestCreated",
      "AccessRequestApproved",
    ],
  },
  {
    id: "privilege_escalation",
    name: "Privilege Escalation",
    description:
      "Entra ID directory role grants, Exchange RBAC role group changes, and OAuth app consent/role-assignment grants - the three real privilege-escalation vectors in M365.",
    operations: [
      "Add member to role.",
      "Add eligible member to role.",
      "Add scoped member to role.",
      "Update role.",
      "Add app role assignment to service principal.",
      "Consent to application.",
      "Add-RoleGroupMember",
      "New-ManagementRoleAssignment",
    ],
  },
];
