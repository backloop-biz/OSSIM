##### POWERSHELL #####
Compilare/modificare le seguenti variabili all'interno del file getaudit.ps1
#Variables
$TimeZone = Get-Date -UFormat '%Z' <-- !! NON MODIFICARE !! -->
$PathFolder="c:\audit\365\"
$Latest=$PathFolder+"latest.txt"
$OutputTMP=$PathFolder+"tmp.log"
$OutputLOG=$PathFolder+"audit.log"
$Operation="UserLoggedIn,UserLoginFailed,TeamsSessionStarted,MailboxLogin,FileAccessed,FileAccessedExtended,FileDeleted,FileMoved,FileRenamed,FileMalwareDetected,FolderDeleted,FolderDeletedFirstStageRecycleBin,FolderDeletedSecondStageRecycleBin,FolderMoved,FolderRenamed,TeamsSessionStarted,FileDeletedFirstStageRecycleBin, FileDeletedSecondStageRecycleBin, FileCopied, DocumentSensitivityMismatchDetected,SecureLinkUsed, FileMalwareDetected, PermissionLevelAdded, AccessRequestCreated, AccessRequestAccepted,AccessRequestDenied,AnonymousLinkUsed, SharingSet,SharingInvitationAccepted, SharingInvitationBlocked, AccessRequestCreated, AnonymousLinkCreated,AnonymousLinkUpdated, SharingInvitationCreated,AnonymousLinkCreated, SecureLinkCreated,AccessRequestDenied, FileSyncDownloadedFull, PermissionLevelModified,PermissionLevelAdded,AddedToSecureLink,PermissionLevelsInheritanceBroken,SharingInheritanceBroken, AddMailboxPermissions, HardDelete, Delete user, Reset user password, Set force change user password"

# Authentication section
$AccountAdmin="ACCOUNT ADMINISTRATOR O365"
[string][ValidateNotNullOrEmpty()] $Password = "PASSWORD ACCOUNT"


##### ALIENVAULT #####
Andare nel file di configurazione (/var/ossec/etc/ossec.conf) inserire:
<ossec_config>
    <!-- rules global entry -->
    <rules>
      <decoder>alienvault/decoders/decoder.xml</decoder>
      <decoder>alienvault/decoders/local_decoder.xml</decoder>
    </rules>
  </ossec_config>
  <ossec_config>
    <!-- rules global entry -->
    <rules>
<include>alienvault/rules/local_rules.xml</include>
 </rules>
  </ossec_config>

o in alternatica via web (environment -> detection -> config) [necessario restart da hids control]


Copiare il file local_decoder.xml in /var/ossec/alienvault/decoders/

Copiare il file local_rules.xml in /var/ossec/alienvault/ruless/

Copiare il file ossec-single-line.cfg.local in /etc/ossim/agent/plugins/
