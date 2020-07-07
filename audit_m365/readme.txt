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

All'interno del local decoder (/var/ossec/alienvault/decoders/local_decoder.xml) inserire:
<decoder name="o365">
<prematch>"O365_Audit_Log"</prematch>
<regex>"O365_Audit_Log","\S+ \S+","(\S+)","(\S+)"</regex>
<order>user,srcip</order>
<fts>user</fts>
</decoder>

All'interno delle local rules (/var/ossec/alienvault/ruless/local_rules.xml) inserire:
<group name="o365">
  <rule id="100003" level="1">
    <decoded_as>o365</decoded_as>
    <description>Office365 audit messages.</description>
  </rule>
  <rule id="100004" level="3">
   <if_sid>100003,100002</if_sid>
    <match>"AzureActiveDirectory"</match>
    <description>Office365 AzureAD  Log</description>
  </rule>

  <rule id="100005" level="2">
   <if_sid>100004</if_sid>
    <match>UserLoggedIn</match>
    <description>Office365 AzureAD Logon success</description>
  </rule>

  <rule id="100006" level="2">
   <if_sid>100004</if_sid>
    <match>UserLoginFailed</match>
    <description>Office365 AzureAD Logon failed</description>
  </rule>

<rule id="100101" level="10" frequency="5" timeframe="3600">
    <if_matched_sid>100006</if_matched_sid>
    <same_source_ip />
    <description>Multiple failed login on AzureAD.</description>
  </rule>

<!-- DOPPIA??
 <rule id="100007" level="2">
   <if_sid>100003</if_sid>
    <match>AzureActiveDirectory</match>
    <description>Office365 AzureAD</description>
  </rule>
-->
 <rule id="100008" level="3">
   <if_sid>100004</if_sid>
    <match>Add user</match>
    <description>Office365 AzureAD Add User</description>
  </rule>

 <rule id="100009" level="3">
   <if_sid>100004</if_sid>
    <match>"Delete user</match>
    <description>Office365 AzureAD Delete User</description>
  </rule>

 <rule id="100010" level="3">
   <if_sid>100004</if_sid>
    <match>Update user</match>
    <description>Office365 AzureAD Update User</description>
  </rule>

 <rule id="100011" level="3">
   <if_sid>100004</if_sid>
    <match>Change user license</match>
    <description>Office365 AzureAD Update License</description>
  </rule>

 <rule id="100012" level="3">
   <if_sid>100002,100003</if_sid>
    <match>"Exchange"</match>
    <description>Office365 Exchange Log</description>
  </rule>

  <rule id="100013" level="2">
   <if_sid>100012</if_sid>
    <match>"MailboxLogin","Succeeded"</match>
    <description>Office365 Exchange Logon success</description>
  </rule>

  <rule id="100014" level="2">
   <if_sid>100012</if_sid>
    <match>"MailboxLogin","Failed"</match>
    <description>Office365 Exchange Logon failed</description>
  </rule>

<rule id="100103" level="10" frequency="5" timeframe="3600">
    <if_matched_sid>100014</if_matched_sid>
    <same_source_ip />
    <description>Multiple failed login on Exchange.</description>
  </rule>


<rule id="100015" level="3">
   <if_sid>100002,100003</if_sid>
    <match>"OneDrive"</match>
    <description>Office365 OneDrive Log</description>
  </rule>

  <rule id="100016" level="2">
   <if_sid>100015</if_sid>
    <match>"FileAccessed"</match>
    <description>Office365 OneDrive File accessed</description>
  </rule>

  <rule id="100017" level="2">
   <if_sid>100015</if_sid>
    <match>"FileDeleted"</match>
    <description>Office365 OneDrive File deleted</description>
  </rule>

<rule id="100102" level="10" frequency="10" timeframe="3600">
    <if_matched_sid>100017</if_matched_sid>
    <same_source_ip />
    <description>Multiple file deleted on onedrive.</description>
    <group>recon,</group>
  </rule>


<rule id="100018" level="2">
   <if_sid>100015</if_sid>
    <match>"FileDeletedFirstStageRecycleBin"</match>
    <description>Office365 OneDrive File deleted firt recycle</description>
  </rule>

<rule id="100019" level="2">
   <if_sid>100015</if_sid>
    <match>"FileDeletedSecondStageRecycleBin"</match>
    <description>Office365 OneDrive File deleted second recycle</description>
  </rule>

 <rule id="100020" level="2">
   <if_sid>100015</if_sid>
    <match>"FileMoved"</match>
    <description>Office365 OneDrive File moved</description>
  </rule>

<rule id="100021" level="2">
   <if_sid>100015</if_sid>
    <match>"FileRenamed"</match>
    <description>Office365 OneDrive File renamed</description>
  </rule>

<rule id="100022" level="2">
   <if_sid>100015</if_sid>
    <match>"FileMalwareDetected"</match>
    <description>Office365 OneDrive File malware detected</description>
  </rule>

<rule id="100023" level="2">
   <if_sid>100015</if_sid>
    <match>"FolderDeleted"</match>
    <description>Office365 OneDrive Folder deleted</description>
  </rule>

<rule id="100024" level="2">
   <if_sid>100015</if_sid>
    <match>"FolderDeletedFirstStageRecycleBin"</match>
    <description>Office365 OneDrive Folder deleted first recycle</description>
  </rule>

<rule id="100025" level="2">
   <if_sid>100015</if_sid>
    <match>"FolderDeletedSecondStageRecycleBin"</match>
    <description>Office365 OneDrive Folder deleted second recycle</description>
  </rule>

 <rule id="100026" level="2">
   <if_sid>100015</if_sid>
    <match>"FolderMoved"</match>
    <description>Office365 OneDrive Folder moved</description>
  </rule>

<rule id="100027" level="2">
   <if_sid>100015</if_sid>
    <match>"FolderRenamed"</match>
    <description>Office365 OneDrive Folder renamed</description>
  </rule>

<rule id="100028" level="3">
   <if_sid>100004</if_sid>
    <match>"Hard Delete user</match>
    <description>Office365 AzureAD HARD Delete User</description>
  </rule>

<rule id="100029" level="2">
   <if_sid>100015</if_sid>
    <match>"FileSyncDownloadedFull"</match>
    <description>Office365 OneDrive FileSyncDownloadedFull</description>
  </rule>

<rule id="100030" level="3">
   <if_sid>100002,100003</if_sid>
    <match>"MicrosoftTeams"</match>
    <description>Office365 Teams Log</description>
  </rule>

  <rule id="100031" level="2">
   <if_sid>100030</if_sid>
    <match>"TeamsSessionStarted"</match>
    <description>Office365 Teams session started</description>
  </rule>

<rule id="100036" level="2">
   <if_sid>100015</if_sid>
    <match>"AccessRequestCreated"</match>
    <description>Office365 OneDrive AccessRequestCreated</description>
  </rule>

<rule id="100037" level="2">
   <if_sid>100015</if_sid>
    <match>"AnonymousLinkCreated"</match>
    <description>Office365 OneDrive AnonymousLinkCreated</description>
  </rule>

<rule id="100038" level="2">
   <if_sid>100015</if_sid>
    <match>"PermissionLevelAdded"</match>
    <description>Office365 OneDrive PermissionLevelAdded</description>
  </rule>

<rule id="100039" level="2">
   <if_sid>100015</if_sid>
    <match>"FileAccessedExtended"</match>
    <description>Office365 OneDrive FileAccessedExtended</description>
  </rule>

 <rule id="100040" level="3">
   <if_sid>100003,100002</if_sid>
    <match>"SharePoint"</match>
    <description>Office365 SharePoint Log</description>
  </rule>

 <rule id="100041" level="2">
   <if_sid>100040</if_sid>
    <match>"FileAccessed"</match>
    <description>Office365 SharePoint FileAccessed</description>
  </rule>

  <rule id="100050" level="2">
   <if_sid>100012</if_sid>
    <match>"HardDelete","Succeeded"</match>
    <description>Office365 Exchange HardDelete</description>
  </rule>

<rule id="100060" level="2">
   <if_sid>100015</if_sid>
    <match>"AnonymousLinkUsed"</match>
    <description>Office365 OneDrive AnonymousLinkUsed</description>
  </rule>

<rule id="100061" level="2">
   <if_sid>100015</if_sid>
    <match>"AnonymousLinkUpdated"</match>
    <description>Office365 OneDrive AnonymousLinkUpdated</description>
  </rule>

<rule id="100062" level="2">
   <if_sid>100015</if_sid>
    <match>"FileCopied"</match>
    <description>Office365 OneDrive FileCopied</description>
  </rule>

<rule id="100063" level="2">
   <if_sid>100015</if_sid>
    <match>"SharingInheritanceBroken"</match>
    <description>Office365 OneDrive SharingInheritanceBroken</description>
  </rule>

<rule id="100064" level="2">
   <if_sid>100015</if_sid>
    <match>"SharingSet"</match>
    <description>Office365 OneDrive SharingSet</description>
  </rule>
</group>
