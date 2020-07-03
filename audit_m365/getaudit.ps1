Param
(
    [Parameter(Mandatory = $false)]
    [switch]$Failed,
    [switch]$MFA,
    [Nullable[DateTime]]$StartDate,
    [Nullable[DateTime]]$EndDate
)
#Variables
$TimeZone = Get-Date -UFormat '%Z'
$PathFolder="c:\audit\365\"
$Latest=$PathFolder+"latest.txt"
$OutputTMP=$PathFolder+"tmp.log"
$OutputLOG=$PathFolder+"audit.log"
$Operation="UserLoggedIn,UserLoginFailed,TeamsSessionStarted,MailboxLogin,FileAccessed,FileAccessedExtended,FileDeleted,FileMoved,FileRenamed,FileMalwareDetected,FolderDeleted,FolderDeletedFirstStageRecycleBin,FolderDeletedSecondStageRecycleBin,FolderMoved,FolderRenamed,TeamsSessionStarted,FileDeletedFirstStageRecycleBin, FileDeletedSecondStageRecycleBin, FileCopied, DocumentSensitivityMismatchDetected,SecureLinkUsed, FileMalwareDetected, PermissionLevelAdded, AccessRequestCreated, AccessRequestAccepted,AccessRequestDenied,AnonymousLinkUsed, SharingSet,SharingInvitationAccepted, SharingInvitationBlocked, AccessRequestCreated, AnonymousLinkCreated,AnonymousLinkUpdated, SharingInvitationCreated,AnonymousLinkCreated, SecureLinkCreated,AccessRequestDenied, FileSyncDownloadedFull, PermissionLevelModified,PermissionLevelAdded,AddedToSecureLink,PermissionLevelsInheritanceBroken,SharingInheritanceBroken, AddMailboxPermissions, HardDelete, Delete user, Reset user password, Set force change user password"

# Authentication section
$AccountAdmin="ADMIN"
[string][ValidateNotNullOrEmpty()] $Password = "PASSWORD"
$SecuredPassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $AccountAdmin, $SecuredPassword

#Getting StartDate and EndDate for Audit log

#Check if present latest file aka not first run
if (Test-Path $Latest -PathType leaf)
{
 $StartDateS=Get-Content $Latest -Raw
 $StartDateS = $StartDateS.Replace(".", ":")
 $StartDate = $StartDateS | Get-Date

 Write-Host "Latest file found, read data from that"
} else
{
#If first run set StartDate to 90min before
 $StartDate=(get-date).AddMinutes(-90)
 $StartDate=Get-Date $StartDate 
}

Write-Host "Set StartDate to $StartDate"

#Because event are not available realtime
$EndDate=(get-date).AddMinutes(-30)

Write-Host "Set EndDate to $EndDate"

$StartDateS = '{0:yyyy-MM-dd HH:mm}' -f ($StartDate)
$StartDateS = $StartDateS.Replace(".", ":") + " " + $TimeZone
$EndDateS = '{0:yyyy-MM-dd HH:mm}' -f ($EndDate)
$EndDateS = $EndDateS.Replace(".", ":") + " " + $TimeZone

#$StartDate=$StartDate.AddHours(-2)
#$EndDate=$EndDate.AddHours(-2)
#$StartDate=$StartDate.AddMinutes(-30)
#$EndDate=$EndDate.AddMinutes(-30)

#Create PS session
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $Credential -Authentication Basic -AllowRedirection
Import-PSSession $Session -AllowClobber -DisableNameChecking

#Check if valid session is created
if([string]::IsNullOrEmpty($Session)) {
   Write-Host "Can't create session." -ForegroundColor Red
	 break
}

#Check whether CurrentEnd exceeds EndDate(checks for 1st iteration)
if($CurrentEnd -gt $EndDate)
{
 $CurrentEnd=$EndDate
}

$AggregateResults = 0
$CurrentResult= @()
$CurrentResultCount=0

#Getting audit log for all users for a given time range
$Results=Search-UnifiedAuditLog -StartDate $StartDateS -EndDate $EndDateS -operations $Operation -SessionId s -SessionCommand ReturnLargeSet -ResultSize 5000

 $AllAuditData=@()
 $AllAudits=
 foreach($Result in $Results)
 {
  $AuditData=$Result.auditdata | ConvertFrom-Json
  $AuditData.CreationTime=(Get-Date($AuditData.CreationTime)).ToLocalTime()
  $AllAudits=@{'Index'='O365_Audit_Log';'Login Time'=$AuditData.CreationTime;'User Name'=$AuditData.UserId;'IP Address'=$AuditData.ClientIP;'Operation'=$AuditData.Operation;'Result Status'=$AuditData.ResultStatus;'Workload'=$AuditData.Workload;'SourceFileName'=$AuditData.SourceFileName;'ObjectId'=$AuditData.ObjectId;'UserAgent'=$AuditData.UserAgent;'ClientInfoString'=$AuditData.ClientInfoString}

  $AllAuditData= New-Object PSObject -Property $AllAudits
  $AllAuditData | Sort 'Login Time' | select 'Index','Login Time','User Name','IP Address',Operation,'Result Status','Workload',SourceFileName,ObjectId,UserAgent,ClientInfoString | Export-Csv $OutputTMP -NoTypeInformation -Append
 }
 Write-Progress -Activity "`n     Retrieving audit log from $StartDate to $EndDate.."`n" Processed audit record count: $AggregateResults"

 $AggregateResults +=$Results.count


If($AggregateResults -eq 0)
{
 Write-Host No records found
}
else
{
 if((Test-Path -Path $OutputTMP) -eq "True")
 {
  Write-Host `nThe Output file availble in $OutputTMP -ForegroundColor Green
 }
 Write-Host `nThe output file contains $AggregateResults audit records

#Reorder data
Import-Csv $OutputTMP -Delimiter ',' | sort 'Login Time' | Export-Csv -Path $OutputLOG -NoTypeInformation -Append

}

#Save to file last run
if (Test-Path $Latest -PathType leaf)
{
#Clear content
 Clear-Content $Latest -Force
} else {
#Create file
 New-Item -ItemType File -Force -Path $Latest
}

#$Date=Get-Date
#$Date=Get-Date $Date -Format "yyyy-MM-dd HH:mm:ss"
Add-Content $Latest $EndDate -NoNewline

#Remove temporary file
if (Test-Path $OutputTMP -PathType leaf)
{
	Remove-item $OutputTMP
}

Remove-PSSession $Session
