#Created 11/19/2021
#By: Alan Newingham
#Get all locked out accounts, time stamp, and device name when failed attempt took place. Export to CSV. Email CSV. Delete CSV after Email.

Function Get-Lockouts {
    [CmdletBinding(
        DefaultParameterSetName = 'All'
    )]
    param (
        [Parameter(
            ValueFromPipeline = $true,
            ParameterSetName = 'ByUser'
        )]
    )
    Begin{
        $filterHt = @{
            LogName = 'Security'
            ID = 4740
        }
        if ($PSBoundParameters.ContainsKey('StartTime')){
            $filterHt['StartTime'] = $StartTime
        }
        if ($PSBoundParameters.ContainsKey('EndTime')){
            $filterHt['EndTime'] = $EndTime
        }
        $PDCEmulator = (Get-ADDomain).PDCEmulator
        # Query the event log just once instead of for each user if using the pipeline
        $events = Get-WinEvent -ComputerName $PDCEmulator -FilterHashtable $filterHt
    }
    Process {
        if ($PSCmdlet.ParameterSetName -eq 'ByUser'){
            $user = Get-ADUser $Identity
            # Filter the events
            $output = $events | Where-Object {$_.Properties[0].Value -eq $user.SamAccountName}
        } else {
            $output = $events
        }
        foreach ($event in $output){
            [pscustomobject]@{
                UserName = $event.Properties[0].Value
                CallerComputer = $event.Properties[1].Value
                TimeStamp = $event.TimeCreated
            }
        }
    }
    End{}
}

#End of function, let's do this.
$date = (Get-Date -Format "yyyy-MM-dd")

#What is the file location appended with my date format?
$file = 'C:\temp\AccountLockouts' + $date + '.csv'

#Run function, Pipe to csv with date, notype, and out-null helps with determining if the command finished running.
Get-Lockouts | Export-Csv -Path $file -NoTypeInformation | Out-Null

#Wait till file is completed, then continue. 
while (!(Test-Path $file)) { Start-Sleep 1 }

#All for email
$username = "noreply@contoso.com"
$password = "SWYgcGllIGlzIGdyZWF0IHRoYW4gSSBhbSBhbiBpZGlvdCE="
$sstr = ConvertTo-SecureString -string $password -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential -argumentlist $username, $sstr
$Attachment = 'C:\temp\AccountLockouts' + $date + '.csv'
$body = "<h1> IT AD Account Lockout Report</h1><br><br>"
$body += "Attached is a queried list of AD accounts that have been locked out.<br>"
$body += "<br><br><br><br><br><br><br>"
$body += 'This automation was created and is maintained by 01000001-01001110.<br>' 
$body += 'Should you find the automation is failing in any way please let me know <a href="https://github.com/01000001-01001110/FailedLoginAttempts">here</a> <br>'
$body += "<br><br><br><br><br><br><br>"
$body += "Report Ran: $date"
Send-MailMessage -To "importantpeople@contoso.com" -from "noreply@contoso.com" -Subject 'AD Account Lockout Report' -Body $body -BodyAsHtml -Attachments $Attachment -smtpserver smtp.office365.com -usessl -Credential $cred -Port 587
#Waste not, delete the file after sending.
Remove-Item $file


