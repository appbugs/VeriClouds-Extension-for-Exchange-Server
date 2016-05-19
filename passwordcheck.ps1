. 'C:\Program Files\Microsoft\Exchange Server\V15\bin\RemoteExchange.ps1'

Connect-ExchangeServer -auto -ClientApplication:ManagementShell

. '.\config.ps1'

# preparation
$resultTypeDef = @"
public class Result {      
    public string result;
	public class Hash_algorithm {
		public string ca_hash;
		public string ca_salt;
	}
	public class Record {
		public string email;
		public string password_hash;
		public Hash_algorithm hash_algorithm;
	}
	public Record[] records;
}
"@;

add-type -TypeDefinition $resultTypeDef;

add-type -AssemblyName "System.Runtime.Serialization"

add-type -path $bcryptNetPath

# iterating mailboxes
$mailboxes=get-mailbox -RecipientTypeDetails UserMailbox -ResultSize Unlimited;

$mailboxes | foreach {
	$mbx = $_;
	$upn = $_.UserPrincipalName.ToLower();
	$upnParts = $upn.Split('@');
	$username = $upnParts[0];
	$dnsDomain = $upnParts[1];
	$dn = $_.DistinguishedName;
	
	$url = new-object System.Uri ($passwordCheckServiceUrlTemplate+$activationToken+"&email="+$upn)
	$request = [System.Net.HttpWebRequest]::Create($url);
	$response = [System.Net.HttpWebResponse]($request.GetResponse());
	$resStream = $response.GetResponseStream();
	
	$tempString = $null;
	$count = 0;
	$sb = new-object System.Text.StringBuilder;
	$buf = new-object byte[] 8192;
	#read the data and print it
	do {
		$count = $resStream.Read($buf, 0, $buf.Length);
		if ($count -ne 0) {
			$tempString = [System.Text.Encoding]::ASCII.GetString($buf, 0, $count);
			$sb = $sb.Append($tempString);
		}
	} while ($count -gt 0);
	$jsonStr = $sb.ToString();
	write-host $jsonStr
	$jsonBytes = [System.Text.Encoding]::Unicode.GetBytes($jsonStr);
	$result = $null;
	$ms = $null;
	
	try{
		$ms = new-object System.IO.MemoryStream (,$jsonBytes);
        $serializer = new-object System.Runtime.Serialization.Json.DataContractJsonSerializer (new-object Result).GetType();
        $result = $serializer.ReadObject($ms);
	} finally{
	    if ($null -ne $ms)
        {
            $ms.Dispose()
        }
	}
	
	if (($result -ne $null) -and ($result.result -eq 'succeeded')) {
		$matched = $false;
		
		if ($result.records.Length -gt 0) {
			$result.records | foreach {
				$record = $_
				if ($_.email -eq $upn) {
					if ($_.hash_algorithm.ca_hash -eq 'bcrypt') {
						#comparing hash
						$dc = get-addomaincontroller -domainname $dnsDomain -discover:$false
						$account = Get-ADReplAccount -DistinguishedName $dn -server $dc
						$md5Hash = $null;
						if ($account -ne $null) {
							$md5Hash = $account.SupplementalCredentials.WDigest[8]
							$md5HashString = [string]::Format("{0:x2}{1:x2}{2:x2}{3:x2}{4:x2}{5:x2}{6:x2}{7:x2}{8:x2}{9:x2}{10:x2}{11:x2}{12:x2}{13:x2}{14:x2}{15:x2}",
								$md5Hash[0], $md5Hash[1], $md5Hash[2], $md5Hash[3], $md5Hash[4], $md5Hash[5], $md5Hash[6], $md5Hash[7],
								$md5Hash[8], $md5Hash[9], $md5Hash[10], $md5Hash[11], $md5Hash[12], $md5Hash[13], $md5Hash[14], $md5Hash[15]);
							write-host $md5HashString
							write-host $record.hash_algorithm.ca_salt
							$bcryptHash = [BCrypt.Net.BCrypt]::HashPassword($md5HashString, $record.hash_algorithm.ca_salt);
							
							$bad_hashes = $_.password_hash.Split(',');
							$bad_hashes | foreach {
								if ($bcryptHash -eq $_) {
									#matched
									$matched = $true;
									write-host "Matched record: $upn" -ForegroundColor Red;

									#setting attribute to show in admin panel
									invoke-expression "set-mailbox $upn -$attributeToSet `"$valueOfAttribute`""
									write-host "Successfully marked user in admin panel" -ForegroundColor Green;
									
									#getting the user's manager
									$user = get-user $upn
									$managerId = $user.Manager
									$managerNotificationText = ""
									if ($managerId -ne $null) {
										$manager = get-mailbox $managerId;
										if ($manager -ne $null) {
											$managerEmail = $manager.PrimarySmtpAddress.ToString();
											$managerName = $manager.DisplayName;
											$managerNotificationText = "Send an email to <a href='mailto:$managerEmail'>$managerName</a>."
										}
									}

									#send email to admin
									$emailBody = get-content ".\email_template.html" -raw
									send-mailmessage -BodyAsHtml ($emailBody -f $upn,$mbx.DistinguishedName,$managerNotificationText) -From $adminMailbox -To $adminMailbox -SmtpServer (get-transportserver -warningaction silent)[0].Name -Subject "[Security Alter] User password leaked!" -UseSsl
									write-host "Successfully sent alert email to administrator!" -ForegroundColor Green;
								}
							}
						}
					}
				}
			}
		}
		
		# Clearing the attribute when it is found not matching any longer
		if ($matched -ne $true) {
			$originalAttribute = invoke-expression "`$mbx.$attributeToSet";
			if ($originalAttribute -eq $valueOfAttribute) {
				invoke-expression "set-mailbox $upn -$attributeToSet `$null"
				write-host "Successfully cleared the password leaked state for user $mbx." -ForegroundColor Green;
			}
		}
	}
}