===== Installation =====
1. Save the source files to the target installation location (e.g. C:\passwordcheck\) on an Exchange server. The server needs to have "Exchange Management Shell" installed. There should be following files under the directory:
	a. config.ps1
	b. email_template.html
	c. README.txt
	d. passwordcheck.ps1
2. Install runtime dependencies:
	a. Install DSInternals Powershell Module by following the instruction from: https://www.dsinternals.com/en/downloads/
	b. Install Bcrypt.Net runtime.
		i. Download Bcrypt.Net package (it is a zip file) from: https://bcrypt.codeplex.com/downloads/get/761250
		ii. Unzip the zip package to the bcryptnet directory under the target passwordcheck install location in #1 above. (e.g. C:\passwordcheck\bcryptnet). Note this path can be change in config.ps1 file as well.

===== Run the tool =====
1. Open windows Powershell with Exchange admin login
2. Go to the installation location of the tool. (e.g. C:\passwordcheck)
3. Change the configuration in config.ps1
    a. $adminMailbox: administrator's email address
    b. $activationToken: the activation token
4. (Optional) Modify the email_template.html to customize email to administrator. Be aware of following parameters would be required in the html file. They can be hidden from HTML
	a. {0} is the placeholder for the password leaked user email address
	b. {1} is the placeholder for the password leaked user distinguished name
	c. {2} is the placeholder for the email of the password leaked user's manager if the manager is found in the system.
5. Run '.\passwordcheck.ps1'