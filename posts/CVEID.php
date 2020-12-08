<p>Software: Custom API 
Version: <= 1.2
Discovered by: Akshay Jain 
Vulnerability: Account takeover 
Description:
i have found that it's possible to abuse autocompletion feature to retrieve sensitive data from any user, using an unprivileged account.
Besides hashed session cookies or api keys in cleartext, a malicious user can retrieve the password_forget_token atributte which leads to account takeover when "Reset password" feature is enabled.
The steps are the following:
    1. Choose a known email or get a list of them using autocompletion
        GET /api/customer/login
   2. Click on reset password link in mail which looks like this
        GET /api/resetpassword/ 
    3. Invoke "Lost password" with target email
    4. the responce shows the attacker email from which password reset was inittiated change the email and send the responce 
 
    5. Login with new password with target email
    
To sum up: an unprivileged user could steal any account or escalate privileges by changing super-admin password. It's also possible to steal admins' api keys and use them with malicious purposes.</p>
 <div class="post-content"> <img src="1.png">
 <div class="post-content"> <img src="2.png">
 <div class="post-content"> <img src="3.png">
