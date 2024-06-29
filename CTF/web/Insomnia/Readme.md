## Rate: Medium
***
##### Loking at the source code we notice the flag is in the admin profile when we login as admin we can read the flag.
![image](https://github.com/Fire-Null/Write-Ups/assets/131773602/5a8ca55b-3a65-432a-adb8-fd16a82c0dbe)
***
##### we need to become admin some how, looking at the source code there's bunch of files and no any particular vulnerabilities, we need to check the authentication logic.
![image](https://github.com/Fire-Null/Write-Ups/assets/131773602/2a7627c9-52fd-4e8f-92af-c342fe0936f5)
***
##### If we look close we notice the wrong logic , the develope is checking if the `json_data` is NOT equal to 2 `if (!count($json_data) == 2) {` the correct logic would be `if (count($json_data) !== 2) {`
##### Now we know the auth works we can take over the admin account, we can use the admin username and remove the password parameter and get authenticated
![image](https://github.com/Fire-Null/Write-Ups/assets/131773602/807611aa-5e26-466e-a770-ef12a6b68358)
