## Rate: Easy
***
##### Checking the challenge we can see there's a functionality that takes a link and gives you a pdf  of that link.
![[Pasted image 20240629150304.png]]

##### now if we try for a simple ssrf we get a error.
![[Pasted image 20240629150403.png]]
##### And if we look close to this error we notice it is using `wkhtmltopdf` for generating the pdf.
##### After searching we found a existing exploit for this pdf generator.
![[Pasted image 20240629151012.png]]
##### Following the exploit we create a local php file that have a redirect to `/etc/passwd` and we give the endpoint to the pdf generator.
![[Pasted image 20240629151614.png]]
##### Sure enough we got the flag.

