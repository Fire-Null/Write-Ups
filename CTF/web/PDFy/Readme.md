## Rate: Easy
***
##### Checking the challenge we can see there's a functionality that takes a link and gives you a pdf  of that link.
![Pasted image 20240629150304](https://github.com/Fire-Null/Write-Ups/assets/131773602/e5ef122a-7d2f-4826-99d3-1f90fd1f8118)
***
##### now if we try for a simple ssrf we get a error.
![Pasted image 20240629150403](https://github.com/Fire-Null/Write-Ups/assets/131773602/be6a601c-6d00-40c9-b4f1-a8adf452fdfd)
***
##### And if we look close to this error we notice it is using `wkhtmltopdf` for generating the pdf.
##### After searching we found a existing exploit for this pdf generator.
![Pasted image 20240629151012](https://github.com/Fire-Null/Write-Ups/assets/131773602/ca57ab0a-1e1c-48f4-a77b-15ba2e13b21b)
***
##### Following the exploit we create a local php file that have a redirect to `/etc/passwd` and we give the endpoint to the pdf generator.
![Pasted image 20240629151614](https://github.com/Fire-Null/Write-Ups/assets/131773602/123ac5f8-207d-4bb7-9acf-8b4657053901)
##### Sure enough we got the flag.

