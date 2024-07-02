## Rate: Easy
***
##### This one is pretty easy after downloading the zip file and extracted it we can see some js code.
![image](https://github.com/Fire-Null/Write-Ups/assets/131773602/2381423f-6e2a-4ee5-bf5f-9dd4f468a346)
***
##### The challange just have one functionality and that is to calculate.
![image](https://github.com/Fire-Null/Write-Ups/assets/131773602/a7ade630-cb1b-42f2-8ee9-06519d1adc20)
***
##### Now checking the code we see is using `eval` in a unsafe way and we can rce out of this.
![image](https://github.com/Fire-Null/Write-Ups/assets/131773602/34f86ad8-a4ff-4eca-af35-e1b09b0b181d)
***
#### And here is the flag and the payload:
```javascript
require('fs').readFileSync('/flag.txt').toString();
```
![image](https://github.com/Fire-Null/Write-Ups/assets/131773602/587e09cf-a347-485a-b1d5-026ff5393f4c)
