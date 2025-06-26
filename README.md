# 🕷️ jsfuzzer – Fast JS Link Fuzzer for Secrets, IPs, Keys & Endpoints

`jsfuzzer` is a fast, concurrency-enabled CLI tool written in Go that scans JavaScript files for:
- 🔐 API keys, tokens, secrets  
- 🌐 Endpoints and paths  
- 🧠 Interesting strings (IPs, JWTs, etc.)

---

## 🚀 Features

- ✅ Scan a single URL or a list of URLs  
- ✅ Read URLs from piped input  
- ✅ Extract secrets and endpoints using built-in regex  
- ✅ Custom regex support with `-regex`  
- ✅ Add custom HTTP headers (e.g., Authorization)  
- ✅ Prepend base URLs to relative endpoints  
- ✅ Output to file or stdout  
- ✅ Fully deduplicated output, easy to pipe to `anew`, `notify`, etc.  

---

## 🛠️ Installation

### From Source (requires Go 1.18+)

```bash
go install github.com/byteoverride/jsfuzzer@latest
```
## 📦 Usage
```bash
jsfuzzer [flags]
```
| Task                      | Command Example                                                                         |
| ------------------------- | --------------------------------------------------------------------------------------- |
| Scan single JS URL        | `jsfuzzer -u https://site.com/main.js`                                                 |
| Scan from file            | `jsfuzzer -l jsurls.txt`                                                               |
| Scan with piped input     | `cat jsurls.txt \| jsfuzzer`                                                           |
| Use custom regex          | `jsfuzzer -u https://site.com/main.js -r '^/api/'`                                     |
| Add custom headers        | `jsfuzzer -u https://site.com/js --headers "Authorization:Bearer X,User-Agent:Hacker"` |
| Prepend base to endpoints | `jsfuzzer -u https://site.com/js --base https://site.com`                              |
| Save results to file      | `jsfuzzer -u https://site.com/main.js -o results.txt`                                  |

### NOTE
- The **--base** is used to append the base url to the endpoint output
- Take the IPs found with a grain of Salt its regex isnt perfect verfy the IP by searching it in the JS and confirm

## 📌Flags 

| Flag           | Description                                          |
| -------------- | ---------------------------------------------------- |
| `-u, --url`    | Single JavaScript URL to scan                        |
| `-l, --list`   | File containing list of JS URLs                      |
| `-o, --output` | Output file to write results                         |
| `-r, --regex`  | Custom regex to filter output (e.g. `^/api/`)        |
| `--headers`    | Custom HTTP headers: `Header1:Value1,Header2:Value2` |
| `--base`       | Base URL to prepend to relative endpoints            |
| `-h, --help`   | Show help message                                    |

