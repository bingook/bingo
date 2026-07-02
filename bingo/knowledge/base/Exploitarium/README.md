https://discord.gg/WytKH65ZR join up for research, help, documentation, and more useful information for those interested.

# Statement

This repo was incomplete when published. 

In regard to AI usage, my fuzzing workflow was automated by AI with a strict workflow. I used GPT-5.3 for ALL the fuzzing, as barely any "thought" is necessary when provided with an efficient workflow. Contrary to the growing narrative that I'm just some random child burning tokens, I DO actually have a degree in the subject and have published multiple papers on fuzzing methodology. I spent years researching and developing new tools and ideas for how to fuzz. You do NOT need a SOTA model to help you identify these issues, I promise! While being able to afford a better model is helpful, my data seems to show that it is only marginal when paired with decent human oversight and a good workflow. None of the actual PoCs themselves were vibe-coded; I did, in fact, hand-type them. I did use AI assistance for RustDesk, however, as I'm not as familiar with the language. The README files are very clearly entirely AI, however, as AI can format a pretty mean Markdown file. I reviewed them to make sure they were accurate.

I'd also like to credit someone for the objdump finding. It turns out, someone beat me to the punch (they also have a better PoC too!). Please give them the credit they deserve:
https://github.com/4D4J/objdump-Out-Of-Bounds-write

# News/Contact

New drops today ;) Biggest thing yet (DELAYED, I PROMISE THE WAIT WILL BE WORTH IT! After this, you guys will *usually* get one new PoC a day)

I've also noticed a surprising amount of "security researchers" aren't able to adjust the PoC to work in their environment. I will broaden the PoCs for those select few...

If you wish to collaborate/discuss with me, contact me on discord @ashdfrkl

Sharing this repo keeps me motivated to continue dropping my findings for you all. 


# Exploitarium

A consolidated archive of my public proof-of-concept and vulnerability research writeups.

Most folders contain one of my former standalone PoC repos, preserved with its original README and tracked files. New research entries are added directly here as self-contained folders.

## Contents

| Folder | Source | Tracked entries |
| --- | --- | ---: |
| `7zip-rar5-motw-chain-poc` | `bd9533f532c1e4ee6af783b9bb49d1133c600e2c` | 3 |
| `anydesk-printer-com-impersonation-poc` | `7491303301093b2d40bee9dadf6b38f757ce78e0` | 4 |
| `c-ares-tcp-uaf-calc-poc` | direct entry, June 24, 2026 | 7 |
| `curl-smtp-expn-recipient-crlf-injection` | direct entry, July 1, 2026 | 3 |
| `docker-cp-copyout-destination-escape` | `d1367b1381736d7f961ac808ce88d4e24a633adc` | 5 |
| `firefox-smartwindow-private-url-exfil-poc` | direct entry, June 24, 2026 | 3 |
| `floci-apigateway-vtl-rce-poc` | direct entry, June 23, 2026 | 3 |
| `flowise-mcp-env-case-bypass-poc` | `ed9fab0086674f1b16467990b33bb9299e93429e` | 3 |
| `ffmpeg-rasc-dlta-calc-poc` | direct entry, June 26, 2026 | 7 |
| `ghidra-12.1.2-rce-ace-calc-poc` | `52dee6362990c03c0d753d074c85428824d46368` | 9 |
| `gitea-act-runner-container-options-poc` | `f06d78fb111732f3e7737f4c07e77ef94c4b64bf` | 4 |
| `gogs-admin-csrf-git-hook-rce-poc` | direct entry, July 1, 2026 | 3 |
| `imagemagick-gs-delegate-hijack-poc` | `8140e8ee0ed78beaf5e8303a795b70b138f5891b` | 5 |
| `ladybird-wasm-esm-host-function-rce-poc` | direct entry, July 1, 2026 | 2 |
| `libarchive-zip-debuginfod-size-boundary` | direct entry, July 1, 2026 | 6 |
| `libssh2-cve-2026-55200-poc` | direct entry, June 23, 2026 | 3 |
| `libssh2-publickey-list-calc-poc` | direct entry, June 25, 2026 | 10 |
| `lunar-modrinth-chain-poc` | `ffd02120708b6503f11585858ce3724872f3b7a7` | 6 |
| `mybb-limited-acp-to-admin` | `1610e0373943c2f6562a99f917d3a3d1fdd9056d` | 5 |
| `nextjs-unstable-cache-object-argument-collision` | direct entry, July 1, 2026 | 3 |
| `nodebb-activitypub-attributedto-local-uid-spoof-poc` | direct entry, July 1, 2026 | 3 |
| `nghttp2-nghttpx-upgrade-queue-poison-poc` | direct entry, June 26, 2026 | 3 |
| `nmap-ipv6-extlen-wrap-poc` | direct entry, June 23, 2026 | 4 |
| `objdump-dlx-calc-poc` | `7df01e4e20c7375a89e8ccf760526c52eb6ad582` | 41 |
| `openvpn-connect-echo-script-ace-poc` | `d2f904d9272d4388c9862131d40e32e072e85e38` | 8 |
| `php857-streambucket-soap-rce-rpoc` | direct entry, June 26, 2026 | 6 |
| `pillow-imagecms-output-mode-oob-poc` | direct entry, July 1, 2026 | 3 |
| `qemu-cxl-type3-mailbox-escape-poc` | direct entry, July 1, 2026 | 7 |
| `rustdesk-session-permission-pocs` | direct entry, June 25, 2026 | 17 |
| `systeminformer-phsvc-trusted-host-lpe-poc` | direct entry, June 24, 2026 | 3 |
| `vlc-vp9-reschange-crash-poc` | `fae72b82f24d03cf2fb9cb55fbb2e7774f684ff3` | 3 |

## Consolidation Check

This section applies to the former standalone repositories listed above by commit hash.

The consolidation was checked from fresh GitHub clones on June 23, 2026 before the old standalone repos were removed.

The check compared each former standalone repo's `HEAD` tree against the matching folder here using Git tree data rather than a loose filesystem diff. For every tracked entry, the check required:

- the same relative path;
- the same Git object type;
- the same tree mode, including executable bits;
- the same Git blob ID.

Matching Git blob IDs means the tracked file bytes are identical. The check covered 12 repos and 96 tracked entries with zero mismatches.

This repository preserves the contents of those PoCs. Repository-level metadata such as stars, issues, pull requests, releases, and separate Git history remain in the original repository histories.

Direct entries, including `c-ares-tcp-uaf-calc-poc`, `curl-smtp-expn-recipient-crlf-injection`, `ffmpeg-rasc-dlta-calc-poc`, `firefox-smartwindow-private-url-exfil-poc`, `floci-apigateway-vtl-rce-poc`, `gogs-admin-csrf-git-hook-rce-poc`, `ladybird-wasm-esm-host-function-rce-poc`, `libarchive-zip-debuginfod-size-boundary`, `libssh2-cve-2026-55200-poc`, `libssh2-publickey-list-calc-poc`, `nextjs-unstable-cache-object-argument-collision`, `nodebb-activitypub-attributedto-local-uid-spoof-poc`, `nghttp2-nghttpx-upgrade-queue-poison-poc`, `nmap-ipv6-extlen-wrap-poc`, `php857-streambucket-soap-rce-rpoc`, `pillow-imagecms-output-mode-oob-poc`, `qemu-cxl-type3-mailbox-escape-poc`, `rustdesk-session-permission-pocs`, and `systeminformer-phsvc-trusted-host-lpe-poc`, are tracked by this repository's commit history.

## ABUSE

Do NOT, under any circumstances, use any material in this repository maliciously. This is good-faith, open-disclosure vulnerability research intended to get more people interested in exploring this area of cybersecurity. 

Cybercrime is cringe.
