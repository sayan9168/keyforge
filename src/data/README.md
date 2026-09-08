# EFF long wordlist

`eff-words.json` contains the 7,776 words from the **EFF Large Wordlist**, created by Joseph Bonneau and the Electronic Frontier Foundation (2016).

- Original: https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt
- Generation guidance: https://www.eff.org/dice
- Retrieval mirror: https://github.com/ulif/diceware/blob/master/diceware/wordlists/wordlist_en_eff.txt
- SHA-256 of the retrieved source text: `addd35536511597a02fa0a9ff1e5284677b8883b83e986e43f15a3db996b903e`
- The mirror declares this particular wordlist **CC BY 3.0**, independently of that project's GPL-licensed application code. Attribution/license: https://creativecommons.org/licenses/by/3.0/ and https://www.eff.org/copyright

The transformation removes the dice indices and serializes the words as a compact JSON array. No words, spelling, hyphenation, or ordering have been changed. No code from the mirror project is used.

Keep the wordlist bundled locally rather than loading it from a CDN. The generator uses space, dot, or underscore separators; none occurs inside these words. Tests verify the full count, uniqueness, alphabet assumptions, and separator safety. Deterministic capitalization changes presentation only.

Public attribution is also distributed in `public/credits.txt`, accessible through the application footer.
