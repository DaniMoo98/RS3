# Matrix 946 Cache Analysis & Findings

## 📊 Summary of Status
- **Source Cache**: OpenRS2 ID 2429 (Revision 946.1)
- **Indices**: 0–66 + 255 (verified)
- **Encryption**: None (Verified 100% key-less archive)
- **Primary Issue**: Standard Jagex vs. OpenRS2/NXT header mismatch

## 🕵️ Technical Breakdown

### The Compression Conflict
When you run the server, it currently reports "Corruption" or "Invalid Huffman" because of the **ZLB Header**.
*   **Source Format**: `[Z][L][B][0x01][DecompLen (4B)]...`
*   **Expected Format**: `[0x02][CompLen (4B)][DecompLen (4B)]...`

I am currently transcoding the cache to remove this 'ZLB' shell.

### Critical Settings
| Key | Value | Note |
|---|---|---|
| `HUFFMAN_ARCHIVE_ID` | `1` | Found in Index 10 |
| `CACHE_INDEX_COUNT` | `67` | Covers all 946 indices |
| `XTEA_KEYS_PATH` | `""` | No keys needed for revision 946 |

## 🛠️ Verification Tools
I have placed two tools in `C:\RSPS\cache_tools\`:
1.  **`read_jcache.py`**: Reads your raw `.jcache` files.
2.  **`read_cache_native.py`**: Directly reads the server's `.dat2` files to verify my fixes.

## 🚀 Next Steps
1.  **Patch `FlatToDat2Converter.kt`** to strip ZLB markers.
2.  **Re-run conversion**.
3.  **Sync `C:\RSPS\matrix_cpp\cache`** with the new fixed data.
