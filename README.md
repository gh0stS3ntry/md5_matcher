# md5_matcher.py

Triage a list of MD5 hashes: extract them from one or more files, flag any that appear in a known-bad list, and enrich each unique hash with a [VirusTotal](https://www.virustotal.com/) verdict. Results are written to a CSV, and VirusTotal answers are cached locally in SQLite so repeat runs are fast and don't burn API quota.

## Features

- **Regex-based extraction** of 32-character hex strings from any text file (works directly on `md5sum` output)
- **Deduplication across all input files**: each unique hash triggers at most one VirusTotal lookup per run
- **Known-bad matching** against your own list of MD5s (O(1) set lookups)
- **VirusTotal v3 enrichment** with a `Malicious: X / Y` verdict and a link to the GUI report
- **Persistent SQLite cache** so previously queried hashes are never re-queried
- **Built-in throttling** (default 15 s between live queries, matching the public API's 4 requests/min)
- **Live CSV output**: the file is flushed after every hash, so you can `tail -f` it while the script runs

## Requirements

- Python 3.7+
- [`requests`](https://pypi.org/project/requests/) (all other imports are from the standard library)
- A VirusTotal API key

```bash
pip install requests
```

## Setup

Export your VirusTotal API key as an environment variable. The script exits immediately if it is not set.

```bash
export VT_API_KEY="your_virustotal_api_key"
```

## Step 1: Collect the MD5 hashes

Before running the script, generate the list of MD5 hashes to enrich by running the following command against the directory you want to triage:

```bash
find /path/to/directory -type f -exec md5sum {} + > /path/to/save/list_of_md5_hashes.txt
```

This produces a file where each line is `<md5>  <file path>`, for example:

```
d41d8cd98f00b204e9800998ecf8427e  /path/to/directory/empty.txt
```

Tips:

- Run the command with sufficient privileges to read the target directory, otherwise unreadable files will be skipped (with errors on stderr) and will not appear in the list.
- The script only extracts the 32-character hashes from each line; the file paths in this list are not used by the script.

## Step 2: Prepare the known-bad list

Create a plain text file with **one MD5 hash per line**. Lines are trimmed and lowercased, and any line that is not exactly 32 characters is ignored.

```
44d88612fea8a8f36de82e1278abb02f
275a021bbfb6489e54d471899f7db9d1
```

## Step 3: Run the script

```bash
python3 md5_matcher.py -f list_of_md5_hashes.txt -b known_bad_md5.txt
```

Check several hash files in a single run (comma-separated, no spaces required):

```bash
python3 md5_matcher.py \
  -f host1_hashes.txt,host2_hashes.txt,host3_hashes.txt \
  -b known_bad_md5.txt \
  -o results.csv \
  -c vt_cache.db \
  --sleep 15
```

### Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `-f`, `--files` | Yes | | Comma-separated list of files containing hashes to check |
| `-b`, `--badlist` | Yes | | Text file of known-bad MD5 hashes, one per line |
| `-o`, `--output` | No | `enriched_ioc_results.csv` | Output CSV file path |
| `-c`, `--cache` | No | `vt_cache.db` | Path to the SQLite cache database (created if it doesn't exist) |
| `--sleep` | No | `15.0` | Seconds to sleep between live VirusTotal API calls |

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `VT_API_KEY` | Yes | Your VirusTotal API key |

## How it works

1. **Load the bad list** into an in-memory set.
2. **Extract and deduplicate**: every input file is scanned line by line for MD5 hashes. Hashes are lowercased and mapped to the set of input files they appeared in.
3. **Enrich each unique hash**:
   - Check the SQLite cache first. A hit skips the API call and the sleep.
   - On a miss, query `GET /api/v3/files/{hash}` on VirusTotal, cache the result, then sleep for `--sleep` seconds.
4. **Write the CSV**: one row per (hash, input file) pair. A hash found in three files produces three rows but costs only one API call.

## Output

The CSV contains the following columns:

| Column | Description |
|--------|-------------|
| `Hash` | The MD5 hash (lowercase) |
| `File containing the hash` | Name (not full path) of the **input file** the hash was found in |
| `Match Known Bad (Y/N)` | `Y` if the hash is in the known-bad list |
| `Cached (Y/N)` | `Y` if the verdict came from the local cache, `N` if it was a live VirusTotal query |
| `VT Verdict` | See the verdict values below |
| `Link to VT Results` | VirusTotal GUI link for the hash, or `N/A` if none is available |

Example:

```csv
Hash,File containing the hash,Match Known Bad (Y/N),Cached (Y/N),VT Verdict,Link to VT Results
44d88612fea8a8f36de82e1278abb02f,host1_hashes.txt,Y,N,Malicious: 58 / 72,https://www.virustotal.com/gui/file/44d88612fea8a8f36de82e1278abb02f
d41d8cd98f00b204e9800998ecf8427e,host1_hashes.txt,N,Y,Malicious: 0 / 66,https://www.virustotal.com/gui/file/d41d8cd98f00b204e9800998ecf8427e
```

### VT Verdict values

| Verdict | Meaning | Cached? |
|---------|---------|---------|
| `Malicious: X / Y` | X engines flagged the file as malicious out of Y total engine results | Yes |
| `Not Found` | VirusTotal has no record of this hash (HTTP 404) | Yes |
| `Rate Limited (429)` | API quota or rate limit exceeded | No |
| `Unauthorized (Check API Key)` | The API key is invalid or missing permissions (HTTP 401) | No |
| `Connection Error` | Network failure or timeout | No |
| `HTTP <code>` | Any other unexpected status code | Yes (see notes) |

## Mapping results back to file paths

The output CSV identifies which *input list* a hash came from, not the original file path on disk. To find the file(s) behind a flagged hash, search your original `md5sum` output:

```bash
grep 44d88612fea8a8f36de82e1278abb02f list_of_md5_hashes.txt
```

## Notes and limitations

- **Public API quota:** the free VirusTotal API allows 4 requests/minute and a daily quota (500 lookups/day at the time of writing). At the default 15 s sleep, expect roughly 240 uncached lookups per hour. If you have a premium key, lower `--sleep` accordingly.
- **Resuming after interruption or rate limiting:** successful lookups are cached as they happen, so simply re-run the same command and completed hashes are served from the cache. Rate-limited, unauthorized, and connection-error results are not cached, so those hashes are retried on the next run.
- **Stale cache entries:** cached verdicts, including `Not Found`, are never refreshed automatically. If a hash may have since been uploaded or re-analyzed, delete its row (or the whole cache file) to force a new lookup:
  ```bash
  sqlite3 vt_cache.db "DELETE FROM vt_cache WHERE md5 = '<hash>';"
  ```
- **Unexpected HTTP errors are cached:** responses such as `HTTP 500` are stored like valid results, so a transient server error can persist across runs. Clear those rows from the cache if you see them.
- **Interrupted rows:** a `Rate Limited (429)` or `Connection Error` verdict is still written to the CSV for that run. Re-run the script to fill them in.
- **Path false positives:** the extractor matches any standalone 32-character hex string on a line, so a file path or name that happens to contain one will also be treated as a hash.
- **Exit codes:** the script exits with `1` if `VT_API_KEY` is not set or the bad list cannot be read, and `0` otherwise. The exit code does not reflect whether any known-bad matches were found, so check the CSV (`Match Known Bad (Y/N)` = `Y`).
- **Security:** keep your API key out of scripts, shell history, and version control. The cache database and output CSV contain only hashes, verdicts, and links.

## Quick reference

```bash
# 1. Collect hashes
find /path/to/directory -type f -exec md5sum {} + > /path/to/save/list_of_md5_hashes.txt

# 2. Set API key
export VT_API_KEY="your_virustotal_api_key"

# 3. Run
python3 md5_matcher.py -f /path/to/save/list_of_md5_hashes.txt -b known_bad_md5.txt

# 4. Review results
column -s, -t < enriched_ioc_results.csv | less -S
```
