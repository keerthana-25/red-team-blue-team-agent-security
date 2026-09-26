# Portability checklist

Sign and date each row after actually running the commands on that operating system — not after reading them. "Looks right" is not the same as "ran successfully." See `README.md` for the exact commands and `Prototype_Setup_and_Run_Guide.docx` for a detailed walkthrough.

## macOS

| Step | Command | Result | Signed | Date |
|---|---|---|---|---|
| Confirm Python 3.9+ | `python3 --version` | | | |
| Extract and enter the folder | (Finder or `cd`) | | | |
| Run the tests | `python3 -m unittest discover -s tests -v` | Expect `OK` at the end | | |
| Run the sample demo | `python3 run_demo.py --config configs/quick_demo.json` | Expect a comparison table and a demonstration warning | | |
| Start the dashboard | `python3 run_web.py --port 8000` | Expect a URL printed and no traceback | | |
| Open the dashboard | Visit `http://127.0.0.1:8000` in a browser | Expect the Configure view, not an error page | | |
| Run one experiment from the dashboard | Click through Configure → Run | Expect it to reach the Compare view | | |
| Stop the server | Ctrl+C in the terminal | Expect a clean shutdown message | | |

## Windows (PowerShell)

| Step | Command | Result | Signed | Date |
|---|---|---|---|---|
| Confirm Python 3.9+ | `python --version` or `py -3 --version` | | | |
| Extract and enter the folder | (File Explorer or `cd`) | | | |
| Run the tests | `python -m unittest discover -s tests -v` | Expect `OK` at the end | | |
| Run the sample demo | `python run_demo.py --config configs/quick_demo.json` | Expect a comparison table and a demonstration warning | | |
| Start the dashboard | `python run_web.py --port 8000` | Expect a URL printed and no traceback | | |
| Open the dashboard | Visit `http://127.0.0.1:8000` in a browser | Expect the Configure view, not an error page | | |
| Run one experiment from the dashboard | Click through Configure → Run | Expect it to reach the Compare view | | |
| Stop the server | Ctrl+C in the terminal | Expect a clean shutdown message | | |
| Path with a space | Extract to a folder whose path contains a space (e.g. `C:\Users\Your Name\Downloads\RedTeamBlueTeam Prototype`) and re-run the test command from there | Expect no path-quoting errors | | |
| Port already in use | Start the dashboard once, then start it again on the same port in a second window | Expect a clear "port in use" message, not a raw traceback | | |

## What this checklist cannot verify

Whether a *different* Windows or macOS configuration (older Python, a corporate proxy, a restricted execution policy in PowerShell) behaves the same way. Note the exact OS version and Python version next to each signature — "works on my machine" is only useful information when it says which machine.

## Current status

Unsigned. This platform has been tested extensively on Linux (Python 3.9, 3.10, and 3.12, and under a non-UTF-8 locale as a stand-in for a common Windows difference) but has never been run on a real macOS or Windows machine. Do not represent macOS/Windows support as verified until at least one row above in each table carries a real signature and date.
