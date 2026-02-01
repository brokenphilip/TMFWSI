# TrackMania Forever Web Services Interceptor
TMFWSI intercepts traffic to TrackMania Forever Web Services (`ws.trackmania.com`) on your local machine, "fixing" bugs such as:
- "`http error 12170`", from the in-game Manialink browser
- "`ERR_SSL_VERSION_OR_CIPHER_MISMATCH`", from a Chromium browser
- `ERROR_INTERNET_SEC_CERT_REVOKED` or `CRYPT_E_REVOKED` - "The SSL certificate was revoked"

By doing so, this allows you to log-in to the following services:
- [home.trackmania.com](http://home.trackmania.com/) web page, to check your linked forums & authorized applications
- [developers.trackmania.com](http://developers.trackmania.com/) web page, to access the Web Services API
- [maniapub](http://maniapub.trackmania.com/) Manialink, to manage your in-game Manialink advertisements
- [freezone:servers](http://dedicp.maniastudio.com/) Manialink, to manage your FreeZone servers
- any other website or Manialink not listed here which uses `ws.trackmania.com` for authentication

> [!NOTE]
> As of CoreMod 1.07 ([TrackMania ModLoader](https://tomashu.dev/software/tmloader/)), the aformentioned bugs have been fixed - if you only need access to in-game Manialinks, it is recommended to use CoreMod/ModLoader instead of TMFWSI.

> [!CAUTION]
> **Do not, under any circumstances, connect to anyone else's TMFWSI instance**, by editing the `hosts` file manually or otherwise. You should only self-host TMFWSI locally on your machine, and the project is designed in such a way to make this process as easy as possible.

> [!WARNING]
> Generally speaking, this is a **very unsafe** way of communicating sensitive (login) data to a server and should merely be used as a temporary workaround for those that require the above listed services, hence why the word "fixing" was put in quotes in the first paragraph - a proper fix would be for the maintainers of the TMF Web Services to renew its certificates and employ better security practices overall.

> [!WARNING]
> It is not uncommon for `ws.trackmania.com` to give broken responses. This is an issue on Nadeo's end and unfixable/out-of-scope for this project.

## Usage
1. Head over to [Releases](https://github.com/brokenphilip/TMFWSI/releases) and download the latest `TMFWSI.zip`
2. Extract the the contents of the zip archive wherever you'd like
   - To avoid file permission issues, do **not** extract TMFWSI in the following locations:
      - "Program Files", as well as "Program Files (x86)", or any of their subdirectories
      - The root of your operating system drive, usually `C:\`
      - Your user profile (`%USERPROFILE%`), the Documents folder (`%USERPROFILE%\Documents`) or your Desktop (`%USERPROFILE%\Desktop`)
4. When you need to access `ws.trackmania.com` or anything which uses it (ie. the services listed above), simply run the program
   - TrackMania Nations/United Forever, as well as some web browsers, will need to be restarted first
5. Whenever you're done, break out of the program using <kbd>Ctrl</kbd> + <kbd>C</kbd> or simply close it

### Launch parameters
- `-debug` - Launches TMFWSI in debug mode - currently, this only shows `DEBUG` prints in the console
- `-ip x.x.x.x` - Starts the SSL server with a custom IP address `x.x.x.x` instead of the default `127.87.83.73`
- `-logging` - Saves all console prints (except for `DEBUG`) to `tmfwsi.log` in the same location as the program
- `-logging verbose` - Saves all console prints (including `DEBUG`) to `tmfwsi.log` in the same location as the program
- `-no-hosts` - Won't automatically update the `hosts` file, but it will need to be done manually, see [below](https://github.com/brokenphilip/TMFWSI#modifying-the-hosts-file-manually)
- `-no-pause` - Won't prompt the user to press <kbd>Enter</kbd> when the program shuts down
- `-no-update` - Won't check GitHub for program updates, **not recommended**

## Troubleshooting and common problems
If you encounter any issues during installation or usage that hasn't been mentioned below, please refer to the [issue tracker](https://github.com/brokenphilip/TMFWSI/issues?q=). If you haven't found your issue, feel free to create a new one. If you have any further questions about the project, or if (understandably) using the issue tracker is too confusing, feel free to add me on Discord (`brokenphilip`) and I will try to get back to you as soon as possible. :)

### `Couldn't connect to server (CURLcode: 7)`
No internet connection, or, in the case of fetching the IP address of the TrackMania Forever Web Services, usually means there already is an entry for it in the `hosts` file, created by TMFWSI or someone/something else. TMFWSI should almost always remove the `hosts` file entry automatically upon shutdown, but in the case it does not, a backup file named can be found in the same folder as the program. For more information, see [below](https://github.com/brokenphilip/TMFWSI#modifying-the-hosts-file-manually).

### `An operation is not supported on a directory.  (Code: 336)`
Upon trying to access the file in question, it came across a folder with the same name. Files and folders cannot have identical names within the same directory. Delete the folder and try again.

### `The specified file is read only.  (Code: 6009)`
Upon trying to access the file in question, it was flagged as read-only. Remove the read-only flag from the file and try again.

### `The operation was canceled by the user.  (Code: 1223)`
In the case of `hosts` file modification, specifically `ShellExecuteEx`, User Account Control prompted you to run TMFWSI as an administrator and it was declined. TMFWSI itself does not require administrator access, it is only used when creating a new sub-process for modifying the `hosts` file, which is a necessary step for the program to work. Either give TMFWSI permission to run as admin, or disable `hosts` file editing by starting TMFWSI with the `-no-hosts` launch parameter (but you will have to modify the `hosts` file yourself, see [below](https://github.com/brokenphilip/TMFWSI#modifying-the-hosts-file-manually)).

### `http error 12170`
Either TMFWSI is not running, or it is running, but you have not restarted your game yet. Shut down TrackMania (Nations/United) Forever, launch TMFWSI and try again.

It is also possible that the `hosts` file has not been modified, either due to an error, or it's been disabled using the `-no-hosts` launch parameter. The hosts file must be modified for TMFWSI to work, either automatically by the program itself or manually by the user (for more information, see [below](https://github.com/brokenphilip/TMFWSI#modifying-the-hosts-file-manually)).

## Modifying the `hosts` file manually
The plain-text `hosts` file can be found in `%WINDIR%\System32\drivers\etc` and can be modified using a text editor such as `Notepad`. It is recommended you create a backup of the `hosts` file and keep it somewhere safe, in case you need to recover it.

### On startup
When you're running TMFWSI with the `-no-hosts` launch parameter, you will need to add the following entry to the bottom of the `hosts` file:
```
// TrackMania Forever Web Services Interceptor
x.x.x.x	ws.trackmania.com
```
...where `x.x.x.x` is the IP of TMFWSI's SSL server (**not** the TrackMania Forever Web Services IP), found in the console output line "`SSL server started - listening to requests on x.x.x.x:443`". By default, this should be `127.87.83.73`, unless specifically changed by the `-ip` launch parameter. The first line is optional, but recommended - as it starts with a `//`, it indicates that the line is a comment, purely for informational purposes.

### On shutdown
When you're running TMFWSI with the `-no-hosts` launch parameter, you will need to remove the aformentioned line(s) from your `hosts` file. If you're not using the launch parameter and TMFWSI simply failed to revert your `hosts` file, a backup named `hosts.tmfwsi_bak` can be found in the same folder as the program. You can open it with a text editor and compare it with the original `hosts` file, replacing it as necessary.

## Workflow
To summarize, TMFWSI locally hosts a middleman SSL server using [httplib](https://github.com/yhirose/cpp-httplib) and [OpenSSL](https://github.com/openssl/openssl), modifying your computer's `hosts` file to point to it, and uses [cURL](https://github.com/curl/curl) (alongside [zlib](https://github.com/madler/zlib)) with the necessary parameters (passing all the HTTP(S) data provided by the web browser or game) to establish a connection to the TMF Web Services while skipping certificate revocation checks - as this is all done locally on your machine, no data gets sent anywhere else other than the TMF Web Services.

## Alternate methods
In case you wish not to use TMFWSI, or you're running into issues while using it, there are two alternative (but fairly technical) approaches:

### Using `inetcpl.cpl`
> [!CAUTION]
> **Not recommended**, as it's more unsafe and tends to not work on modern Windows versions - either use TMFWSI or the cURL method.

1. Open Run (<kbd>Win</kbd> + <kbd>R</kbd>)
2. Type `inetcpl.cpl` and press <kbd>Enter</kbd>
3. Under the **Advanced** tab, scroll all the way down to the **Security** section
4. Untick "Check for server certificate revocation"
5. Restart your computer, if required

There is a similar method using `gpedit.msc` but it's needlessly more complicated and effectively achieves the same effect.

### Using cURL
> [!WARNING]
> It is assumed you have Cheat Engine, as well as a runnable version of cURL installed and added to your `PATH`.

> [!NOTE]
> This method is very similar to how TMFWSI works internally, which does everything for you.
1. Visit the site you wish to access, for example [developers.trackmania.com](http://developers.trackmania.com/), and attempt to log-in
   - For Manialinks, check the following paragraph
2. Copy the resulting `ws.trackmania.com` URL
3. Launch PowerShell and type the following command: `curl.exe -k --ssl-no-revoke --dump-header - "(url)"`, where `(url)` is the URL you copied
   - Alternatively, you can also launch CMD and do the following command: `curl -k --ssl-no-revoke --dump-header - "(url)"`, but it's easier and more convenient with PowerShell
4. Copy the `Location:` URL given to you by cURL - it should point to `https://players.trackmaniaforever.com/...`
5. Enter the URL in your web browser. You might be required to log-in using your game account credentials first, similarly to how you would login to the player page
   - If you get a `Failed to connect to ws.trackmania.com port 443 after 2050 ms: Couldn't connect to server` error from cURL, this likely indicates that `ws.trackmania.com` is still in your `hosts` file - either remove it, or replace `ws.trackmania.com` with its [actual IP address](https://www.nslookup.io/domains/ws.trackmania.com/webservers/)
7. Your browser should take you to a `ws.trackmania.com` URL once again after logging in (or immediately after pasting the URL in your web browser, in case you were already logged in)
8. Copy the resulting `ws.trackmania.com` URL once again, running the exact same cURL command as before
9. Once again, copy the `Location:` URL given to you by cURL - this time, the results should be the website of interest (`developers.trackmania.com` in the above example, `dedicp.maniastudio.com` for `freezone:servers` in the below example)
10. If you're trying to access a web page, enter the URL in your web browser. If you're trying to access a Manialink, enter the URL in your Manialink browser
11. If you're still having issues, repeat this process once again or (in the case of web pages) add the cookie given to you by the last cURL prompt under `Set-Cookie:` to the web page and refresh.

If you wish to visit Manialinks instead, for example `freezone:servers`, you will need to copy the `ws.trackmania.com` URL from in-game by either:
1. Taking a screenshot and typing it out manually,
2. Taking a screenshot and using an OCR to extract text from the image,
3. Using Cheat Engine to search for the `https://ws.trackmania.com/oauth2/authorize` string (UTF-8 or UTF-16, both should work), adding it to the list, and extending the length until the entire URL is revealed, or
4. **The easiest method**: using Cheat Engine with the provided cheat tables for [Nations](https://github.com/brokenphilip/TMFWSI/blob/main/ManialinkNations.CT) or [United](https://github.com/brokenphilip/TMFWSI/blob/main/ManialinkUnited.CT) - these cheat tables use static pointers (globals) and offsets to automatically find the URL in memory, no searching necessary

Using Cheat Engine in this regard is perfectly safe, but make sure not to use it with conflicting software (while the Competition Patch is running, for example). After you've extracted the URL, follow step 3 onwards.
