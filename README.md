# TrackMania Forever Web Server Interceptor
> [!NOTE]
> This repository is currently an **early work-in-progress**, any and all information is subject to change without notice and may be missing or incorrect.

TMFWSI intercepts traffic to TrackMania Forever Web Services (`ws.trackmania.com`) on your local machine, "fixing" bugs such as:
- "`http error 12170`", from the in-game Manialink browser
- "`ERR_SSL_VERSION_OR_CIPHER_MISMATCH`", from a Chromium browser
- "`ERROR_INTERNET_SEC_CERT_REVOKED` or `CRYPT_E_REVOKED` - The SSL certificate was revoked"

By doing so, this allows you to log-in to the following services:
- [home.trackmania.com](http://home.trackmania.com/) web page, to check your linked forums & authorized applications (and a lottery which may or may not work, lol)
- [developers.trackmania.com](http://developers.trackmania.com/) web page, to access the Web Services API
- [maniapub](http://maniapub.trackmania.com/) Manialink, to manage your in-game advertisements
- [freezone:servers](http://dedicp.maniastudio.com/) Manialink, to manage your FreeZone servers
- any other website or Manialink not listed here that uses `ws.trackmania.com` for authentication

Technically speaking, this is accomplished by locally hosting a middleman SSL server using [httplib](https://github.com/yhirose/cpp-httplib) and [OpenSSL](https://github.com/openssl/openssl), modifying your computer's `hosts` file to point to it, and using [cURL](https://github.com/curl/curl) (alongside [zlib](https://github.com/madler/zlib)) with the necessary parameters to establish a connection to the TMF Web Services by skipping certificate revocation checks - as this is all done locally on your machine, no data gets sent anywhere else.

> [!WARNING]
> It is possible to repurpose this project to host a public server rather than a local one, but hosting and **especially** connecting to one is ill-advised because the host can easily read the communicated data, which is an obvious security hazard - you should only self-host TMFWSI, and the project is designed in such a way to make this process as easy as possible.

> [!CAUTION]
> While this program is safer than the popular `inetcpl.cpl` alternate method (explained below), it is important to note that this is still a **very unsafe** way of communicating sensitive (login) data to a server and should merely be used as a temporary workaround for those that desperately require the above listed services, hence why the word "fixing" was put in quotes in the first paragraph - a proper fix would be for the maintainers of the TMF Web Services to renew its certificates and employ better security practices overall.

## Usage
1. Head over to [Releases](https://github.com/brokenphilip/TMFWSI/releases) and download the latest `TMFWSI.zip`
2. Extract the the contents of the zip archive wherever you'd like
3. When you need to access `ws.trackmania.com`, simply run the program
   - TrackMania Nations/United Forever, as well as some web browsers, will need to be restarted first
4. Whenever you're done, simply close the program

## Troubleshooting
If you encounter any issues during installation or usage, please refer to the [issue tracker](https://github.com/brokenphilip/TMFWSI/issues?q=). If you haven't found your issue, feel free to create a new one. If you have any further questions about the project, or if (understandably) using the issue tracker is too confusing, feel free to add me on Discord (`brokenphilip`) and I will try to get back to you as soon as possible. :)

## Alternate method using `inetcpl.cpl`
> [!CAUTION]
> More unsafe and not recommended - either use TMFWSI or the cURL method, which are slightly-less-but-still unsafe.

1. Open Run (<kbd>Win</kbd> + <kbd>R</kbd>)
2. Type `inetcpl.cpl` and press <kbd>Enter</kbd>
3. Under the **Advanced** tab, scroll all the way down to the **Security** section
4. Untick "Check for server certificate revocation"
5. Restart your computer, if required

There is a similar method using `gpedit.msc` but it's needlessly more complicated and effectively achieves the same effect, but worse.

## Alternate method using cURL
> [!WARNING]
> As this method is of technical nature, it is assumed you have Cheat Engine, as well as a runnable version of cURL installed and added to your `PATH`. This method is very similar to how TMFWSI works internally, which does everything for you.
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
4. **The easiest method**: using Cheat Engine with the provided cheat tables for [Nations](https://github.com/brokenphilip/TMFWSI/blob/main/ManialinkNations.CT) or [United](https://github.com/brokenphilip/TMFWSI/blob/main/ManialinkUnited.CT).

Using Cheat Engine in this regard is perfectly safe, but make sure not to use it with conflicting software (while the Competition Patch is running, for example). After you've extracted the URL, follow step 3 onwards.