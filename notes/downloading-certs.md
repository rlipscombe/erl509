# Downloading certificates

You might want to grab the certificate chain from a website, for comparing with erl509-generated certificates.

```sh
openssl s_client -connect serverfault.com:443 -showcerts </dev/null 2>/dev/null | gawk '/BEGIN/ {} /BEGIN/, /END/ { print }' | gawk 'BEGIN {n=1} x == 1 {n++; x=0} /END CERTIFICATE/ {x=1} {print > "cert" n ".pem"}'
```

It doesn't show the root certificate, because that's not in the chain -- you should have a copy in your local trust
store.

If you want the complete chain, in Firefox:

1. Navigate to the site.
2. Click the padlock icon in the address bar.
3. Click the "Connection secure" entry.
4. Click "More information".
5. On the "Page Info" dialog box, click the "View Certificate" button.
6. On the "Certificate" page that appears, click the "Download - PEM (chain)" link.

A .PEM file containing the entire certificate chain, including the root, will be put in your "Downloads" folder.

To split it into separate PEM files, use the following, for example:

```sh
cat ~/Downloads/serverfault-com-chain.pem | gawk 'BEGIN {n=1} x == 1 {n++; x=0} /END CERTIFICATE/ {x=1} {print > "serverfault-com-cert-" n ".pem"}'
```
