# acme-client
An RFC-compliant implementation of an ACME client (see [RFC8555](https://datatracker.ietf.org/doc/html/rfc8555))

Implemented with Python3.

The software not only runs the ACME client, but also sets up a DNS server and a HTTP server to serve ACME challenges and a HTTPS server with the obtained certificate,
for demonstration purposes.

## Download and install the software
All you need to do is:
- Clone this repository
- Run the `compile` script, in order to install required Python dependencies

## Run the software
Execute the `run` script with the arguments described below.

**Positional arguments**
- `Challenge type`
_(required, `{dns01 | http01}`)_ indicates which ACME challenge type the client should perform. Valid options are `dns01` and `http01` for the `dns-01` and `http-01` challenges, respectively.

**Keyword arguments:**
- `--dir DIR_URL`
_(required)_ `DIR_URL` is the directory URL of the ACME server.
- `--record IPv4_ADDRESS` 
_(required)_ `IPv4_ADDRESS` is the IPv4 address which is returned by the DNS server for all A-record queries. 
- `--domain DOMAIN`
_(required, multiple)_ `DOMAIN`  is the domain for  which to request the certificate.
If multiple `--domain` flags are present, a single certificate for multiple domains is requested.
Wildcard domains have no special flag and are simply denoted by, e.g., `*.example.net`.
- `--revoke`
_(optional)_ If present, the application immediately revokes the certificate after obtaining it.
In both cases, your application starts its HTTPS server and set it up to use the newly obtained certificate.

**Example:**

Consider the following invocation of `run`:
```
run dns01 --dir https://example.com/dir --record 1.2.3.4 --domain one.website.org --domain two.website.org
```
When invoked like this, the application obtains a single certificate valid for both `one.website.org` and `two.website.org`.
It uses the ACME server at the URL `https://example.com/dir` and performs the `dns-01` challenge.
The DNS server of the application responds with `1.2.3.4` to all requests for `A` records.
Once the certificate has been obtained, the application starts its HTTPS server and install the obtained certificate in this server.


