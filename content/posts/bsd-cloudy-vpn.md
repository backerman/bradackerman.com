+++
title = "A partly-cloudy IPsec VPN"
author = "Brad Ackerman"
lastmod = 2018-12-04T19:31:00-05:00
tags = ["VPN", "IPsec", "OpenBSD", "FreeBSD", "Cloud"]
draft = false
+++

## Overview {#overview}

I'm redoing my [DigitalOcean](https://www.digitalocean.com/) virtual
machines (which they call droplets). My requirements are:

-   VPN
    -   Road-warrior access, so I can use private network resources from
        anywhere.
    -   A site-to-site VPN, extending my home network to my VPSes.
-   Hosting for public and private network services.
-   A proxy service to provide a public IP address to services hosted at
    home.

The last item is on the list because I don't actually have a public IP
address at home; my firewall's external address is in the [RFC
1918](https://www.rfc-editor.org/info/rfc1918) space, and the entire
apartment building shares a single public IPv4 address.[^1] \(IPv6?
Don't I wish.) The end-state network will include one
[OpenBSD](https://www.openbsd.org/) droplet providing firewall,
router, and VPN services; and one [FreeBSD](https://www.freebsd.org/)
droplet hosting multiple jailed services.

[^1]: Rekhter, Moskowitz, Karrenberg, de Groot & Lear, "Address
    Allocation for Private Internets" (1996).

I'll be providing access via these droplets to a
[NextCloud](https://nextcloud.com/) instance at home. A simple NAT on
the DO router droplet isn't going to work, because packets going from
home to the internet would exit through the apartment building's
connection and not through the VPN.  It's possible that I could do
work around this issue with `pf` packet tagging, but
[HAProxy](https://www.haproxy.org/) is simple to configure and
unlikely to result in hard-to-debug problems. `relayd` is also an
option, but doesn't have the TLS parsing abilities of HAProxy, which
I'll be using later on.

Of course, since this system includes jails running on a VPS, and
they've got RFC 1918 addresses, I want them reachable from my home
network. Once that's done, I can access the private address space from
anywhere through a VPN connection to the cloudy router.

The VPN itself will be of the IPsec variety. IPsec has a
(somewhat-deserved) reputation for complexity, but recent versions of
OpenBSD turn down the difficulty by quite a bit.

The end-state network should look like:

{{< figure caption="End-state configuration of the network."
src="/201812-cloudy/endstate.svg" >}}

This VPN both separates internal network traffic from public traffic
and uses encryption to prevent interception or tampering.

Once traffic has been encrypted, decrypting it without the key would,
as Bruce Schneier once put it, require a computer built from something
other than matter that occupies something other than space. Dyson
spheres and a frakton of causality violation would possibly work, as
would mathemagical technology that alters the local calendar such that
P=NP.[^3] Black-bag jobs and/or [suborning cloud provider
employees](https://xkcd.com/538/) doesn't quite have that guarantee of
impossibility, however. If you have serious security requirements,
you'll need to do better than a random blog entry.

[^3]: Lee, _Ninefox Gambit_, Solaris (2016).

## Install OpenBSD

DigitalOcean still doesn't officially support OpenBSD, so we'll create
a FreeBSD ufs droplet and fix it in post. [These
instructions](https://www.tubsta.com/2015/04/openbsd-on-digital-ocean/)
will work. Some useful notes:

1. The current OpenBSD version is, as of this writing, 6.4. The below procedure
both downloads the miniroot and verifies it against the provided checksum.

    ```plain
    $ sudo su -
    # fetch https://cdn.openbsd.org/pub/OpenBSD/6.4/amd64/{miniroot64.fs,SHA256}
    # sha256 -c `grep miniroot SHA256 | cut -d= -f2` miniroot64.fs
    SHA256 (miniroot64.fs) = 649b2f412750dee2ef6f42bdd66fb5f015d095b4225fb775a4267aa01e3f80dd
    ```

2. The DigitalOcean console is a bit wonky in OpenBSD for some
reason; it will frequently interpret the return key as two newlines.
<kbd><kbd>Ctrl</kbd>-<kbd>J</kbd></kbd> seems to work better for some reason.

3. The partitioning in the linked instructions works fine, but I prefer to
have separate log partitions at a minimum, e.g.:

```plain
#                size           offset  fstype [fsize bsize   cpg]
  a:          8197.2M          2104544  4.2BSD   2048 16384 12958 # /
  b:          1027.6M               64    swap                    # none
  c:         25600.0M                0  unused
  d:          1529.6M         18892416  4.2BSD   2048 16384 12958 # /tmp
  e:          2047.4M         22025088  4.2BSD   2048 16384 12958 # /var
  f:          2055.2M         26218080  4.2BSD   2048 16384 12958 # /var/log
  g:         10738.8M         30427104  4.2BSD   2048 16384 12958 # /home
```

## Configure OpenBSD

After rebooting into the newly-installed system, `sshd` is enabled but
the root user can't log in. If you didn't create another user yet and
add them to `wheel`, log in on the console and temporarily change
`PermitRootLogin` to `yes` in `/etc/ssh/sshd_config`, then `rcctl
reload sshd`. `ssh` in, add your public key to
`/root/.ssh/authorized_keys`, and change `PermitRootLogin` to
`without-password`; or change it back to `no` after adding the
non-root (but en-`wheel`ed) user.  There will almost certainly be
security patches to install; run `syspatch` and reboot.

Unlike other operating systems, the necessary IPsec functionality is
part of OpenBSD's base system; we'll install HAProxy for later,
though.  (And also vim, but that's optional.) We'll also set up `doas`
with a configuration equivalent to DigitalOcean's default
`sudo`---permit users in `wheel` to run commands as root without a
password, because user accounts don't need them (and disabling `ssh`
password-based login completely negates the Rumpelstiltskin
attack[^1a]).

[^1a]: That being the one where bots try default passwords, and
    failing that attempt to exhaust the password space. While the bots
    won't be able to successfully guess a password when passwords
    aren't accepted, they'll still clutter the logs; so a blacklisting
    system such as [`sshguard`](https://www.sshguard.net/) is still
    useful.

``` shell
pkg_add haproxy vim--no_x11
echo "permit nopass :wheel" > /etc/doas.conf
```

### Keymat generation

(N.B.: The terminology used in this blog is from [Committee on
National Security Systems](https://www.cnss.gov/cnss/) Instruction
(CNSSI) No. 4009.[^2])

[^2]: Committee on National Security Systems, "Committee on National
    Security Systems (CNSS) Glossary" (2005).

OpenBSD's `ikectl` command includes basic X.509 certificate authority
(CA) functionality. For this article, we'll use it to create a CA that
directly signs keys. In a production system, please do not use an
online root CA to sign everything. Faraday cages, hardware security
modules, two-person integrity, and/or a Marine with an M4 are, as
always, optional.

The defaults are read from `/etc/ssl/ikeca.cnf`. You'll want to change
the top section (`CERT_*`) to avoid repeatedly typing in the values
you actually want for country/city/etc. (They don't actually matter,
but see [Maxim #37](https://www.schlockmercenary.com/2004-02-23):
There is no overkill; there is only only "open fire" and "I need to
reload".) You may also wish to extend the certificate validity time
and change the message digest to sha512 (which is faster than sha256
on modern computers) by editing the `CA_default` section at the
bottom.

We then create our CA. Its name is arbitrary; here I'll just use
`ipsec`.

```plain
# ikectl ca ipsec create
CA passphrase:
Retype CA passphrase:
Generating RSA private key, 2048 bit long modulus
...............................+++
................................................................................
................................................................................
......+++
e is 65537 (0x10001)
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [US]:
State or Province Name (full name) [Zendia]:
Locality Name (eg, city) [Arkham]:
Organization Name (eg, company) [Miskatonic University]:
Organizational Unit Name (eg, section) [iked]:
Common Name (eg, fully qualified host name) [VPN CA]:
Email Address [certs@example.com]:
Signature ok
subject=/C=US/ST=Zendia/L=Arkham/O=Miskatonic University/OU=iked/CN=VPN CA/emailAddress=certs@example.com
Getting Private key
Using configuration from /etc/ssl/ipsec/ca-revoke-ssl.cnf
# ikectl ca ipsec install
```

Supplying a password is mandatory; creation will fail if you try to
just press enter. The password is saved in the CA directory
(`/etc/ssl/name`), so this would be a less-than-ideal place for
reuse.

Next, create the keymat itself. `ikectl` is sufficiently intelligent
to figure out that an FQDN needs to go in the Subject Alternative Name
field.

```plain
# ikectl ca ipsec install
certificate for CA 'ipsec' installed into /etc/iked/ca/ca.crt
CRL for CA 'ipsec' installed to /etc/iked/crls/ca.crl
# ikectl ca ipsec certificate my.cloudy.host.fqdn create
[ ... just hit enter at the prompts ... ]
# ikectl ca ipsec certificate my.cloudy.host.fqdn install
writing RSA key
# ikectl ca ipsec certificate my.home.router.fqdn create
[ ... same thing ... ]
# ikectl ca ipsec certificate my.home.router.fqdn export
Export passphrase:
Retype export passphrase:
writing RSA key
exported files in /root/my.home.router.fqdn.tgz
```

If you'd like to verify that the certificates have been generated
correctly (never a bad idea), check the output of:

``` shell
openssl x509 -in /etc/ssl/ipsec/"hostname goes here".crt -noout -text
```

The `ikectl ca` command generates the public certificate and private
key; the `export` subcommand creates a tarball in your current
directory, to be copied to the client, containing:

| Filename                          | Description                                                  |
|-----------------------------------|--------------------------------------------------------------|
| `ca/ca.crt`                       | The CA's certificate                                         |
| `certs/my.home.router.fqdn.crt`   | The client's certificate                                     |
| `crls/ca.crl`                     | The CA's current certificate revocation list                 |
| `export/ca.pfx`                   | The CA's certificate in PKCS #12 format                      |
| `export/my.home.router.fqdn.pfx`  | The CA's certificate and client's keypair in PKCS #12 format |
| `private/my.home.router.fqdn.key` | The client's RSA private key                                 |
| `private/local.key`               | The client's RSA private key (same as above)                 |
| `local.pub`                       | The client's RSA public key                                  |
|                                   |                                                              |

The PKCS #12 files (whether or not they contain private keys) are
encrypted using the passphrase provided during export; all other files
are unencrypted.

The `install` subcommand copies the selected certificate to
`/etc/iked/certs/my.cloudy.host.fqdn.crt` (public) and
`/etc/iked/private/local.key` (private).

Finally, the `ikectl ca` command does not place the keymat where
`iked` will look for it, so copy it to the right place in the right
format.

```shell
openssl rsa -in /etc/iked/private/local.key -pubout > \
  /etc/iked/pubkeys/fqdn/my.cloudy.host.fqdn
openssl x509 -pubkey  -in /etc/ssl/ipsec/my.home.router.fqdn.crt \
  -noout > /etc/iked/pubkeys/fqdn/my.home.router.fqdn
```

### Network interfaces

We'll configure multiple interfaces for the VPN; `enc0` defines the
endpoint address of the VPN itself, and `gre0` defines the tunnel
we'll run over it. (GRE is required because we can't run OSPF directly
over the IPsec tunnel.)

Create `/etc/hostname.enc0` and `/etc/hostname.gre0`:

| Interface | Contents of `/etc/hostname.if`                                                       |
|-----------|--------------------------------------------------------------------------------------|
| `enc0`    | `inet 172.16.128.1/32`                                                               |
| `gre0`    | `inet 172.16.129.1/32`<br />`dest 172.16.129.2`<br />`tunnel 172.16.128.1 172.16.128.2` |
|           |                                                                                      |

Then bring them up. You'll probably see an error message about the
`hostname.if` files being insecure; they were world-readable, which
the `netstart` script corrects.

``` shell
sh /etc/netstart enc0 gre0
```

### sysctls

Create `/etc/sysctl.conf`:

``` plain
net.inet.ip.forwarding=1
net.inet6.ip6.forwarding=1
net.inet.gre.allow=1
```

### VPN and routing configuration

The VPN will initially encrypt and route traffic within our private
address space; we'll add other services later. To make this work,
we'll need to configure and enable:

-   ospfd
-   iked
-   pf
-   HAProxy

`iked` handles keying for the VPN endpoints. The daemon configuration
(in `/etc/iked.conf`) will look something like this:

```plain
myfqdn = "my.cloudy.router.fqdn"
mypublic = "192.0.2.3"

homefqdn = "my.home.router.fqdn"

ikev2 "cloudy" default ipcomp esp \
        from 172.16.128.1/32 to 172.16.128.2/32 \
        local $mypublic  \
        ikesa enc aes-256 prf hmac-sha2-512 auth hmac-sha2-512 group ecp384 \
        childsa enc aes-256-gcm prf hmac-sha2-512 group ecp384 \
        srcid $myfqdn dstid $homefqdn
```

The above configuration creates a policy allowing traffic between
172.16.128.1 (`enc0` on the server) and 172.16.128.2 (`lo1` on the
client). The `srcid` and `dstid` parameters specify which of the
`from` and `to` address blocks is local and which remote.

We use authenticated encryption with associated data (AEAD) for the
child (ESP) SA, but that's not an option for the parent (IKE)
SA. `iked`'s configuration doesn't specify the Integrity Check Value
(ICV) length that would follow `aes-256-gcm` in other implementations
(e.g. `aes-256-gcm16`); this is because you should only use a 16-octet
ICV.

At this point, you can fix the configuration file's permissions and
turn on the VPN (temporarily)

``` shell
chmod 640 /etc/iked.conf
iked -vvd
```

`iked` will display some debug messages to the terminal, but there shouldn't
be any errors. Press <kbd><kbd>Ctrl</kbd>-<kbd>C</kbd></kbd> to exit.

`ospfd` propagates routing information between the two sites, and is
configured with `/etc/ospfd.conf`:

```plain
router-id 172.16.128.1

area 0.0.0.0 {
        interface gre0
}
```

And yes, that's going to need to have the proper permissions.

``` shell
chmod 640 /etc/ospfd.conf
```

We'll configure OpenBSD's firewall to allow remote dial-in and ensure
that unencrypted traffic is not permitted to traverse the private
network. A basic PF configuration (`/etc/pf.conf`):

```shell
ext_if="vio0"
int_if="vio1"

rtr_svc_tcp="{ssh}"

match in all scrub (no-df max-mss 1440)
match out on $ext_if inet from ! ($ext_if) nat-to ($ext_if)
antispoof for $ext_if

set skip on {lo, enc, gre}

block drop in on $ext_if
pass out on $ext_if
pass out on $int_if

pass in on $ext_if inet6 proto icmp6

# Port build user does not need network
block return out log proto {tcp udp} user _pbuild

# Router services
pass in on $ext_if proto tcp from any to ($ext_if) port $rtr_svc_tcp keep state
pass in on $ext_if inet proto icmp from any to ($ext_if)

# Proxied services
# pass in on $ext_if proto tcp from any to ($ext_if) port {http, https} keep state

# IPsec
pass in on $ext_if proto {ah, esp} to ($ext_if)
pass in on $ext_if proto udp to ($ext_if) port { isakmp, ipsec-nat-t }
```

This can be enhanced to add filtering on the IPsec tunnel; that will
be left as an exercise to the reader. Finally, load the firewall
configuration, enable the services and restart to make sure
everything's good.

```shell
pfctl -f /etc/pf.conf
rcctl enable iked
rcctl enable ospfd
rcctl enable pf
shutdown -r now
```

We'll configure HAProxy after setting up routing on the local end.

## Configure the home network (FreeBSD)

### Pre-setup

At the time of writing, the current FRRouting version isn't in the
default (quarterly) package repository; so we'll need to switch this
machine to latest by `s/quarterly/latest` in the repository URL, which
is configured in `/etc/pkg/FreeBSD.conf`. Once that's been done,
install the packages we'll need.

```shell
pkg update
pkg upgrade
pkg install frr6 strongswan
```

The `enc` interface driver in FreeBSD is a module by default, and
isn't automatically loaded. So we'll need to load it now, and set it
to load on boot.

```shell
echo 'if_enc_load="YES"' >> /boot/loader.conf
kldload if_enc
```

### Firewall

At a minimum, we want to `set skip on enc` (or set up actual rules)
and prevent internal traffic from leaking out unencrypted. For a
proper value of paranoia, set up useful rules for the VPN instead of
skipping those interfaces, and use an updown script to remove the
tunnel configuration from `gre0` when no IPsec connection is present.

`/etc/pf.conf` will look something like:

```shell
# The network card names for the internal and external interfaces go here.
int_if="xl0"
ext_if="cm0"
private_space="172.16.0.0/16"
set limit { states 40000, frags 20000, src-nodes 20000 }

scrub on $int_if all fragment reassemble
scrub on $ext_if all fragment reassemble

nat on $ext_if inet from ! ($ext_if) to any -> ($ext_if)

antispoof for $int_if

block drop in
# Don't filter loopback or the VPN.
set skip on {lo, enc, gre}

pass out flags S/SA keep state allow-opts
pass in on $int_if from ($int_if:network) to any

# Ensure that our VPN traffic won't try to escape.
block out on $ext_if proto gre
block out on $ext_if from $private_space to $private_space
```

Enabling the firewall is different from OpenBSD, but when you want to
change the configuration it's the same `pfctl -f /etc/pf.conf` as
root.

``` shell
sysrc pf_enable=YES
service pf start
```

### IPsec

OpenBSD's `iked` isn't supported on other OSes, so we'll use
strongSwan instead.

We write a configuration to
`/usr/local/etc/swanctl/conf.d/cloudy.conf` using values derived from
[Algo](https://github.com/trailofbits/algo). One important note: every
component of a proposal should be specified, or strongSwan will pick
something stupid and the rekey negotiation will fail even though the
initial keying went just fine.  So for AEAD you'll need to specify the
encryption, pseudorandom function (hash), and Diffie-Hellman or
elliptic curve group, for a total of three components; non-AEAD
proposals will separate the authentication and encryption algorithms
for a total of four components.

```plain
connections {

   cloud {
      local_addrs  = %any
      remote_addrs = my.cloudy.host.fqdn

      local {
         auth = pubkey
         certs = my.home.router.fqdn.crt
         id = my.home.router.fqdn.org
      }
      remote {
         auth = pubkey
         id = my.cloudy.host.fqdn
         cacerts = ca.crt
      }
      children {
         net-net {
            local_ts = 172.16.128.2/32
            remote_ts = 172.16.128.1/32
            esp_proposals = aes256gcm16-prfsha512-ecp384
            dpd_action = restart
            ipcomp = yes
            hw_offload = auto
            # When the connection is loaded, or when it is closed, a trap
            # will be installed to reconnect when there's traffic. The
            # OSPF announcements will ensure that the link stays up at
            # all times.
            start_action = trap
            close_action = trap
         }
      }
      version = 2
      fragmentation = yes
      dpd_delay = 30s
      proposals = aes256-sha2_512-prfsha512-ecp384
   }
}
```

Put the keymat from the export tarball into `/usr/local/etc/swanctl`
as follows:

| Copy this file                    | to this subdirectory |
|-----------------------------------|----------------------|
| `ca/ca.crt`                       | `x509ca`             |
| `certs/my.home.router.fqdn.crt`   | `x509`               |
| `private/my.home.router.fqdn.key` | `private`            |

Verify that the configuration has been correctly input by loading it.

```plain
# service strongswan onestart
Starting strongSwan 5.7.1 IPsec [starter]...
no netkey IPsec stack detected
no KLIPS IPsec stack detected
no known IPsec stack detected, ignoring!

# swanctl --load-all
loaded certificate from '/usr/local/etc/swanctl/x509/my.home.router.fqdn.crt'
loaded certificate from '/usr/local/etc/swanctl/x509ca/ca.crt'
loaded rsa key from '/usr/local/etc/swanctl/private/my.home.router.fqdn.key'
no authorities found, 0 unloaded
no pools found, 0 unloaded
loaded connection 'cloudy'
successfully loaded 1 connections, 0 unloaded
# swanctl --list-certs

List of X.509 End Entity Certificates

  subject:  "C=US, ST=Massachusetts, L=Innsmouth, O=Miskatonic University, OU=iked, CN=my.home.router.fqdn, E=certs@example.com"
  issuer:   "C=US, ST=Zendia, L=Arkham, O=Miskatonic University, OU=iked, CN=VPN CA, E=certs@example.com"
  validity:  not before Sep 30 21:15:13 2018, ok
             not after  Jun 26 21:15:13 2021, ok (expires in 950 days)
  serial:    02
  altNames:  my.home.router.fqdn
  flags:     clientAuth
  subjkeyId: xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx
  pubkey:    RSA 2048 bits, has private key
  keyid:     xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx
  subjkey:   xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx

List of X.509 CA Certificates

  subject:  "C=US, ST=Zendia, L=Arkham, O=Miskatonic University, OU=iked, CN=VPN CA, E=certs@example.com"
  issuer:   "C=US, ST=Zendia, L=Arkham, O=Miskatonic University, OU=iked, CN=VPN CA, E=certs@example.com"
  validity:  not before Sep 30 21:13:24 2018, ok
             not after  Sep 30 21:13:24 2019, ok (expires in 315 days)
  serial:    xx:xx:xx:xx:xx:xx:xx:xx
  flags:     CA CRLSign self-signed
  pathlen:   1
  subjkeyId: xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx
  pubkey:    RSA 2048 bits
  keyid:     xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx
  subjkey:   xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx:xx
# swanctl --list-conns
cloud: IKEv2, no reauthentication, rekeying every 14400s, dpd delay 30s
  local:  %any
  remote: my.cloudy.host.fqdn
  local public key authentication:
    id: my.home.router.fqdn
    certs: C=US, ST=Zendia, L=Arkham, O=Miskatonic University, OU=iked, CN=my.home.router.fqdn, E=certs@example.com
  remote public key authentication:
    id: my.cloudy.host.fqdn
    cacerts: C=US, ST=Zendia, L=Arkham, O=Miskatonic University, OU=iked, CN=VPN CA, E=certs@exaple.com
  net-net: TUNNEL, rekeying every 3600s, dpd action is restart
    local:  172.16.128.2/32
    remote: 172.16.128.1/32
```

Now you can enable strongSwan in `/etc/rc.conf`.

```shell
sysrc strongswan_enable=YES
```

The provided `rc.d` script doesn't load swanctl on startup, so we'll need
to include our own as `/usr/local/etc/rc.d/strongswan_swanctl`:

```shell
#!/bin/sh
# Load or unload swanctl configuration.

# PROVIDE: strongswan_swanctl
# REQUIRE: strongswan
# BEFORE: LOGIN

command="/usr/local/sbin/swanctl"
. /etc/rc.subr

name="strongswan_swanctl"
rcvar=${name}_enable
extra_commands="reload"

load_rc_config $name

start_cmd="swanctl_start"
stop_cmd=":"
reload_cmd="swanctl_start"
restart_cmd="swanctl_start"
status_cmd="swanctl_status"

swanctl_start() {
  # strongswan's rc.d script exits before it's actually started.
  [ -e /var/run/charon.vici ] || sleep 1
  ${command} --load-all
}

swanctl_status() {
  ${command} --list-conns
  ${command} --list-certs
}

run_rc_command "$1"
```

Enable it as per usual, and create the `gre0` interface corresponding
to the one we created on the other side.

```shell
sysrc cloned_interfaces+="gre0"
sysrc ifconfig_gre0="inet 172.16.129.2/24 172.16.129.1"
sysrc ifconfig_gre0+="tunnel 172.16.128.2 172.16.128.1"
service netif start gif0
chmod +x /usr/local/etc/rc.d/strongswan_swanctl
sysrc strongswan_swanctl_enable=YES
service strongswan_swanctl start
```

### OSPF

We'll use [FRRouting](https://frrouting.org/) to implement OSPF on the
FreeBSD side. First, enable it:

```shell
sysrc frr_enable="YES"
sysrc frr_daemons="zebra ospfd"
sysrc frr_wait_for="default"
# As suggested by the FRRouting package
echo "kern.ipc.maxsockbuf=16777216" >> /etc/sysctl.conf
touch /usr/local/etc/frr/{zebra,ospfd}.conf
chown -R frr:frr /usr/local/etc/frr
service frr start
```

Executing `vtysh` will open a Cisco-like shell in enable
(administrator) mode. Enter configuration mode with `config t`, then
configure OSPF:

```plain
router ospf
 passive-interface xl0
 network 172.16.1.0/24 area 0.0.0.0
 network 172.16.129.0/30 area 0.0.0.0
```

Interfaces on networks that you'll be distributing routes for, and
don't themselves have an OSPF router on the other end, should be
declared with `passive-interface`. Save with a control-Z, then `wr
mem`. After a few seconds, `show ip ospf neighbor` should show the
remote droplet.

### Proxy configuration

As a reminder from part 1, we're going to use HAProxy to allow
services on the Internet to access a NextCloud instance at home.
The proxy should support both TLS on port 443 (normal traffic) and
cleartext on port 80 (Let's Encrypt certificate renewal).

There are two possible ways to do this:

-   Terminate the TLS session in the cloud. Slightly riskier in that the
    cloud servers have access to the cleartext, but I'm probably being
    paranoid. Consolidated logging on one server.
-   Terminate the TLS session on the NextCloud server. Keeps exposure
    of the cleartext as low as possible, but need to correlate logs
    of two systems.

We'll use the first of these options. The HAProxy configuration below
exhibits several useful features:

-   Insecure TLS versions are dropped.
-   Connections are only passed through to the server if the client
    provides the correct hostname.

Put it in `/etc/haproxy/haproxy.cfg` and modify as necessary.

```plain
global
        log 127.0.0.1   local0 debug
        maxconn 1024
        chroot /var/haproxy
        uid 604
        gid 604
        daemon
        pidfile /var/run/haproxy.pid

defaults
        log     global
        mode    http
        option  httplog
        option  redispatch
        retries 3
        maxconn 2000
        timeout connect 5000ms
        timeout client 50000ms
        timeout server 50000ms

listen http-in
      mode http
      log global
      option httplog
      bind *:80
      http-request deny unless { hdr(Host) -m str nextcloud.fqdn.goes.here }
      use_backend http-ok

listen https-in
        mode tcp
        log global
        option tcplog
        bind *:443
        tcp-request inspect-delay 5s
        tcp-request content reject unless { req.ssl_hello_type 1 } { req.ssl_ver 3.2: }
        use_backend https-ok if { req_ssl_sni -m str nextcloud.fqdn.goes.here }

backend http-ok
        # and this IP address is where connections are proxied to
        server nextcloud 172.16.10.1:80 maxconn 32

backend https-ok
        mode tcp
        server nextcloud-s 172.16.10.1:443 maxconn 32
```

Uncomment the pass rule for this traffic in pf.conf, then reload the
rules and start HAProxy.

``` shell
pfctl -f /etc/pf.conf
rcctl enable haproxy
rcctl start haproxy
```

## Conclusion

800ish lines of blog later, we have a working IPsec tunnel and OSPF
daemons on either side passing routes around. We also have a proxy
forwarding HTTP(S) connections to an internal host, and the
configuration can easily be expanded to accommodate more.

Part 2 of this series will feature extending the VPN to an additional
droplet, which will host some jails on FreeBSD.
