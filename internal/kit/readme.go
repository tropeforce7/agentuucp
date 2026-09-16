package kit

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/tropeforce7/agentuucp/internal/buildinfo"
)

// The README is the kit's own document, and has to be enough on its own for
// someone holding the archive and nothing else: what this is, what host it
// is for, how to unpack it, what the script does on a host with no relay
// and on one that has, what the bundle is and what to delete when the relay
// is up. Its sentences are pinned by tests.

// bundleWarning is the paragraph a kit with a bundle carries, word for word.
const bundleWarning = "relay-bundle.json holds the relay's two signing keys in the clear. install.sh\n" +
	"seals it to this host and deletes it; delete this archive from every machine\n" +
	"it touched once the relay is up.\n"

// systemdRule is the one line on what the script needs.
const systemdRule = "It needs systemd 250 or later running as PID 1: Debian 12 or 13, Ubuntu 24.04\n" +
	"or later, Fedora, or RHEL 9 and its rebuilds. The script refuses anything else\n" +
	"and names the reason.\n"

func readme(s Spec, arch string, port int) []byte {
	var b strings.Builder
	url := publicURL(s.Hosts[0], port)
	fmt.Fprintf(&b, "AgentUUCP relay kit for %s\n", s.Hosts[0])
	fmt.Fprintf(&b, "%s\n\n", strings.Repeat("=", len("AgentUUCP relay kit for ")+len(s.Hosts[0])))
	b.WriteString("This directory installs an AgentUUCP relay on the host named above as a system\n")
	b.WriteString("service: the relay binary, its settings, its administrators, its systemd unit,\n")
	b.WriteString("and a script that puts them where the deployment guide puts them and starts\n")
	fmt.Fprintf(&b, "the relay. It was made by auu-ca kit on %s.\n\n", s.Now.UTC().Format(time.DateOnly))
	fmt.Fprintf(&b, "  host           %s\n", strings.Join(s.Hosts, ", "))
	fmt.Fprintf(&b, "  architecture   linux/%s\n", arch)
	if version := buildinfo.Of(bytes.NewReader(s.RelayBinary)); version != "" {
		fmt.Fprintf(&b, "  relay version  %s\n", version)
	}
	fmt.Fprintf(&b, "  listen         %s\n", s.Listen)
	fmt.Fprintf(&b, "  public_url     %s\n", url)
	fmt.Fprintf(&b, "  registration   %s\n", s.Registration)
	fmt.Fprintf(&b, "  client certs   %s\n", s.ClientCerts)
	fmt.Fprintf(&b, "  administrators %d\n", countAdmins(s.Admins))
	fmt.Fprintf(&b, "  trust anchor   %s\n\n", s.Anchor)

	if s.Bundle != nil {
		b.WriteString(bundleWarning)
	} else {
		b.WriteString("This kit carries no bundle. install.sh installs everything else and stops short\n")
		b.WriteString("of starting the relay, printing the two lines that finish the job once the\n")
		b.WriteString("bundle is on this host, run as root from the directory it landed in:\n\n")
		b.WriteString(withoutBundleLines())
	}
	b.WriteString("\n")
	b.WriteString(systemdRule)
	b.WriteString("\n")
	b.WriteString("Unpacking needs `unzip`, which a minimal install does not have (`apt install\n")
	b.WriteString("unzip`, or `dnf install unzip`): `unzip -o FILE` keeps every file's mode and\n")
	b.WriteString("replaces a kit already unpacked here without asking;\n")
	b.WriteString("`python3 -m zipfile -e FILE .` does not, which is fine, since the script sets the\n")
	b.WriteString("bundle's mode itself before anything reads it. Its first act after that is to\n")
	b.WriteString("check every file here against MANIFEST, and it prints each command before\n")
	b.WriteString("running it.\n\n")
	b.WriteString("On a host with no relay:\n\n")
	b.WriteString("  sudo sh auu-relay-kit/install.sh\n\n")
	b.WriteString("On a host that has one, to bring it to what this kit holds, or to repair one\n")
	b.WriteString("whose unit or binary has gone:\n\n")
	b.WriteString("  sudo sh auu-relay-kit/install.sh update\n\n")
	b.WriteString("update stops the relay and copies its database, binary, unit, settings,\n")
	b.WriteString("administrators and credential into /var/lib/auu/backups/<time>/, with a RESTORE\n")
	b.WriteString("file there that says how to put them back; it never puts them back itself. It\n")
	b.WriteString("replaces the binary and the unit, seals the bundle here over the old credential\n")
	b.WriteString("when the kit has one, and replaces the settings and the administrators only if\n")
	b.WriteString("they have not been edited since the last kit: an edited file is kept, the kit's\n")
	b.WriteString("copy is written beside it as /etc/auu/relay.json.kit or /etc/auu/admins.kit,\n")
	b.WriteString("and the script says so. A kit whose bundle has already been sealed can be run\n")
	b.WriteString("again; the credential on the host is kept.\n\n")
	b.WriteString("When the relay is up, delete this directory and the archive it came from, here\n")
	b.WriteString("and on the machine that made it: they hold nothing the relay needs now. Then,\n")
	b.WriteString("from anywhere:\n\n")
	fmt.Fprintf(&b, "  curl %s/v1/health\n\n", url)
	b.WriteString("and from an administrator's own machine, pointing it at the relay with the trust\n")
	b.WriteString("anchor above, then the check:\n\n")
	fmt.Fprintf(&b, "  auu relay add %s --name NAME --anchor %s\n", url, s.Anchor)
	b.WriteString("  auu-admin status\n")
	return []byte(b.String())
}

// withoutBundleLines are the two commands that finish a kit made without
// its bundle, once the bundle file is on the host beside the credential's
// place.
func withoutBundleLines() string {
	return "  systemd-creds encrypt --name=relay-bundle relay-bundle.json /etc/auu/relay-bundle.cred\n" +
		"  systemctl enable --now auu-relay\n"
}

// countAdmins is how many of the lines are keys rather than blank or
// comments; the lines were parsed before this is called.
func countAdmins(lines []string) int {
	n := 0
	for _, l := range lines {
		t := strings.TrimSpace(l)
		if t != "" && !strings.HasPrefix(t, "#") {
			n++
		}
	}
	return n
}
