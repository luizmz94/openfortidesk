# Third-party notices

The Swift and C sources in this repository were developed for this project;
Git records no imported source files or vendored packages. They use Apple system
SDKs and POSIX APIs. The project's MIT license does not relicense those SDKs.
This is a source/history review, not an independent provenance or security audit.

**openfortivpn** is an external dependency, maintained by its own contributors:
https://github.com/adrienverge/openfortivpn (GPL-3.0 with the upstream OpenSSL
exception; consult upstream LICENSE and source headers for its exact scope). Neither its executable
nor Homebrew libraries are included in release archives. The locally approved
runtime is copied from the user's installation by the privileged helper.

**OpenVPN** is an external dependency, maintained by OpenVPN Inc. and its
contributors: https://github.com/OpenVPN/openvpn (GPL-2.0; its `dns-updown`
script is BSD-2-Clause). It is not included in release archives either; when the
user approves it, the helper copies the local installation, its libraries, its
`dns-updown` script and license files into the protected runtime. OpenVPN is a
registered trademark of OpenVPN Inc.; this project is independent of it.

**Brand assets:** the original V/node symbol and icon were supplied by the project
owner as the VPN GUI brand pack. SVG content credentials identify Claude as a
creating/modifying tool, not an exclusive human author. They are retained as
project assets. The editable OpenFortiDesk wordmark uses generic sans-serif text;
no font files or copied Manrope glyph outlines are included in that wordmark.
The original Manrope wordmark exports have been excluded from the public asset
set; no font license is inferred from the font name alone.

AppKit/SwiftUI use system fonts and SF Symbols through Apple's APIs. No system
font or SF Symbols font file is redistributed. Fortinet and openfortivpn names
belong to their respective owners. This project is independent of both.
