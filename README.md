# Simple GIP Dissector for Wireshark

This is a simple GIP dissector for Wireshark. It currently only auto-detects
USB packets of the Xbox controller series and does only minimal decoding.


## Usage

To use it, check if one of the following directories exists:

* `~/.wireshark`
* `~/.config/wireshark`

Create a `plugins` directory inside, then symlink `src/gip-dissector.lua`
to it. If you start Wireshark now and load an Xbox controller packet dump,
it should decode many parts of the protocol.

Feel free to send improvements via a Github PR.
