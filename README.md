# wireshark-tase
Wireshark dissectors for TASE (Tel-Aviv Stock Exchange) protocols

# Usage
To install the scripts, place them in the Wireshark personal or global Lua Plugins directory
(see Help -> About Wireshark -> Folders -> Personal/Global Lua Plugins to find the path on your system).

To manually dissect a packet, right-click on the packet, select 'Decode As...' 
and select the protocol from the drop-down list.

To apply dissect heuristics, i.e. auto-detect packets that use this protocol,
enable the "Heuristic Detection" option in the protocol preferences.

To dissect all packets with a predefined port, set the Ports option in the protocol
preferences. Multiple comma-separated ports can be specified, as well as port ranges.

# License
This project is licensed under the terms of the GPL 3 license.
