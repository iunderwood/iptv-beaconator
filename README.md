# iptv-beaconator
A python script which generates multicast beacons to announce programs in an IPTV environment

## The Story

This script first found its way to life at the start of 2021 when my employer acquired a new program encoder for its IPTV network.  The new encoder was destined to be a VOD player, enabling the scheduling of pre-recorded programs that were prepared internally.

The IPTV headend in use is made by a company called ZeeVee.  In addition to providing encoders to put live channels over IP, they also make a small PoE-capable receiver.  The receivers are programmable, but left to their own devices, they will tune into a dedicated multicast group and build out their own channel map.  The size and scope of the institution pretty much necessitated as much automatic configuration as possible.

Since the new VOD players send their output to IP directly, there was no built-in method to add their channels to the channel map.  Fortunately, the ZeeVee beacon format was quite easy to determine and after some small efforts, the first internal "beacnator" was born.

After successfully deployment, the beaconator would sit for a couple years.  In a minor fit of curiosity, I thought it would be cool to add SAP Announcement capability to the script such that the channel map would be usable with VLC on a compatible network.  With a little help from ChatGPT to spark the idea, I added the capability to send out SAP announcements that are largely RFC-2974 and RFC-8866 compatible.

## Requirements

Requirements are really light:
* iupy - my python utility module.
* pyyaml - Python YAML module.

## Configuration

This is an early README revision and will only cover the beaconator.yaml file at this time.

### beaconator.yaml

The provided beaconator.yaml is based upon output I use to employ a small IPTV headend in my residence 

#### Configuration Location

The script will look for a beaconator.yaml in the following directory order:
* The directory it's being executed in.
  * `./beaconator.yaml`
* The executing user's home directory.
  * `~/beaconator.yaml`
* If the `IUPY_CFG` environment variable is defined, the script will look for a further "beaconator" subdirectory deeper within the base specified.  (e.g. `IUPY=/usr/etc/myconfig`, look for `/usr/etc/myconfig/beaconator/beaconator.yaml`)
* After this, the file structure will be checked for all other POSIX systems:
  * `/usr/local/etc/beaconator.yaml`
  * `/usr/local/etc/beaconator/beaconator.yaml`
  * `/etc/beaconator.yaml`
  * `/etc/beaconator/beaconator.yaml`

If the file isn't found, the program will exit.

#### Configuration Format

The configuration is a YAML file composed of two sections: beacon and lineup

##### beacon

This section contains the beacon types with their multicast group address, port, and loop interval.

```
beacon:
  -
    type: sap
    groupAddr: 224.2.127.254
    groupPort: 9875
    interval: 60
  -
    type: zeevee
    groupAddr: 239.13.1.19
    groupPort: 21217
    interval: 4
```

_SAP Section_

The SAP group address is configured at the standard global multicast address for SAP as defined in RFC-2974, section 3.  This is 224.2.127.254.  However, the administrative scopes that VLC listens to include 239.195.255.255 (SAP Organization Scope) and 239.255.255.255 (SAP Local Subnet).  The port is set as the RFC requires.

The announcement interval for the channel lineup is arbitrarily set.  This ignores RFC-2974, section 3.1 which assumes a 4000 bps transmission limit which is not likely to apply to a private network.  The actual beacon packet rate will be determined by the size of the channel lineup and the interval the beacons repeat.

_ZeeVee Section_

The parameters for sending ZeeVee beacons are non-negotiable.  The multicast group and port are hard-coded into the receivers.  ZeeVee receivers will drop programs from their channel lineup after missing a couple beacons, which are expected to come at a 4-second interval as best I can tell.

##### lineup

The lineup contains a list of programs to be announced and fits the structure below.  The first channel from the example configuration is provided and will be explained in depth.

```
lineup:
  -
    channelName: WBZ HD
    channelNumber: 4-1
    channelGroupIP: 239.255.1.1
    channelSourceIP: 172.30.0.141
    channelSourcePort: 28001
    announce:
      - sap
      - zeevee
```

Each program must provide the information describing the program.

_channelName_

This is a short identifier for the channel.  This should be in alphanumeric characters only with special characters limited to parenthesis.

_channelNumber_

This is the identifying channel number for the program.  If subchannels are being deligated as in the example above, the delimiter must be a hyphen in order to use the feature on the ZeeVee remote control.

_channelGroupIP_

This is the multiccast group address the program is being broadcast out to.

_channelSourceIP_

This is the source address of the program being multicast.  The information is included in all of the beacons, even in networks where IGMPv3 and source-specific multicast are not being used.

_channelSourcePort_

The is the UDP port the program being multicast.  This will likely vary from system to system, so this number will depend on your encoder settings.

_announce_

This is a simple list of which threads should be announcing the beacons.  For example, a channel which is encoded to the network using a ZeeVee headend may only need a SAP announcement.  Similarly, a program may only be announced to a ZeeVee set-top box and excluded from SAP announcements.

Bear in mind that limiting an announcement type will not secure a given program.  It will, however limit its ability to be discovered automatically.

## Debugging

The script can be called with the `--debug` argument in order to generate a beacon output text for diagnostics.  When this happens, each beacon thread will only run once and will produce the plain-text components of each beacon.

## Notes

Beacon timing is based upon the total interval and the size of the lineups for each beacon type.  The beacons will be (mostly) evenly distributed across the full interval.  For example, a lineup of 4 programs with default timings will send out a beacon approximately every 15 seconds with SAP and every second with ZeeVee before looping.  The intent is to keep traffic distribution even and eliminate bursts.

VLC does not support session modification or session deletion features in SAP announcements due to the inherent security of such.  However, it will remove announcements via an implicit removal method, which is either after 1 hour from receipt of announcement, or 10 times the detected beacon interval.  With a 60-second beacon interval, stale announcements would disappear automatically after 10 minutes.  Be aware, that if the program announcements fail, VLC will also stop displaying a program, even it continues to be mutlicast.

ZeeVee beacons are based upon available documentation and a small amount of reverse engineering.  If you use this, it's likely because you have already bought their stuff.

## References

* [ZeeVee: Intelligent AV Distribution](https://www.zeevee.com/)
* [RFC 2974: Session Announcement Protocol](https://www.rfc-editor.org/rfc/rfc2974)
* [RFC 8866: Session Description Protocol](https://www.rfc-editor.org/rfc/rfc8866)