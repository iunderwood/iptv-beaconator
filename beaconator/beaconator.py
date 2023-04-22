#!/usr/bin/env python3

# Internal Imports
import argparse
import binascii
import datetime
import logging
import pprint
import socket
import struct
import threading
import time

# External Imports
import iupy
import yaml
import yaml.scanner

version = 0.2
config = dict()


def cli_args():
    """
    Process arguments from the command line.

    :return:
    """
    _logger = logging.getLogger("beaconator/cli_args")

    cli_parser = argparse.ArgumentParser(description="beaconator v{}".format(version),
                                         epilog="This program regularly sends out beacons supporting IPTV.")
    cli_parser.add_argument('-d', '--debug',
                            action='store_true',
                            help="Enable debug output")
    cli_parser.add_argument('-c',
                            action='store_true',
                            help="Display configuration")

    _args = cli_parser.parse_args()

    if vars(_args)['debug']:
        logging.basicConfig(level=logging.DEBUG)
        _logger.debug("Debug Logging Enabled")
    else:
        _logger.debug("This should not be on.")
        logging.basicConfig(level=logging.WARNING)

    return _args


def load_config(config_file):
    """
    Loads and processes the module configuration.

    :param config_file:
    :return:
    """
    _logger = logging.getLogger("beaconator/load_config")

    global config

    # Load the configuration file into a dictionary.
    config_dict = iupy.get_my_config(config_file, subdir="beaconator")

    if not config_dict:
        _logger.error("Unable to find configuration {} in any of the expected locations.".format(config_file))
        return False

    # Attempt to load the YAML config into a dictionary.
    try:
        config_yaml = yaml.load(config_dict['data'], Loader=yaml.SafeLoader)
    except yaml.scanner.ScannerError as error:
        _logger.error("File {} is not a valid YAML file.\n----\n{}\n----\n".format(config_file, error))
        return False

    # Create the config, if we can't append to it first.
    try:
        config = {**config, **config_yaml}
    except TypeError:
        config = {**config_yaml}

    # Save metadata to the config dictionary
    config['cfg_time'] = config_dict['filetime']
    config['cfg_file'] = config_dict['file']

    return


def print_config():
    """
    This function prints the configuration information.

    :return:
    """

    globals()

    print("Config file loaded: {}".format(config['cfg_file']))
    pprint.pprint(config)


def socket_new():
    """
    This function opens up and returns a socket object for multicast announcement.

    :return: b_socket
    """

    # Set up a new socket.  This is an IPv4, datagram, UDP socket
    b_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    b_socket.settimeout(0.2)
    b_socket.setsockopt(socket.IPPROTO_IP, socket.SO_REUSEADDR, 1)
    b_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack('b', 16))

    return b_socket


def socket_info(config_dict, b_method):
    """
    This function returns the beacon information for a defined method.

    :param config_dict:
    :param b_method:
    :return:
    """

    _logger = logging.getLogger("beaconator/socket_info")

    for item in config_dict['beacon']:
        if item['type'] == b_method:
            _logger.debug("Located socket info for {} method.".format(b_method))
            return item

    _logger.debug("Unable to find socket information for {} method.".format(b_method))
    return False


def lineup_list(config_dict, b_method):
    """
    This function creates a list of channels that match an announcement method.

    :param config_dict:
    :param b_method:
    :return:
    """

    _logger = logging.getLogger("beaconator/lineup_list")

    lineup = list()

    for program in config_dict['lineup']:

        # Add to the lineup, if the beacon method is in the announcement list.
        if b_method in program['announce']:
            _logger.debug("Program {} announced via {}".format(program['channelName'], b_method))
            lineup.append(program)

    _logger.debug("{} list has {} entries".format(b_method, len(lineup)))

    return lineup


def beacon_packet(b_socket, b_method, b_channel, b_info):
    """
    This function generates and transmits an announcement based upon its type.

    :param b_socket:
    :param b_method:
    :param b_channel:
    :param b_info:
    :return:
    """

    _logger = logging.getLogger("beaconator/beacon_packet")

    beacon_dest = (b_info['groupAddr'], b_info['groupPort'])

    # Generate and transmit SAP Announcement
    if b_method == "sap":
        datetime_int = int(datetime.datetime.utcnow().timestamp())

        session_info = "v=0\r\n" \
                       "o=- {} {} IN IP4 {}\r\n" \
                       "s={}: {}\r\n" \
                       "i=IPTV Video Network\r\n" \
                       "c=IN IP4 {}/16\r\n" \
                       "t=0 0\r\n" \
                       "a=recvonly\r\n" \
                       "a=type:broadcast\r\n" \
                       "a=source-filter: incl IN IP4 * {}\r\n" \
                       "m=video {} udp mpeg\r\n". \
            format(datetime_int, datetime_int, b_channel['channelSourceIP'],
                   b_channel['channelNumber'], b_channel['channelName'],
                   b_channel['channelGroupIP'],
                   b_channel['channelSourceIP'],
                   b_channel['channelSourcePort'])

        _logger.debug("SDP Message: {}".format(session_info))

        hash_base = "{}: {}".format(b_channel['channelNumber'],
                                    b_channel['channelName'])

        sap_struct = iupy.sap_segment(version=1, src_ip_addr=config['myip'],
                                      id_hash=binascii.crc_hqx(bytes(hash_base, 'utf-8'), 0),
                                      payload_type='application/sdp', payload=session_info)

        if sap_struct is None:
            _logger.debug("Unable to build SAP Packet.")
            return

        try:
            b_socket.sendto(sap_struct, beacon_dest)
        except OSError as error:
            _logger.error("OSError on SAP send: {}".format(error))

    # Generate and transmit ZeeVee Beacon
    elif b_method == "zeevee":
        # Set Output Message
        message = '<?xml version="1.0" encoding="UTF-8"?><ZVIP type="guide"><CHAN><srcip>{}</srcip>' \
                  '<ip>{}</ip><port>{}</port><tstype>tsoverudp</tstype><name>{}</name><pnum>{}</pnum>' \
                  '</CHAN></ZVIP>'. \
            format(b_channel['channelSourceIP'],
                   b_channel['channelGroupIP'],
                   b_channel['channelSourcePort'],
                   b_channel['channelName'],
                   b_channel['channelNumber'])

        # Debug Print Message
        _logger.debug("Zeevee Message: {}".format(message))

        # Post Beacon to Socket
        try:
            b_socket.sendto(str.encode(message), beacon_dest)
        except OSError as error:
            _logger.error("OSError on ZeeVee Send: {}".format(error))
    else:
        _logger.error("Unrecognized method: {}".format(b_method))

    return


def beacon_loop(b_method):
    """
    This function controls the looping of beacon announcements.

    :param b_method:
    :return:
    """

    _logger = logging.getLogger("beaconator/beacon:{}".format(b_method))
    _logger.debug("Starting beacon loop...")

    info = socket_info(config, b_method)
    lineup = lineup_list(config, b_method)

    # If there is nothing in a given lineup, just return.
    if len(lineup) == 0:
        _logger.debug("Lineup length is zero.")
        return
    else:
        _logger.info("Lineup for {} contains {} elements".format(b_method, len(lineup)))

    # The loop delay is the interval divided by the length of the lineup.
    loop_delay = info['interval'] / len(lineup)
    _logger.info("Inter-beacon delay: {} seconds.".format(loop_delay))

    beacon_socket = socket_new()

    # The beacons will loop unless broken out, which we check the global config for.
    done = False
    while not done:
        # Perform only one loop if we are debugging.
        if _logger.getEffectiveLevel() == logging.DEBUG:
            _logger.debug("One Debug Loop Only")
            done = True

        # Loop through the lineup, with the prescribed delay between announcements.
        for channel in lineup:
            beacon_packet(beacon_socket, b_method, channel, info)
            time.sleep(loop_delay)

            # Check and see if we have a break condition.
            if "break" in config:
                done = True
                break

    _logger.debug("Beacon Loop Complete")

    beacon_socket.close()

    return


if __name__ == "__main__":
    """
    The function which runs it all.

    :return:
    """

    # Process the CLI
    args = cli_args()

    # Load the beaconator configuration.
    load_config("beaconator.yaml")

    # Detect my address and apply it to the global configuration.
    config['myip'] = iupy.get_my_ip()

    # Print the configuration if it is requested, then exit.
    if vars(args)['c'] is True:
        print_config()
        exit(0)

    print("Beaconator v{} - There is no output.".format(version))

    # Define the threads required.
    t1 = threading.Thread(target=beacon_loop, args=("sap", ))
    t2 = threading.Thread(target=beacon_loop, args=("zeevee", ))

    # Start our threads
    logging.info("Starting Threads...")
    t1.start()
    t2.start()

    # Once the threads are called, the program ends and waits.
    logging.debug("All threads have been called.")

    # Close threads gracefully if there's a keyboard interrupt.
    try:
        while True:
            time.sleep(.1)
    except KeyboardInterrupt:
        print(" Closing threads ...")
        config['break'] = True
        t1.join()
        t2.join()
