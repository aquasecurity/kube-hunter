from argparse import ArgumentTypeError


def ip(string):
    error = ArgumentTypeError("{} is not a valid IP address".format(string))
    octets = string.split(".")

    if len(octets) != 4:
        raise error

    try:
        for o in octets:
            o = int(o)
            if o < 0 or o > 255:
                raise error
    except ValueError:
        raise error

    return string


def subnet(string):
    parts = string.split("/")

    if len(parts) != 2:
        raise ArgumentTypeError("{} is not a valid subnet".format(string))

    host, mask = parts

    ip(host)

    try:
        mask = int(mask)
    except ValueError:
        raise ArgumentTypeError("{} is not an integer".format(mask))

    if mask < 0 or mask > 32:
        raise ArgumentTypeError("{} is not valid host identifier".format(mask))

    return string
