#!/usr/bin/env python3

import pytest
import tests  # noqa


def main():
    exit(pytest.main(["."]))


if __name__ == "__main__":
    main()
