#!/usr/bin/env python3

import argparse
import pytest
import tests

def main():
    exit(pytest.main(['.']))


if __name__ == '__main__':
    main()
