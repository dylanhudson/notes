#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import csv
#import pandas as pd

if len(sys.argv) != 2:
    print("Missing input file.")
    print('Use: %s <filename>' % sys.argv[0])
    sys.exit(1)

filename = sys.argv[1]

with open('filename', newline='') as data:
    data_reader = csv.reader(data, delimiter='\t')
    for line in data_reader:
        print(line) # pipe output to desired file
