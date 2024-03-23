#!/usr/bin/env python3
import pandas as pd
import binascii

df = pd.read_csv('newlog.csv',delimiter='`9628478396`',names=['filename','entry'],encoding='latin-1')

nonetype =0
nan = 0

for i in range(len(df['entry'])):
    # print(i)
    if (type(df['entry'][i]) == float):
        # nan += 1
        continue

    try:
        len(df['entry'][i]) >= 0
        # nonetype += 1
    except:
        continue 
    if df['entry'][i].isascii() == False:
        df['entry'][i] = '<bin>' + binascii.hexlify(df['entry'][i].encode()).decode()

print(nonetype,nan)
