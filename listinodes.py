#!/usr/bin/env python3

import os
import argparse
import sys

def scan_dir(path,rec):
    with os.scandir(path) as itr:
        for entry in itr:
            if entry.is_file():
                print('File : ',entry.name)
                print('\tPath : ',entry.path)
                print('\tInode : ',entry.inode())
                print()
            elif entry.is_dir():
                print('Directory : ',entry.name)
                print('\tDir Inode : ',entry.inode())
                print()
                if(rec):
                    scan_dir(entry.path,rec)

def scan_file(path):
    try:
        fs = os.stat(path)
        print(f'Name : {path}')
        print(f"\tInode : {fs.st_ino}")
    except FileNotFoundError:
        print(f"File not found ")
    except Exception as e:
        print("Problem scanning the file : ",e)

def main():
    parser = argparse.ArgumentParser(description="Simple python file that scans for everything in the given directory and gives it's inode")
    parser.add_argument('-d','--dir',type=str,help="Directory to get info from")
    parser.add_argument('-r','--recursive',action='store_true',help='Recursively list files in the directories')
    parser.add_argument('-f','--file',type=str,default=None,help='File to get inode for')
    args = parser.parse_args()
    
    if(args.file):
        scan_file(args.file)
        sys.exit(0)

    d = args.dir
    if(not args.dir):
        print(f'Getting current directory information')
        d = './'

    rec = False
    if(args.recursive):
        rec = True

    scan_dir(d,rec)


if __name__ == '__main__':
    main()
