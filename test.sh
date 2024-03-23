#!/bin/bash

for i in $(cat not_installed.txt); do
	sudo apt install $i
done
