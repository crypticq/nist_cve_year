#!/bin/bash



for i in {2016..2022}; do cp main.py $i.py && python3 $i.py $i ; done

