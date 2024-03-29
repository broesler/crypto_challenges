#!/usr/bin/env python3
# =============================================================================
#     File: char_freq.py
#  Created: 2022-07-31 17:04
#   Author: Bernie Roesler
#
"""
Description:
"""
# =============================================================================

import numpy as np

char_freq = dict(
    Space=18.28846265,
    E    =10.26665037,
    T    = 7.51699827,
    A    = 6.53216702,
    O    = 6.15957725,
    N    = 5.71201113,
    I    = 5.66844326,
    S    = 5.31700534,
    R    = 4.98790855,
    H    = 4.97856396,
    L    = 3.31754796,
    D    = 3.28292310,
    U    = 2.27579536,
    C    = 2.23367596,
    M    = 2.02656783,
    F    = 1.98306716,
    W    = 1.70389377,
    G    = 1.62490441,
    P    = 1.50432428,
    Y    = 1.42766662,
    B    = 1.25888074,
    V    = 0.79611644,
    K    = 0.56096272,
    X    = 0.14092016,
    J    = 0.09752181,
    Q    = 0.08367550,
    Z    = 0.05128469)

tot = sum(char_freq.values())
char_freq = {k: v / tot for k, v in char_freq.items()}

assert np.isclose(sum(char_freq.values()), 1.0)

# for k, v in sorted(char_freq.items()):
#     print(f"{k}  \t{v:>f}")
#
# A       0.065454
# B       0.012614
# C       0.022382
# D       0.032896
# E       0.102875
# F       0.019871
# G       0.016282
# H       0.049887
# I       0.056799
# J       0.000977
# K       0.005621
# L       0.033243
# M       0.020307
# N       0.057236
# O       0.061721
# P       0.015074
# Q       0.000838
# R       0.049980
# S       0.053278
# T       0.075322
# U       0.022804
# V       0.007977
# W       0.017074
# X       0.001412
# Y       0.014306
# Z       0.000514
# Space   0.183256

s = "Anything less than the best is a felony."
d = dict()
for c in s:
    if c in d:
        d[c] += 1
    else:
        d[c] = 1

# =============================================================================
# =============================================================================
