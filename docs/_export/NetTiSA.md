---
title: NetTiSA
description: List of unirec fields exported together with NetTiSA flow fields on interface by nettisa plugin.    
fields: 
  - 
    name: "NTS_MEAN"
    type:  "float"
    ipfix: "8057/1020"
    value:   "The mean of the payload lengths of packets"
  - 
    name: "NTS_MIN"
    type:   "uint16"
    ipfix: "8057/1021"
    value:  "Minimal value from all packet payload lengths"
  - 
    name: "NTS_MAX"
    type:   "uint16"
    ipfix: "8057/1022"
    value:  "Maximum value from all packet payload lengths"
  - 
    name: "NTS_STDEV"
    type:   "float"
    ipfix: "8057/1023"
    value:   "Represents a switching ratio between different values of the sequence of observation."
  - 
    name: "NTS_KURTOSIS"
    type:  "float"
    ipfix: "8057/1024"
    value:   "The standard deviation is measure of the variation of data from the mean."
  - 
    name: "NTS_ROOT_MEAN_SQUARE"
    type:  "float"
    ipfix: "8057/1025"
    value:   "The measure of the magnitude of payload lengths of packets."
  - 
    name: "NTS_AVERAGE_DISPERSION"
    type:  "float"
    ipfix: "8057/1026"
    value:   "The average absolute difference between each payload length of packet and the mean value."
  - 
    name: "NTS_MEAN_SCALED_TIME"
    type:  "float"
    ipfix: "8057/1027"
    value:   "The kurtosis is the measure describing the extent to which the tails of a distribution differ from the tails of a normal distribution."
  - 
    name: "NTS_MEAN_DIFFTIMES"
    type:  "float"
    ipfix: "8057/1028"
    value:   "The scaled times is defined as sequence s(t) = t<sub>1</sub> − t<sub>1</sub> , t<sub>2</sub> − t<sub>1</sub> , … , t<sub>n</sub> − t<sub>1</sub> . We compute the mean of the value with same method as for feature <i>Mean</i>."
  - 
    name: "NTS_MIN_DIFFTIMES"
    type:   "float"
    ipfix: "8057/1029"
    value:   "The time differences is defined as sequence <i>d<sub>t</sub></i> = t<sub>j</sub> - t<sub>i</sub> | j = i + 1, i in 1, 2, ... n - 1. We compute the mean of the value with same method as for feature <i>Mean</i>."
  - 
    name: "NTS_MAX_DIFFTIMES"
    type:   "float"
    ipfix: "8057/1030"
    value:   "Minimal value from all time differences, i.e., min space between packets."
  - 
    name: "NTS_TIME_DISTRIBUTION"
    type:   "float"
    ipfix: "8057/1031"
    value:   "Maximum value from all time differences, i.e., max space between packets."
  - 
    name: "NTS_SWITCHING_RATIO"
    type:   "float"
    ipfix: "8057/1032"
    value:   "Describes the distribution of time differences between individual packets."
---