#!/bin/bash
function aender() {
 eval "$1='neuer Wert'";
}

wert="alter Wert";
echo $wert
aender wert
echo $wert
