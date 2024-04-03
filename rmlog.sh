#!/bin/bash

lista=("t11" "t12" "t21" "t31" "t32" "t41" "t51" "t52")

for elemento in "${lista[@]}"
do
    # Esegui il comando rm sostituendo "a1" con l'elemento corrente della lista
    rm "${elemento}/data/log/${elemento}_log.log"
done
