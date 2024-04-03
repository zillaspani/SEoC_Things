#!/bin/bash

lista=("t11" "t12" "t21" "t31" "t32" "t41" "t51" "t52")

for elemento in "${lista[@]}"
do
    rm "${elemento}/app.py"
    # Execute the cp command, replacing "a1" with the current element of the list
    cp "./app.py" "${elemento}/app.py"
done

docker-compose up --build