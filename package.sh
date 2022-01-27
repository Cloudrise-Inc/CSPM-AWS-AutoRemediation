#! /bin/bash
echo on
TARGET=Lambda/GetNetskopeDLPScanAlertsLambda

cd $TARGET 

pip install --target ./package -r requirements.txt 
cd package
zip -r ../GetNeskopeDLPScanAlertsLambda.zip .
cd ..
zip -g GetNeskopeDLPScanAlertsLambda.zip lambda_function.py
zip -rg GetNeskopeDLPScanAlertsLambda.zip utils

rm -rf package

# Upload lambda to bucket.