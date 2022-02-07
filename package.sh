#! /bin/bash
echo on
TARGET=Lambda/DLPScanLabelActionLambda
ZIP_NAME=S3DLPLabelActionLambda

cd $TARGET 

pip install --target ./package -r requirements.txt --no-deps
cd package
zip -r ../$ZIP_NAME.zip .
cd ..
zip -g $ZIP_NAME.zip lambda_function.py
zip -rg $ZIP_NAME.zip utils

rm -rf package

# Upload lambda to bucket.