
cd ../
mkdir install

git clone https://github.com/awslabs/aws-c-common.git
cd aws-c-common
mkdir build
cd build
cmake %* -DCMAKE_BUILD_TYPE="Release" -DCMAKE_INSTALL_PREFIX=../../install ../ || goto error
msbuild.exe aws-c-common.vcxproj /p:Configuration=Release || goto error
msbuild.exe INSTALL.vcxproj /p:Configuration=Release || goto error
ctest -V || goto error
cd ../..

cd aws-c-io
mkdir build
cd build
cmake %* -DCMAKE_BUILD_TYPE="Release" -DCMAKE_INSTALL_PREFIX=../../install ../ || goto error
msbuild.exe aws-c-io.vcxproj /p:Configuration=Release || goto error
msbuild.exe tests/aws-c-io-tests.vcxproj /p:Configuration=Release || goto error
ctest -V

goto :EOF

:error
echo Failed with error #%errorlevel%.
exit /b %errorlevel%