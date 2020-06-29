# escape=`

FROM mcr.microsoft.com/windows:1809

CMD [ "cmd.exe" ]

RUN powershell -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "[System.Net.ServicePointManager]::SecurityProtocol = 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin" && `
    choco install -y --timeout 0 git make python2 visualstudio2012professional && `
    refreshenv && `
    git --version

RUN git clone https://github.com/nchong-at-aws/vcc.git && `
    git clone https://github.com/z3prover/z3.git

RUN cd "C:\Program Files (x86)\Microsoft Visual Studio 11.0\Common7\Tools" && `
    .\vsvars32.bat && `
    cd "C:\z3" && `
    git checkout z3-4.3.0 && `
    python scripts\mk_make.py && `
    cd "build" && `
    nmake && `
    cd "C:\vcc" && `
    # some vcc build failures are acceptable
    (msbuild || exit 0)

RUN copy /Y "C:\z3\build\z3.exe" "C:\vcc\vcc\Host\bin\Debug\z3.exe"

# Add vcc to path
RUN powershell -Command "$path = $env:path + ';C:\vcc\vcc\Host\bin\Debug'; Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment\' -Name Path -Value $path"

# sanity check
RUN vcc "C:\vcc\vcc\Test\testsuite\examples3\ArrayList.c"
