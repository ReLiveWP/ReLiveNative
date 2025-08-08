## Deployment

#### Pkg_ReLiveWP
 - `wlidsvc.dll`
 - `msidcrl.dll`
 - relive config app
 - registry/security entries to make these two work

Depends on: `Pkg_ReLivePlatform`, `Pkg_ReLiveRoots`

#### Pkg_ReLivePlatform
 - `libatomic-1.dll`
 - `libcurl.dll`
 - `libpsl-5.dll`
 - `libsqlite3-0.dll`
 - `libssp-0.dll`
 - `zlib1.dll`
 - `libstdc++-6.dll` << optional

Depends on: `Pkg_ReLiveRoots`

#### Pkg_ReLiveRoots
 - `tlsroots.pem`