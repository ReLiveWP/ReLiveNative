# msidcrl.dll

Client Library for Windows LIVE ID Functionality. 

## Note:
While this library is technically C++, to avoid loading libstdc++6.dll (about 1.5MB) into the working set of every client program, please avoid using any STL features. That kind of functionality should live within wlidsvc.