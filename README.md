# sbsigntool_sm2
This code is modified from the [sbsigntool](https://github.com/wmarone/sbsigntool), I just take palce the sign algorithm(sha256 to sm2).
##how to install
Before you compile the code, you should make sure the gmssl installed. And then eport the path of the gmssl:
```
export CFLAGS="-I/usr/local/ssl/include"
export LDFLAGS="-L/usr/local/ssl/lib"
export LIBS="-ldl"
```
You can find build-depends packages from the following website --[sbsigntool (0.6-0ubuntu1~12.04.1)](http://packages.ubuntu.com/zh-cn/source/precise/sbsigntool)
##how to use
If you have finished the installation, you can do the following to generate a key and cert and then exerience the signtool.

	1.generate a private key:
		gmssl ecparam -genkey  -name secp112r1 -out eckey.pem
	2.use the key to generate a cert
		gmssl req -new -x509 -key eckey.pem -out eckey.cert
	3.use the private key (and cert) to sign a efi file
		sbsign --key eckey.pem --cert eckey.cert --output test.efi grubx64.efi
	4.use the cert to verify the signed file
		sbverify --cert eckey.cert test.efi
