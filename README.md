# 基于SHA256和RSA的数字签名

## RSA算法实现
在尝试了自己动手造车轮，用C++编写大数类和素性检测函数，以及尝试使用C及C++的附加大数类库（譬如MPUINT, GMP, GUN Cryto, boost等）之后，终于意识到自己编写的类和函数过于低效，而附加类库又过于庞杂。  
在经过无数次失败的尝试后，决定转用标准库自带了大数类的JAVA。  
果然，JAVA原生的大数库使用简便而且高效。剩下的只需要自己编写RSA的算法实现即可。终于让我意识到了C++的局限性。  
不过，这个过程也不是一无所获。查阅了大量的资料，让我深刻地了解了RSA算法和素性检测算法，同时也意识到了大数运算的复杂性。  
	
## SHA函数
相较于RSA，SHA的实现过程就没那么坎坷了，但也绝非易事。在Wikipedia上查找了SHA256的伪代码实现，将之转化为JAVA代码。  
第一次运行，计算英文Hello的hash值并于网上的在线hash值计算软件比对，发现不一致。遂查看网页的源代码，然后逐条执行，与自己的程序比对，反复纠错。其中还遇到了负数右移的问题。在查找资料后，将右移>>改为无符号右移>>>，配合其他一些地方的改动，终于顺利解决。  

## 签名函数
与前两者比较起来，签名函数是最轻松的。基本没遇到什么问题，按着公式顺利解决。  

## Screenshots / 截屏
Load key and verify signature:  
![VerifySign](/docs/hashCode&verifyFunctionPass.png "Load key and verify signature.")

Generate key & Get hash value of file:  
![KeyAndHash](/docs/generateKey&getHashVal.png "Generate key & Get hash value of file.")

Signature & Verify:  
![SignAndVerify](/docs/signature&verify.png "Signature & Verify.")

## Author / 作者
[![Donny](https://avatars.githubusercontent.com/u/22200374?v=3&s=150 "Donny")](https://github.com/Donny-Hikari)