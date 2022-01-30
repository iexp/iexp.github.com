---
layout: post
title:   浅谈系统安全启动
date: 2022-01-27 15:16:29
categories: Android安全攻防
tags: bootloader security
toc: true
author: lihs
---
## 介绍
安全启动（Secure Boot)也叫验证启动(Verified Boot)。在支持安全启动的系统中，启动过程的每一步，在加载程序之前，都要验证待加载的程序，验证不通过则中止启动，从而保证系统在启动过程中加载的每一个模块都是安全的。安全启动被攻破后，teeos、kernel、system等分区镜像都是不可信的，攻击 者通过篡改这些镜像可达到攻击系统的目的，例如修改kernel进行永久root、安装第三方ROM、修改teeos来访问用户的敏感数据（如指纹、人脸、根密钥等）、修改运营商数据等 。

## 原理

安全启动是通过签名校验来实现的：

>上电 ----> 片上程序 --签名校验（此处的公钥由efuse熔丝保护)--> ATF BL31 --签名校验--> Secure OS --签名校验--> 其它镜像

安全启动流程：
1. 逐级校验方式 ， 验签从`片上程序`开始 。
2. 镜像 (ATF BL31[^1], SecureOS, Kernel)采用 “摘要算法” + “非对称签名算法”进行签名。
3. 根公钥的HASH值烧写在芯片的OTP中。

## 实现

Fastboot模式下刷镜像流程：
```c
/*
fastboot flash {partition} {*.img} 烧写指定分区
例如：fastboot flash boot boot.img
      fastboot flash system system.img
*/
Rx_cmd
 --->sub_usb_rx_ //接收adb 命令
       -->sub_flash_func // 
          -->sub_usbcmd_flash_func
             -->sub_verify
                -->sub_download_verify //
                   -->sub_image_verify
                      -->sub_imgsecure_verify   // 安全镜像校验 
                         --> sub_verify_cert    // 校验一级、二级以及内容证书
                             -->sub_parser_vrl  // 解析VRL
                             --> sub_verify_xx
                                 -->sub_internal_parser       // 将pCert指向的证书内容解析到rsaData
                                 -->sub_read_public_key_hash   // 从efuse中读取公钥HASH
                                 --> sub_hash_cmp // SHA256(v.rsa_n +v.rsa_np),并与efuse中读取到的SHA256进行对比，即保证镜像中VRL中公钥的完整性.
                                 -->sub_verify_signature //对VRL的前0x1cc的数据进行签名验证
                                     --> sub_calc_sha256 //计算VRL前0x1CC字节的SHA256
                                     --> sub_rsa_pss // RSA PSS方式 验证数字签名 ,0x1cc-0x2cc是 0x00-0x1cc共0x1cc字节数据的数字签名
                             --> sub_xxx // 如果是内容证书并且自签名通过，则对镜像内容进行校验并进行AES CTR解密，目前xxx等镜像都是加密存储,运行时解密 。
```

## 总结
Android系统正常启动加载镜像或fastboot模式下刷镜像时，系统都会对要加载或刷入的镜像做完整性校验。`efuse中的公钥哈希保证了一级证书的RSA公钥不被篡改，通过RSA公钥和签名信息对一级证书内容进行签名验证（RSA-PSS方式），保证了一级证书内容的完整性. 而一级证书内容包含了下一级证书的RSA公钥哈希，其验签过程与一级证书相同。同样最后一级证书的RSA公钥哈希保存在上一级证书，其完整性也是通过RSA-PSS方式验证。最后一级证书内容包含了整个镜像数据的哈希，用于保证整个镜像的完整性。 这样OTP、一级证书、二级证书、三级证书和镜像数据就形成了信任链。` 这样只有通过厂商RSA 私钥签名的镜像才能被加载，也防止了刷机方式进行ROOT。
RSA[^2]-PSS[^4]数字签名验证[^3]本质也是对比`两个途径获取的哈希值  ` ,一个是通过计算被签名数据 获取的哈希，另一个是通过RSA公钥 解密签名信息 获取的哈希，RSA公钥的完整性由efuse熔丝保护，RSA-PSS方式的验签只是加入了对原始数据hash拼接salt后的再一次哈希计算，增加了安全强度。


## 参考
[^1]:[arm-trusted-firmware](https://github.com/ARM-software/arm-trusted-firmware)

[^2]:[带你彻底理解RSA算法原理](https://blog.csdn.net/dbs1215/article/details/48953589)

[^3]:[数字签名：RSA-PSS 实现](https://blog.csdn.net/qq_34911465/article/details/78790377)

[^4]:[RSA签名的PSS模式](https://cloud.tencent.com/developer/article/1376530)