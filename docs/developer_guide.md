# 开发手册与接口

## 算法约定

依据 Stallings《Cryptography and Network Security》第 8 版附录 D 的 S-AES。每个状态为 16 位，按列主序排布为 `[[n0,n2],[n1,n3]]`。S-box 为 `9,4,A,B,D,1,8,5,6,2,0,3,C,E,F,7`；GF(2⁴) 模多项式为 `x⁴+x+1`。正向列混淆矩阵为 `[[1,4],[4,1]]`，逆矩阵为 `[[9,2],[2,9]]`。轮常数为 `80`、`30`。加密顺序：`AddKey0 → SubNib → ShiftRow → MixColumn → AddKey1 → SubNib → ShiftRow → AddKey2`。解密逆序执行。

参考：[第 8 版附录 D PDF](https://testbed.umfst.ro/crypt/LABs_APPs/L4-Ciphers/AES/APENDIX_D-SIMPLIFIED_AES.pdf)。

## 公共接口

从 `saes` 导入。除 ASCII/CBC 接口外，分组和密钥都以非负整数传入。

| 函数 | 输入 | 输出 |
| --- | --- | --- |
| `expand_key(key)` | 16 位密钥 | 三个 16 位轮密钥元组 |
| `encrypt_block(plaintext, key)` / `decrypt_block(ciphertext, key)` | 16 位分组与 16 位密钥 | 16 位整数 |
| `double_encrypt(block, key)` / `double_decrypt(block, key)` | 16 位分组与 32 位 `K1||K2` | 16 位整数 |
| `triple_encrypt(block, key)` / `triple_decrypt(block, key)` | 16 位分组与 48 位 `K1||K2||K3` | 16 位整数 |
| `mitm_attack(pairs, limit=None)` | `(明文,密文)` 整数对列表 | 所有符合已知对的 32 位候选密钥 |
| `encrypt_ascii(text, key)` / `decrypt_ascii(hex, key)` | ASCII 字符串或 Hex、16 位密钥 | Hex 或 ASCII 字符串 |
| `cbc_encrypt(data, key, iv=None)` | 字节串、16 位密钥、可选 16 位 IV | `(iv, 密文字节串)` |
| `cbc_decrypt(ciphertext, key, iv)` | 密文字节串、密钥、IV | 原文字节串 |

`mitm_attack` 的第一对按 `E(P,K1)=D(C,K2)` 建哈希表，再逐个验证其余对。只有一组时返回多个候选是正常结果；多组仍可能碰撞，返回值不能在数学上保证唯一真密钥。

ASCII 与 CBC 均使用块长 2 字节的 PKCS#7 填充。ASCII 页按 ECB 独立分组；CBC 页按 `C_i=E(P_i XOR C_(i-1),K)`，其中 `C_0=IV`。IV 用 `secrets.randbits(16)` 生成。CBC 解密会校验填充，但填充校验不是消息认证。

## 测试

`python -m unittest discover -s tests -v`。测试含教科书参数与向量、S-AES 多点往返、双重/三重往返、ASCII 边界、CBC 篡改传播、MITM 真密钥候选。
