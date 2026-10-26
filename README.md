# S-AES 算法实现

信息安全导论 · S-AES 课程作业。沿用[上次 S-DES 项目](https://github.com/Cyanlament/realization-of-S-DES-algorithm)的“源码、测试、证据、用户指南、开发手册”组织方式，重新实现本次算法与五关实验。源码只依赖 Python 标准库，桌面 GUI 使用 Tkinter。

| 组员 | 姓名 | 学号 |
| --- | --- | --- |
| 1 | 扶满 | 20245177 |
| 2 | 蔡旭涛 | 20240947 |

## 1 启动

安装 Python 3.10 或更新版本。在 Windows 双击 `run.bat`，或在项目根目录执行：

```shell
python main.py
```

图形界面提供单块 S-AES、双重和三重加解密、ASCII 文本加解密、32 位双重密钥中间相遇搜索、CBC 文本加解密。所有密钥、分组、IV 均按十六进制输入；密文以十六进制显示，避免乱码丢失。

## 2 实验成果

| 关卡 | 实现与证据 |
| --- | --- |
| 第 1 关：基本测试 | 16 位分组、16 位密钥，GUI 加解密；`D728` / `4AF5` → `24EC` |
| 第 2 关：交叉测试 | 本组与外组程序在 `K=4AF5、P=D728` 时均得到 `C=24EC`，双方解密均恢复 `D728`；运行截图和证据范围见组间交叉测试报告 |
| 第 3 关：扩展功能 | ASCII 两字节分组、PKCS#7 填充、Hex 密文 |
| 第 4 关：多重加密 | 32 位 E(E(P,K1),K2)、中间相遇攻击、48 位 EEE 三重加解密 |
| 第 5 关：工作模式 | CBC、随机 16 位 IV、显式 IV 共享、密文篡改对照 |

数值与操作记录见[五关测试结果](evidence/test_results.md)，组间运行截图与结论见[组间交叉测试报告](evidence/cross_group_template.md)。

## 3 文档与验证

- [用户指南](docs/user_guide.md)
- [开发手册及接口](docs/developer_guide.md)
- [五关测试结果](evidence/test_results.md)
- [组间交叉测试报告](evidence/cross_group_template.md)
- [附录 D 组件交叉测试](evidence/component_cross_test.md)

在项目根目录运行：

```shell
python -m unittest discover -s tests -v
```

目录：`saes/` 为算法和模式；`main.py` 为 GUI；`tests/` 为自动化测试；`evidence/` 为实验结果；`docs/` 为说明。

S-AES 的 16 位分组和密钥仅用于教学。CBC 可展示篡改传播，但不提供可靠的完整性认证；密文出现改动时仍可能通过填充校验。课件中的“链式连锁，篡改可查”应理解为可观察到影响，不能据此将本程序用于安全通信。
