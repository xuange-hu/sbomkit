# sbomkit（中文说明）

**零依赖的供应链体检工具。** 读取项目真正锁定的依赖，产出 CycloneDX / SPDX
SBOM，判断"这个能不能发货"，并对比两份 SBOM，让 PR 能因为降级或许可证变更而失败。

```bash
pip install sbomkit
sbomkit scan .
```

## 三个与其他工具不同的地方

**1. 许可证是表达式，不是字符串。**

多数工具对 license 字段做子串匹配，于是会在最常见的情况上误报：

```
(MIT OR GPL-3.0-only)
```

你有权任选一支，所以这个依赖对闭源产品是安全的。任何 grep 到 `GPL` 就报的
工具都会把它拦掉。sbomkit 真正解析 SPDX 语法（`AND` 优先级高于 `OR`，
`WITH` 带例外），再按分发策略求解：

```console
$ sbomkit licenses "(MIT OR GPL-3.0-only)"
OR (any one)
  MIT -> permissive
  GPL-3.0-only -> strong copyleft
  closed-source  ALLOW    MIT  (OR-expression: taking the friendliest permitted branch (MIT))
```

而 `MIT AND GPL-3.0-only` 在同一策略下是 **DENY** —— `AND` 取最严的一支。

**2. 风险在"变化"里，不在快照里。**

升级是噪音，**降级**、新增传递依赖、某个包悄悄从 MIT 换成 AGPL 不是。
只看单张快照的工具一条都发现不了。

**3. 每条结论都能溯源。**

不联网、不调模型、不猜。每条 finding 带文件路径、行号和原始文本。
许可证无法确定时答案是 `unknown`，不是"大概没问题"。

## 常用命令

```bash
sbomkit scan .                          # 体检
sbomkit sbom . -o bom.json              # CycloneDX 1.6
sbomkit sbom . --format spdx -o b.spdx  # SPDX 2.3
sbomkit diff baseline.json new.json --fail-on high
sbomkit licenses "(MIT OR GPL-3.0-only)"
sbomkit rules
sbomkit demo                            # 生成样例项目，17 条规则全部命中
```

## 支持的输入

| 生态 | manifest | lockfile |
|---|---|---|
| PyPI | `requirements*.txt`、`constraints.txt`、`pyproject.toml`（PEP 621 + Poetry） | `poetry.lock`、`uv.lock` |
| npm | `package.json` | `package-lock.json`（v1/v2/v3）、`yarn.lock` v1 |
| Go | `go.mod` | `go.sum` |
| Cargo | `Cargo.toml` | `Cargo.lock` |

## 分发策略

| 策略 | 允许 |
|---|---|
| `closed-source` | 公有领域 + 宽松许可证（默认） |
| `weak-ok` | 再加弱 copyleft（MPL、LGPL、CDDL） |
| `oss` | 全部，含强/网络 copyleft |
| `strict` | 仅宽松许可证 |

## 许可证数据来源（按优先级）

1. `--license-map`（JSON）
2. lockfile 内联字段（npm 有）
3. **本地已安装元数据**：`node_modules/<pkg>/package.json`、
   `.venv/**/site-packages/*.dist-info/METADATA`
4. 内置约 150 个常见包的表格
5. `unknown`

第 3 项与第 4 项冲突本身就是一条 finding（SBK012）。

## 范围之外

- 漏洞数据（CVE/OSV）不在此列——离线工具声称能做就是在猜。
- `pnpm-lock.yaml` 与 Yarn Berry 尚未支持。
- Go / Cargo 的许可证通常返回 `unknown`，因为它们的 lockfile 不带许可证
  信息，也不探测本地缓存。

MIT 许可证。
