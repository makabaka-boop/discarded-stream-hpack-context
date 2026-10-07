# h2audit — HTTP/2 单向捕获 HPACK 审计器

抓包工具按流号丢弃 HTTP/2 请求时，被丢弃的头区块仍然推进连接级 HPACK
动态表；若过滤后不再解码这些区块，后续正常请求的索引引用就解不出来。
本工具读取**一个捕获方向**的原始帧字节和待丢弃流编号，重组并解码所有
头区块（含被丢弃的），输出正常流的有序头列表及逐项引用来源。

## 实现边界

- 协商动态表上限固定 **256 字节**；捕获总大小不超过 **16 KiB**。
- 不处理 TLS、服务端推送（`PUSH_PROMISE` 直接判连接错误）和流量控制。
- HPACK 全部自行实现：N 位前缀整数、字符串字面量、索引/字面量表示、
  动态表容量更新、逐项淘汰（条目大小 = 名长 + 值长 + 32）。
- **只有 Huffman 字符串原语**调用成熟组件（`hpack.huffman_table.
  decode_huffman`；库缺失时回退到内置的 RFC 7541 Appendix B 表解码器，
  两者行为一致，有测试保证）。整个头区块绝不交给现成 HPACK 解码器。

## 审计规则

| 情况 | 行为 |
| --- | --- |
| 头区块未结束（缺 CONTINUATION）就插入其他帧 | 连接错误，停止 |
| 被丢弃流的头区块 | 完整解码并推进共享动态表，只是不交付字段 |
| 正常流的头列表 | 按字段顺序输出，重复字段不折叠，附引用来源 |
| 字段数 > 64 | 只拒绝该列表，压缩指令照常消费，连接继续 |
| 非法索引 / 非法容量更新（>256 或不在块首）/ 坏 Huffman | 停止整个连接，不猜测后续状态 |

退出码：`0` 正常消费；`1` 用法/IO 错误；`2` 连接错误（报告部分结果后停止）。

## 用法

```bash
python3 h2audit.py <capture.bin> [--drop-streams 3,7] [--verbose]
```

输出为 JSON：每个头区块一条记录（`delivered` / `dropped` / `rejected`），
`delivered` 含 `headers` 数组，每项带 `source`：

- `{"type": "indexed", "table": "static"|"dynamic", "index": N}`
- `{"type": "literal", "indexing": "incremental"|"without"|"never",
   "name_from": {...}|"literal", "value_huffman": bool, ...}`

`--verbose` 额外输出连接末尾的动态表状态（索引、条目、占用字节）。

## 容器（Compose 挂载输入文件）

```bash
docker compose build
# 把捕获文件放进 ./captures（只读挂载到容器的 /captures）
docker compose run --rm auditor /captures/your-capture.bin --drop-streams 3,7
docker compose up auditor                    # 跑 compose 里预置的 demo 命令
docker compose --profile test run --rm tests # 容器内跑测试
```

## 测试与样例

样例全部由标准编码器（`hpack.Encoder`，表上限 256）生成：

```bash
python3 tests/test_h2audit.py                  # 12 项测试
python3 tests/test_h2audit.py --emit-demo captures/   # 重新生成演示捕获
```

覆盖：被丢弃区块与后续索引引用串接（流 5 的头区块是纯动态表索引
`0xbf 0xbe 0xc0`，只有解码了被丢弃的流 3 才能解析）、256 字节表淘汰
与重发字面量、HEADERS+CONTINUATION 分片（含填充/优先级）、坏区块
（非法索引、非法容量更新、坏 Huffman、截断帧、帧穿插）、>64 字段拒绝
后连接继续、重复字段保序，以及**过滤前后正常请求字段完全一致**的
不变量校验。
