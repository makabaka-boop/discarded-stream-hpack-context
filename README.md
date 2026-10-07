# HTTP/2 HPACK 捕获审计器

这个 Python 命令行工具读取**一个捕获方向**的真实 HTTP/2 帧字节（无 TLS），重组
`HEADERS`/`CONTINUATION`，逐项解码 HPACK，并可把指定流的完整头区块从交付结果中
过滤掉。被过滤区块仍会完整执行压缩指令，包括动态表插入、容量更新和逐项淘汰，因此
后续正常请求对动态表的引用不会因抓包过滤而失配。

## 范围与约束

- 固定模拟协商的 `SETTINGS_HEADER_TABLE_SIZE = 256` 字节。
- 输入只包含 HTTP/2 帧，不处理 TLS、连接前言、服务端推送或流量控制。
- 总输入不超过 16 KiB。
- 自行重组 `HEADERS` + `CONTINUATION`。
- 自行逐条解析 HPACK indexed/literal/dynamic table size update 指令，并维护动态表。
- 只把 Huffman **字符串原语**委托给成熟的 `hpack` 组件（`decode_huffman`）；不会把
  整个头区块传给现成 HPACK 解码器。
- 重复头字段按原顺序保留，不折叠。
- 单列表超过 64 个字段时只拒绝该列表输出；仍继续消费整个区块并推进动态表。
- 非法索引、非法容量更新、坏 Huffman、未结束头区块中插入其他帧等均为连接错误，立即
  停止，不猜测后续状态。

## 本地运行

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python -m h2_audit.cli samples/filtered-shared-hpack.bin --discard-stream 3
```

可重复或逗号分隔多个流：

```bash
python -m h2_audit.cli capture.bin --discard-stream 3,7 --discard-stream 11 -o report.json
```

报告为 JSON。`name_b64`/`value_b64` 是精确字节；`name`/`value` 只是 UTF-8 可读视图。

## Compose 容器

构建：

```bash
docker compose build auditor
docker compose run --rm auditor
```

默认挂载 `samples/filtered-shared-hpack.bin` 并丢弃流 3。处理其它捕获文件：

```bash
CAPTURE_PATH=/absolute/path/capture.bin DISCARD_STREAMS=3,7 \
  docker compose run --rm auditor
```

也可显式覆盖命令并挂载任意文件：

```bash
docker compose run --rm \
  -v "$PWD/capture.bin:/input/capture.bin:ro" \
  auditor /input/capture.bin --discard-stream 3
```

## 测试

测试使用标准 `hpack.Encoder` 生成动态表插入、淘汰、Huffman 和分片样例：

```bash
pip install -r requirements.txt
python -m unittest -v test_auditor.py
```

关键测试包含：

1. 丢弃区块插入自定义条目，后续正常流使用动态索引；比较过滤前后正常流字段相同。
2. 标准编码器在 256 字节表中生成淘汰，解码器逐项跟随。
3. `HEADERS`/`CONTINUATION` 任意字节位置分片重组。
4. 头区块未 `END_HEADERS` 前插入其他帧，连接错误。
5. 坏 Huffman、非法索引、超过 256 的容量更新均停止整个连接。
6. 65 个字段只拒绝该列表，但动态表继续推进。
7. 重复字段不折叠。

## 代码结构

- `h2_audit/frame_reader.py`：HTTP/2 帧读取、HEADERS/CONTINUATION 重组、报告输出。
- `h2_audit/hpack_decoder.py`：HPACK 整数、字符串、索引、字面量、容量更新、插入/淘汰。
- `h2_audit/static_table.py`：RFC 7541 61 项静态表。
- `tools/generate_samples.py`：用标准 HPACK 编码器生成手工演示捕获。
- `test_auditor.py`：状态机和帧级测试。
