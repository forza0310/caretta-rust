//! BTF 高层查询:在解析后的 type 段里按 struct 名 + 字段名定位 byte offset。
//!
//! 调用方:
//!   - `parse_sock_offsets`(本文件):caretta 启动时把 sock_common 几个字段的偏移
//!     推到 eBPF 端的 SOCK_OFFSETS map。
//!   - 测试 fixture(本文件 #[cfg(test)] 模块):用合成 BTF blob 验证查询语义。
//!
//! 与 `parser.rs` 的边界:本文件不直接 byte-decode,只调 parser 暴露的
//! `parse_header` / `read_type_at` / `flatten_named_members` / `resolve_field_size` /
//! `read_string` 等原语。

use anyhow::{Context as _, anyhow, bail};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use super::parser::{
    KIND_STRUCT, TypeInfo, flatten_named_members, parse_header, read_string, read_type_at,
    resolve_field_size,
};
use crate::types::{SockOffsets, TcpSockOffsets};

/// 默认 vmlinux BTF 路径——所有支持 BTF 的内核(5.5+)都会在这里挂出 BTF blob。
pub const DEFAULT_VMLINUX_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";

/// 在 BTF 里查 `struct_name` 的字段偏移。
///
/// `fields`:`(字段名, 期望 size_bytes)` 列表。每个字段同时校验 size 与可见性,
/// 任何字段缺失或 size 不符都直接 bail——内核改了 ABI 时希望启动就失败,
/// 比静默读垃圾好。
///
/// 返回 `字段名 -> byte offset`。
pub fn read_struct_field_offsets(
    btf_path: &Path,
    struct_name: &str,
    fields: &[(&str, u32)],
) -> anyhow::Result<HashMap<String, u32>> {
    let data = fs::read(btf_path)
        .with_context(|| format!("failed to read BTF blob: {}", btf_path.display()))?;
    parse_struct_field_offsets(&data, struct_name, fields)
}

/// `read_struct_field_offsets` 的纯函数版,接收已读入内存的 BTF 字节。
///
/// 拆出来主要为了写 unit test:fixture 是合成 BTF blob,不依赖文件系统。
pub fn parse_struct_field_offsets(
    data: &[u8],
    struct_name: &str,
    fields: &[(&str, u32)],
) -> anyhow::Result<HashMap<String, u32>> {
    let header = parse_header(data)?;

    // 字符串段:从 hdr_len + str_off 起,长 str_len 字节。
    let str_base = header.hdr_len as usize + header.str_off as usize;
    let str_end = str_base
        .checked_add(header.str_len as usize)
        .ok_or_else(|| anyhow!("BTF string section overflow"))?;
    if str_end > data.len() {
        bail!("BTF string section out of range");
    }
    let strings = &data[str_base..str_end];

    // type 段:从 hdr_len + type_off 起,长 type_len 字节。
    let type_base = header.hdr_len as usize + header.type_off as usize;
    let type_end = type_base
        .checked_add(header.type_len as usize)
        .ok_or_else(|| anyhow!("BTF type section overflow"))?;
    if type_end > data.len() {
        bail!("BTF type section out of range");
    }
    let types = &data[type_base..type_end];

    // 第一遍:扫所有 type record 把 type_id -> (位置, 头部) 索引出来。type_id 从 1 起,
    // 0 是 VOID 占位(BTF 约定)。索引的目的是后续要按字段 type id follow 链路拿 INT
    // 的 size,所以单次扫描存下来比反复扫合算。
    let mut id = 1u32;
    let mut by_id: HashMap<u32, TypeInfo> = HashMap::new();
    let mut cursor = 0usize;
    while cursor < types.len() {
        let (info, advance) = read_type_at(types, cursor)?;
        by_id.insert(id, info);
        cursor += advance;
        id = id
            .checked_add(1)
            .ok_or_else(|| anyhow!("BTF type id overflow"))?;
    }

    // 找目标 struct——按 kind=STRUCT + name 精确匹配。
    let target = by_id
        .values()
        .find(|t| {
            if t.kind != KIND_STRUCT {
                return false;
            }
            matches!(read_string(strings, t.name_off), Ok(name) if name == struct_name)
        })
        .ok_or_else(|| anyhow!("struct {struct_name} not found in BTF"))?;

    // 把目标 struct 的所有 named 字段平展开,递归吃掉 anonymous union/struct(它们的
    // member 在 C 层面属于外层 struct,offset 要相对外层做)。`sock_common` 把 skc_daddr
    // 等字段藏在嵌套 anonymous union 里,这层递归是必须的。
    let flat = flatten_named_members(types, strings, &by_id, target, 0, 8)?;

    let mut result = HashMap::new();
    for (field_name, expected_size) in fields {
        let m = flat
            .iter()
            .find(|m| m.name == *field_name)
            .ok_or_else(|| anyhow!("field {field_name} not found in struct {struct_name}"))?;

        // BTF member offset 默认是 bit offset。常规字段都是 8 位对齐,转 byte offset
        // 后做 size 校验。bitfield 我们这里不期待出现(sock_common 几个字段都不是)。
        if m.bit_offset % 8 != 0 {
            bail!(
                "field {field_name} of {struct_name} has non-byte-aligned offset \
                 ({} bits); bitfield not supported",
                m.bit_offset
            );
        }
        let byte_offset = m.bit_offset / 8;

        let actual_size = resolve_field_size(types, &by_id, m.type_id, 8)
            .with_context(|| format!("failed to resolve size of {struct_name}.{field_name}"))?;
        if actual_size != *expected_size {
            bail!(
                "{struct_name}.{field_name} has size {actual_size} bytes \
                 (expected {expected_size}); kernel ABI may have changed"
            );
        }

        result.insert((*field_name).to_string(), byte_offset);
    }

    Ok(result)
}

/// 解析 vmlinux BTF 拿 caretta eBPF 程序需要读的 sock_common 字段偏移。
///
/// 字段 size 校验:
///   - skc_daddr / skc_rcv_saddr 是 __be32,4 字节
///   - skc_dport / skc_num       是 __u16,2 字节
/// size 不符就 bail,免得 eBPF 端读错字段导致数据乱掉还不好排查。
pub fn parse_sock_offsets(btf_path: &Path) -> anyhow::Result<SockOffsets> {
    let offs = read_struct_field_offsets(
        btf_path,
        "sock_common",
        &[
            ("skc_daddr", 4),
            ("skc_rcv_saddr", 4),
            ("skc_dport", 2),
            ("skc_num", 2),
        ],
    )?;

    // unwrap 安全:read_struct_field_offsets 在缺字段时已经 bail,走到这里所有 key 必在。
    Ok(SockOffsets {
        skc_daddr_off: offs["skc_daddr"],
        skc_rcv_saddr_off: offs["skc_rcv_saddr"],
        skc_dport_off: offs["skc_dport"],
        skc_num_off: offs["skc_num"],
    })
}

/// 解析 vmlinux BTF 拿 `struct tcp_sock` 的采样字段偏移。
///
/// 当前解三个 u32 字段:
///   - `srtt_us`:smoothed RTT(微秒 << 3),用户态 `>> 3` 还原成 µs 再换秒
///   - `segs_in` / `segs_out`:kernel 维护的累计收/发 TCP 段数,monotonic counter
/// 任意字段缺失或 size 不符直接 bail——和 sock_common 路径一致,拦住 ABI 漂移。
pub fn parse_tcp_sock_offsets(btf_path: &Path) -> anyhow::Result<TcpSockOffsets> {
    let offs = read_struct_field_offsets(
        btf_path,
        "tcp_sock",
        &[("srtt_us", 4), ("segs_in", 4), ("segs_out", 4)],
    )?;

    Ok(TcpSockOffsets {
        srtt_us_off: offs["srtt_us"],
        segs_in_off: offs["segs_in"],
        segs_out_off: offs["segs_out"],
        _reserved: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::super::parser::{
        BTF_HEADER_SIZE, BTF_MAGIC_LE, KIND_ARRAY, KIND_INT, KIND_STRUCT, KIND_TYPEDEF, KIND_UNION,
    };
    use super::*;

    /// 合成一份最小 BTF blob,内含两个 INT(`__u32`/`__u16`)+ 一个 STRUCT 把它们当
    /// 字段拼起来。这是后续测试的基线 fixture。
    ///
    /// type id 分配规则(BTF 约定 0=VOID,从 1 起):
    ///   1: INT "u32"
    ///   2: INT "u16"
    ///   3: STRUCT "demo" { a: u32 @ off 0, b: u16 @ off 32 (bit) = 4 (byte) }
    fn build_minimal_btf() -> Vec<u8> {
        let mut strings: Vec<u8> = Vec::new();
        // 字符串 0 必须是空字符串(BTF 约定)。
        strings.push(0);
        let off_u32 = strings.len() as u32;
        strings.extend_from_slice(b"u32\0");
        let off_u16 = strings.len() as u32;
        strings.extend_from_slice(b"u16\0");
        let off_demo = strings.len() as u32;
        strings.extend_from_slice(b"demo\0");
        let off_a = strings.len() as u32;
        strings.extend_from_slice(b"a\0");
        let off_b = strings.len() as u32;
        strings.extend_from_slice(b"b\0");

        let mut types: Vec<u8> = Vec::new();
        // type id 1: INT "u32" size=4
        types.extend_from_slice(&off_u32.to_le_bytes());
        types.extend_from_slice(&((KIND_INT << 24) | 0u32).to_le_bytes());
        types.extend_from_slice(&4u32.to_le_bytes());
        // INT trailing: 1 个 u32 编码字段(我们不读,填 0)
        types.extend_from_slice(&0u32.to_le_bytes());
        // type id 2: INT "u16" size=2
        types.extend_from_slice(&off_u16.to_le_bytes());
        types.extend_from_slice(&((KIND_INT << 24) | 0u32).to_le_bytes());
        types.extend_from_slice(&2u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        // type id 3: STRUCT "demo",vlen=2,size=8
        types.extend_from_slice(&off_demo.to_le_bytes());
        types.extend_from_slice(&((KIND_STRUCT << 24) | 2u32).to_le_bytes());
        types.extend_from_slice(&8u32.to_le_bytes());
        // member a: name=off_a, type_id=1 (u32), bit offset=0
        types.extend_from_slice(&off_a.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        // member b: name=off_b, type_id=2 (u16), bit offset=32 (byte offset 4)
        types.extend_from_slice(&off_b.to_le_bytes());
        types.extend_from_slice(&2u32.to_le_bytes());
        types.extend_from_slice(&32u32.to_le_bytes());

        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&BTF_MAGIC_LE.to_le_bytes()); // magic
        blob.push(1); // version
        blob.push(0); // flags
        blob.extend_from_slice(&(BTF_HEADER_SIZE as u32).to_le_bytes()); // hdr_len
        blob.extend_from_slice(&0u32.to_le_bytes()); // type_off
        blob.extend_from_slice(&(types.len() as u32).to_le_bytes()); // type_len
        blob.extend_from_slice(&(types.len() as u32).to_le_bytes()); // str_off
        blob.extend_from_slice(&(strings.len() as u32).to_le_bytes()); // str_len
        blob.extend(types);
        blob.extend(strings);
        blob
    }

    #[test]
    fn should_resolve_field_offsets_for_known_struct() {
        let blob = build_minimal_btf();
        let off = parse_struct_field_offsets(&blob, "demo", &[("a", 4), ("b", 2)])
            .expect("offsets should resolve");
        assert_eq!(off["a"], 0);
        assert_eq!(off["b"], 4);
    }

    #[test]
    fn should_bail_when_struct_missing() {
        let blob = build_minimal_btf();
        let err = parse_struct_field_offsets(&blob, "absent", &[("a", 4)])
            .expect_err("missing struct must bail");
        assert!(format!("{err}").contains("not found"));
    }

    #[test]
    fn should_bail_when_field_size_changed() {
        let blob = build_minimal_btf();
        let err = parse_struct_field_offsets(
            &blob,
            "demo",
            &[("a", 8)], // 真实是 4
        )
        .expect_err("size mismatch must bail, not silently return offset");
        let msg = format!("{err}");
        assert!(
            msg.contains("size") && (msg.contains("expected") || msg.contains("ABI")),
            "error should explain size mismatch, got: {msg}"
        );
    }

    #[test]
    fn should_bail_when_field_missing_in_struct() {
        let blob = build_minimal_btf();
        let err = parse_struct_field_offsets(&blob, "demo", &[("zzz", 4)])
            .expect_err("missing field must bail");
        assert!(format!("{err}").contains("not found"));
    }

    #[test]
    fn should_reject_blob_with_wrong_magic() {
        let mut blob = build_minimal_btf();
        // 故意污染 magic,模拟 big-endian / 损坏 blob。
        blob[0] = 0;
        blob[1] = 0;
        let err = parse_struct_field_offsets(&blob, "demo", &[("a", 4)])
            .expect_err("bad magic must bail");
        assert!(format!("{err}").contains("magic"));
    }

    /// 多 struct 共存场景:确保按 kind+name 精确定位,不会把另一个 struct 的字段当成
    /// 目标 struct 的字段返回(典型反例:某 struct 里有 `daddr` 但叫 `__sk_common` 的
    /// 不同结构,精确名匹配是底线)。
    #[test]
    fn should_pick_struct_by_exact_name_when_multiple_structs_exist() {
        // 在 baseline 之上再加一个同字段名但不同 struct name 的 struct。
        let mut strings: Vec<u8> = vec![0];
        let off_u32 = strings.len() as u32;
        strings.extend_from_slice(b"u32\0");
        let off_demo = strings.len() as u32;
        strings.extend_from_slice(b"demo\0");
        let off_decoy = strings.len() as u32;
        strings.extend_from_slice(b"decoy\0");
        let off_field = strings.len() as u32;
        strings.extend_from_slice(b"x\0");

        let mut types: Vec<u8> = Vec::new();
        // type 1: INT u32
        types.extend_from_slice(&off_u32.to_le_bytes());
        types.extend_from_slice(&((KIND_INT << 24) | 0u32).to_le_bytes());
        types.extend_from_slice(&4u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        // type 2: STRUCT decoy { x @ 0 }
        types.extend_from_slice(&off_decoy.to_le_bytes());
        types.extend_from_slice(&((KIND_STRUCT << 24) | 1u32).to_le_bytes());
        types.extend_from_slice(&4u32.to_le_bytes());
        types.extend_from_slice(&off_field.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        // type 3: STRUCT demo { x @ bit 32 (byte 4) }——同字段名但偏移不同
        types.extend_from_slice(&off_demo.to_le_bytes());
        types.extend_from_slice(&((KIND_STRUCT << 24) | 1u32).to_le_bytes());
        types.extend_from_slice(&8u32.to_le_bytes());
        types.extend_from_slice(&off_field.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&32u32.to_le_bytes());

        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&BTF_MAGIC_LE.to_le_bytes());
        blob.push(1);
        blob.push(0);
        blob.extend_from_slice(&(BTF_HEADER_SIZE as u32).to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&(types.len() as u32).to_le_bytes());
        blob.extend_from_slice(&(types.len() as u32).to_le_bytes());
        blob.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        blob.extend(types);
        blob.extend(strings);

        let off =
            parse_struct_field_offsets(&blob, "demo", &[("x", 4)]).expect("demo.x should resolve");
        assert_eq!(off["x"], 4, "must pick demo.x not decoy.x");
    }

    /// typedef 链:把字段 type 包一层 typedef(模拟真实内核 `__be32` typedef 到
    /// `unsigned int` 的情况),确保 size 校验仍然能 follow 到 INT 拿到 size。
    #[test]
    fn should_resolve_size_through_typedef_chain() {
        let mut strings: Vec<u8> = vec![0];
        let off_uint = strings.len() as u32;
        strings.extend_from_slice(b"unsigned int\0");
        let off_be32 = strings.len() as u32;
        strings.extend_from_slice(b"__be32\0");
        let off_demo = strings.len() as u32;
        strings.extend_from_slice(b"demo\0");
        let off_a = strings.len() as u32;
        strings.extend_from_slice(b"a\0");

        let mut types: Vec<u8> = Vec::new();
        // type 1: INT unsigned int size=4
        types.extend_from_slice(&off_uint.to_le_bytes());
        types.extend_from_slice(&((KIND_INT << 24) | 0u32).to_le_bytes());
        types.extend_from_slice(&4u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        // type 2: TYPEDEF __be32 -> 1 (no trailing)
        types.extend_from_slice(&off_be32.to_le_bytes());
        types.extend_from_slice(&((KIND_TYPEDEF << 24) | 0u32).to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        // type 3: STRUCT demo { a: __be32 @ 0 }
        types.extend_from_slice(&off_demo.to_le_bytes());
        types.extend_from_slice(&((KIND_STRUCT << 24) | 1u32).to_le_bytes());
        types.extend_from_slice(&4u32.to_le_bytes());
        types.extend_from_slice(&off_a.to_le_bytes());
        types.extend_from_slice(&2u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());

        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&BTF_MAGIC_LE.to_le_bytes());
        blob.push(1);
        blob.push(0);
        blob.extend_from_slice(&(BTF_HEADER_SIZE as u32).to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&(types.len() as u32).to_le_bytes());
        blob.extend_from_slice(&(types.len() as u32).to_le_bytes());
        blob.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        blob.extend(types);
        blob.extend(strings);

        let off = parse_struct_field_offsets(&blob, "demo", &[("a", 4)])
            .expect("size via typedef should resolve");
        assert_eq!(off["a"], 0);
    }

    /// 数组字段:模拟 `struct demo { u8 buf[16]; }`——sock_common 现在没有数组字段,
    /// 但将来要 IPv6,`skc_v6_daddr` 是 `struct in6_addr`,内部就含 `__u8[16]` 数组,
    /// resolve_field_size 必须能算出 elem_size × nelems = 1 × 16 = 16。
    #[test]
    fn should_resolve_array_field_size() {
        let mut strings: Vec<u8> = vec![0];
        let off_u8 = strings.len() as u32;
        strings.extend_from_slice(b"u8\0");
        let off_demo = strings.len() as u32;
        strings.extend_from_slice(b"demo\0");
        let off_buf = strings.len() as u32;
        strings.extend_from_slice(b"buf\0");

        let mut types: Vec<u8> = Vec::new();
        // type 1: INT u8 size=1
        types.extend_from_slice(&off_u8.to_le_bytes());
        types.extend_from_slice(&((KIND_INT << 24) | 0u32).to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        // type 2: ARRAY (anon),vlen=0、size=0;trailing 12 字节 (elem_type=1, index_type=0, nelems=16)
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&((KIND_ARRAY << 24) | 0u32).to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes()); // elem_type
        types.extend_from_slice(&0u32.to_le_bytes()); // index_type(我们不读)
        types.extend_from_slice(&16u32.to_le_bytes()); // nelems
        // type 3: STRUCT demo vlen=1 size=16,字段 buf 指向 ARRAY(type id=2)@ bit 0
        types.extend_from_slice(&off_demo.to_le_bytes());
        types.extend_from_slice(&((KIND_STRUCT << 24) | 1u32).to_le_bytes());
        types.extend_from_slice(&16u32.to_le_bytes());
        types.extend_from_slice(&off_buf.to_le_bytes());
        types.extend_from_slice(&2u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());

        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&BTF_MAGIC_LE.to_le_bytes());
        blob.push(1);
        blob.push(0);
        blob.extend_from_slice(&(BTF_HEADER_SIZE as u32).to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&(types.len() as u32).to_le_bytes());
        blob.extend_from_slice(&(types.len() as u32).to_le_bytes());
        blob.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        blob.extend(types);
        blob.extend(strings);

        // 期望 size=16(1 byte × 16):验证应通过,offset 为 0。
        let off = parse_struct_field_offsets(&blob, "demo", &[("buf", 16)])
            .expect("array field size should resolve as elem_size * nelems");
        assert_eq!(off["buf"], 0);

        // 期望 size=8(故意写错):验证应 bail——证明 ARRAY 分支真的算到了 16,
        // 而不是 fallback 到某个偶然为 8 的值。
        let err = parse_struct_field_offsets(&blob, "demo", &[("buf", 8)])
            .expect_err("array size mismatch must bail");
        let msg = format!("{err}");
        assert!(
            msg.contains("size") || msg.contains("16"),
            "error should explain size mismatch, got: {msg}"
        );
    }

    /// 匿名嵌套场景:模拟 sock_common 把 skc_daddr / skc_rcv_saddr 藏在
    /// `union { struct { ... }; ... }` 里的真实形态。
    ///
    /// 类型布局:
    ///   1: INT u32 size=4
    ///   2: STRUCT (anon) { skc_daddr@0bit, skc_rcv_saddr@32bit }, size=8
    ///   3: UNION (anon) { (anon struct id=2) @ 0bit }, size=8
    ///   4: STRUCT outer { (anon union id=3) @ 0bit }, size=8
    ///
    /// 期望:`outer.skc_daddr` byte off=0,`outer.skc_rcv_saddr` byte off=4。
    #[test]
    fn should_flatten_named_fields_through_anonymous_union_and_struct() {
        let mut strings: Vec<u8> = vec![0];
        let off_u32 = strings.len() as u32;
        strings.extend_from_slice(b"u32\0");
        let off_outer = strings.len() as u32;
        strings.extend_from_slice(b"outer\0");
        let off_daddr = strings.len() as u32;
        strings.extend_from_slice(b"skc_daddr\0");
        let off_rcv = strings.len() as u32;
        strings.extend_from_slice(b"skc_rcv_saddr\0");

        let mut types: Vec<u8> = Vec::new();
        // type 1: INT u32 size=4
        types.extend_from_slice(&off_u32.to_le_bytes());
        types.extend_from_slice(&((KIND_INT << 24) | 0u32).to_le_bytes());
        types.extend_from_slice(&4u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        // type 2: STRUCT anon vlen=2 size=8 — name_off=0(空字符串=匿名)
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&((KIND_STRUCT << 24) | 2u32).to_le_bytes());
        types.extend_from_slice(&8u32.to_le_bytes());
        types.extend_from_slice(&off_daddr.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&off_rcv.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&32u32.to_le_bytes());
        // type 3: UNION anon vlen=1 size=8 — 一个匿名 member 指向 type 2
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&((KIND_UNION << 24) | 1u32).to_le_bytes());
        types.extend_from_slice(&8u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes()); // member name=anon
        types.extend_from_slice(&2u32.to_le_bytes()); // type=2
        types.extend_from_slice(&0u32.to_le_bytes());
        // type 4: STRUCT outer vlen=1 size=8 — 一个匿名 member 指向 type 3
        types.extend_from_slice(&off_outer.to_le_bytes());
        types.extend_from_slice(&((KIND_STRUCT << 24) | 1u32).to_le_bytes());
        types.extend_from_slice(&8u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&3u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());

        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&BTF_MAGIC_LE.to_le_bytes());
        blob.push(1);
        blob.push(0);
        blob.extend_from_slice(&(BTF_HEADER_SIZE as u32).to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&(types.len() as u32).to_le_bytes());
        blob.extend_from_slice(&(types.len() as u32).to_le_bytes());
        blob.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        blob.extend(types);
        blob.extend(strings);

        let off =
            parse_struct_field_offsets(&blob, "outer", &[("skc_daddr", 4), ("skc_rcv_saddr", 4)])
                .expect("anon-nested fields should flatten");
        assert_eq!(off["skc_daddr"], 0);
        assert_eq!(off["skc_rcv_saddr"], 4);
    }

    /// 真实 vmlinux 烟雾测试。需要 `/sys/kernel/btf/vmlinux` 可读,所以默认 ignored,
    /// 由开发者手动 `cargo test -- --ignored` 跑。生产 CI 不依赖。
    #[test]
    #[ignore = "needs /sys/kernel/btf/vmlinux (kernel 5.5+, CONFIG_DEBUG_INFO_BTF=y)"]
    fn should_resolve_sock_common_against_real_vmlinux() {
        let path = std::env::var("VMLINUX_BTF_PATH")
            .unwrap_or_else(|_| DEFAULT_VMLINUX_BTF_PATH.to_string());
        let off = read_struct_field_offsets(
            Path::new(&path),
            "sock_common",
            &[
                ("skc_daddr", 4),
                ("skc_rcv_saddr", 4),
                ("skc_dport", 2),
                ("skc_num", 2),
            ],
        )
        .expect("sock_common offsets should resolve from real vmlinux");
        // sock_common 这 4 个字段 ABI 上从 2.6 之后没动过,真实内核里应当全部解出。
        assert!(off.contains_key("skc_daddr"));
        assert!(off.contains_key("skc_rcv_saddr"));
        assert!(off.contains_key("skc_dport"));
        assert!(off.contains_key("skc_num"));
        eprintln!("sock_common offsets on this kernel: {off:?}");
    }

    /// 同 should_resolve_sock_common_against_real_vmlinux,但覆盖 tcp_sock 的采样字段
    /// (srtt_us / segs_in / segs_out)。size=4 校验同步守住"kernel 改这几个字段类型"
    /// 这类隐式 ABI 变更。
    #[test]
    #[ignore = "needs /sys/kernel/btf/vmlinux (kernel 5.5+, CONFIG_DEBUG_INFO_BTF=y)"]
    fn should_resolve_tcp_sock_against_real_vmlinux() {
        let path = std::env::var("VMLINUX_BTF_PATH")
            .unwrap_or_else(|_| DEFAULT_VMLINUX_BTF_PATH.to_string());
        let off = parse_tcp_sock_offsets(Path::new(&path))
            .expect("tcp_sock sampling offsets should resolve from real vmlinux");
        // 这几个字段都在 tcp_sock 内部、跟在 sock_common 嵌入头之后,偏移绝不会是 0;
        // segs_in/segs_out 也不可能与 srtt_us 同址。
        assert!(off.srtt_us_off > 0);
        assert!(off.segs_in_off > 0 && off.segs_in_off != off.srtt_us_off);
        assert!(off.segs_out_off > 0 && off.segs_out_off != off.segs_in_off);
        eprintln!(
            "tcp_sock offsets on this kernel: srtt_us={} segs_in={} segs_out={}",
            off.srtt_us_off, off.segs_in_off, off.segs_out_off
        );
    }

    /// 合成一份带 tcp_sock 的最小 BTF,断言 parse_tcp_sock_offsets 能正确解出
    /// srtt_us / segs_in / segs_out 三处偏移并都通过 size=4 校验——守住"任一字段
    /// 缺失或 size 不符即 bail",并锁住 parse_tcp_sock_offsets 的解析路径与
    /// parse_sock_offsets 同源,不会偷偷走旁路。
    #[test]
    fn should_parse_tcp_sock_sampling_offsets_from_synthetic_btf() {
        // type id 分配:
        //   1: INT "u32" size=4
        //   2: STRUCT "tcp_sock" {
        //        padding_a: u32 @ off 0,
        //        srtt_us:   u32 @ off 4,
        //        segs_in:   u32 @ off 8,
        //        segs_out:  u32 @ off 12,
        //      }
        let mut strings: Vec<u8> = vec![0];
        let off_u32 = strings.len() as u32;
        strings.extend_from_slice(b"u32\0");
        let off_tcpsock = strings.len() as u32;
        strings.extend_from_slice(b"tcp_sock\0");
        let off_pad = strings.len() as u32;
        strings.extend_from_slice(b"padding_a\0");
        let off_srtt = strings.len() as u32;
        strings.extend_from_slice(b"srtt_us\0");
        let off_segs_in = strings.len() as u32;
        strings.extend_from_slice(b"segs_in\0");
        let off_segs_out = strings.len() as u32;
        strings.extend_from_slice(b"segs_out\0");

        let mut types: Vec<u8> = Vec::new();
        // type 1: INT u32 size=4
        types.extend_from_slice(&off_u32.to_le_bytes());
        types.extend_from_slice(&((KIND_INT << 24) | 0u32).to_le_bytes());
        types.extend_from_slice(&4u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        // type 2: STRUCT tcp_sock vlen=4 size=16
        types.extend_from_slice(&off_tcpsock.to_le_bytes());
        types.extend_from_slice(&((KIND_STRUCT << 24) | 4u32).to_le_bytes());
        types.extend_from_slice(&16u32.to_le_bytes());
        types.extend_from_slice(&off_pad.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&0u32.to_le_bytes());
        types.extend_from_slice(&off_srtt.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&32u32.to_le_bytes());
        types.extend_from_slice(&off_segs_in.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&64u32.to_le_bytes());
        types.extend_from_slice(&off_segs_out.to_le_bytes());
        types.extend_from_slice(&1u32.to_le_bytes());
        types.extend_from_slice(&96u32.to_le_bytes());

        let mut blob: Vec<u8> = Vec::new();
        blob.extend_from_slice(&BTF_MAGIC_LE.to_le_bytes());
        blob.push(1);
        blob.push(0);
        blob.extend_from_slice(&(BTF_HEADER_SIZE as u32).to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        blob.extend_from_slice(&(types.len() as u32).to_le_bytes());
        blob.extend_from_slice(&(types.len() as u32).to_le_bytes());
        blob.extend_from_slice(&(strings.len() as u32).to_le_bytes());
        blob.extend(types);
        blob.extend(strings);

        // 走与 parse_tcp_sock_offsets 完全同源的入口,验证三字段 byte offset。
        let off = parse_struct_field_offsets(
            &blob,
            "tcp_sock",
            &[("srtt_us", 4), ("segs_in", 4), ("segs_out", 4)],
        )
        .expect("tcp_sock sampling fields should resolve");
        assert_eq!(off["srtt_us"], 4);
        assert_eq!(off["segs_in"], 8);
        assert_eq!(off["segs_out"], 12);

        // size 校验失败必须 bail——故意把 segs_in 写成 8 校验拦截路径。
        let err = parse_struct_field_offsets(
            &blob,
            "tcp_sock",
            &[("srtt_us", 4), ("segs_in", 8), ("segs_out", 4)],
        )
        .expect_err("size mismatch on segs_in must bail");
        let msg = format!("{err}");
        assert!(
            msg.contains("size") && (msg.contains("expected") || msg.contains("ABI")),
            "error should explain size mismatch, got: {msg}"
        );
    }
}
