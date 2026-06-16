//! 最小 BTF 二进制 parser。
//!
//! 这是 caretta 用户态读取 vmlinux BTF 拿 `struct sock_common` 字段偏移的专用工具。
//!
//! ## 为什么不用 aya 自带的 Btf?
//!
//! aya 的 `aya::Btf` 把核心 API(`type_by_id`、`members()`、`string_at()` 等)全部留作
//! `pub(crate)`,外部 crate 拿不到 struct member 偏移。我们也不想把整个 aya-obj 内部
//! 通路暴露出来当依赖,所以这里只手写解 sock_common 一个 path,有限可控。
//!
//! ## 范围(只覆盖必要场景):
//!   - 读取 `/sys/kernel/btf/vmlinux`(linux 5.5+ + `CONFIG_DEBUG_INFO_BTF=y`,主流发行版默认开)
//!   - 解析 BTF 二进制,定位 `BTF_KIND_STRUCT` 类型记录
//!   - 列举 struct 的 members,对调用方关心的字段做 size 校验、返回 byte offset
//!
//! 不做 CO-RE 重定位、不处理 split BTF、不解析 line info——只够 caretta 用。
//!
//! ## BTF 二进制布局参考
//!
//! ```text
//! [btf_header (24 bytes)]
//! [type section]          // 一连串 btf_type record,每条头部 12 bytes
//! [string section]        // 字段名都是这里的偏移
//!
//! struct btf_header {
//!     __u16 magic;       // 0xeB9F (LE)
//!     __u8  version;     // 通常 1
//!     __u8  flags;
//!     __u32 hdr_len;     // 24
//!     __u32 type_off;    // type 段相对 hdr_len 的偏移
//!     __u32 type_len;    // type 段长度
//!     __u32 str_off;     // string 段相对 hdr_len 的偏移
//!     __u32 str_len;     // string 段长度
//! };
//!
//! struct btf_type {
//!     __u32 name_off;
//!     __u32 info;          // bits 0-15: vlen, bits 24-28: kind
//!     union { __u32 size; __u32 type; };
//! };
//!
//! struct btf_member {      // STRUCT/UNION 后面 vlen 个
//!     __u32 name_off;
//!     __u32 type;
//!     __u32 offset;        // 默认是 bit offset
//! };
//! ```

use anyhow::{Context as _, anyhow, bail};
use std::collections::HashMap;
use std::fs;

const BTF_MAGIC_LE: u16 = 0xeB9F;
const BTF_HEADER_SIZE: usize = 24;
const BTF_TYPE_HEADER_SIZE: usize = 12;
const BTF_MEMBER_SIZE: usize = 12;
const BTF_ENUM_RECORD_SIZE: usize = 8;
const BTF_ENUM64_RECORD_SIZE: usize = 12;
const BTF_PARAM_SIZE: usize = 8;
const BTF_VAR_SIZE: usize = 4;
const BTF_VAR_SECINFO_SIZE: usize = 12;
const BTF_DECL_TAG_SIZE: usize = 4;
const BTF_INT_SIZE: usize = 4;
const BTF_ARRAY_SIZE: usize = 12;

// BTF_KIND_* 编码,直接对照 include/uapi/linux/btf.h。
const KIND_VOID: u32 = 0;
const KIND_INT: u32 = 1;
const KIND_PTR: u32 = 2;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_FWD: u32 = 7;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
const KIND_FUNC: u32 = 12;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_FLOAT: u32 = 16;
const KIND_DECL_TAG: u32 = 17;
const KIND_TYPE_TAG: u32 = 18;
const KIND_ENUM64: u32 = 19;

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
    btf_path: &str,
    struct_name: &str,
    fields: &[(&str, u32)],
) -> anyhow::Result<HashMap<String, u32>> {
    let data = fs::read(btf_path)
        .with_context(|| format!("failed to read BTF blob: {btf_path}"))?;
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
            .ok_or_else(|| {
                anyhow!("field {field_name} not found in struct {struct_name}")
            })?;

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

        let actual_size = resolve_int_size(&by_id, m.type_id, 8).with_context(|| {
            format!("failed to resolve size of {struct_name}.{field_name}")
        })?;
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

#[derive(Debug)]
struct BtfHeader {
    hdr_len: u32,
    type_off: u32,
    type_len: u32,
    str_off: u32,
    str_len: u32,
}

fn parse_header(data: &[u8]) -> anyhow::Result<BtfHeader> {
    if data.len() < BTF_HEADER_SIZE {
        bail!("BTF blob too small for header");
    }
    let magic = u16::from_le_bytes([data[0], data[1]]);
    if magic != BTF_MAGIC_LE {
        bail!(
            "unexpected BTF magic 0x{magic:04x}; expected 0x{BTF_MAGIC_LE:04x} \
             (only little-endian BTF supported)"
        );
    }
    // version + flags 各 1 byte,我们不解读。
    let hdr_len = u32::from_le_bytes(data[4..8].try_into().unwrap());
    if hdr_len < BTF_HEADER_SIZE as u32 {
        bail!("BTF hdr_len {hdr_len} smaller than minimum {BTF_HEADER_SIZE}");
    }
    let type_off = u32::from_le_bytes(data[8..12].try_into().unwrap());
    let type_len = u32::from_le_bytes(data[12..16].try_into().unwrap());
    let str_off = u32::from_le_bytes(data[16..20].try_into().unwrap());
    let str_len = u32::from_le_bytes(data[20..24].try_into().unwrap());
    Ok(BtfHeader {
        hdr_len,
        type_off,
        type_len,
        str_off,
        str_len,
    })
}

#[derive(Clone, Debug)]
struct TypeInfo {
    /// type record 头之后 trailing 数据在 type 段里的起始 byte offset(用于解 STRUCT 的
    /// members)。
    body_offset: usize,
    name_off: u32,
    kind: u32,
    vlen: u32,
    /// 对 INT/ENUM/STRUCT/UNION/DATASEC: size,以 byte 计。
    /// 对 PTR/TYPEDEF/CONST/VOLATILE/RESTRICT/FUNC/FUNC_PROTO: type id。
    size_or_type: u32,
}

/// 读 cursor 处的 btf_type record 头与 trailing,返回 TypeInfo 与该 record 的总长度。
fn read_type_at(types: &[u8], cursor: usize) -> anyhow::Result<(TypeInfo, usize)> {
    if cursor + BTF_TYPE_HEADER_SIZE > types.len() {
        bail!("BTF type record header exceeds section");
    }
    let name_off = u32::from_le_bytes(types[cursor..cursor + 4].try_into().unwrap());
    let info = u32::from_le_bytes(types[cursor + 4..cursor + 8].try_into().unwrap());
    let size_or_type =
        u32::from_le_bytes(types[cursor + 8..cursor + 12].try_into().unwrap());

    let vlen = info & 0xffff;
    let kind = (info >> 24) & 0x1f;

    let body_offset = cursor + BTF_TYPE_HEADER_SIZE;
    let trailing = match kind {
        KIND_VOID => 0,
        KIND_INT => BTF_INT_SIZE,
        KIND_PTR
        | KIND_FWD
        | KIND_TYPEDEF
        | KIND_VOLATILE
        | KIND_CONST
        | KIND_RESTRICT
        | KIND_FUNC
        | KIND_FLOAT
        | KIND_TYPE_TAG => 0,
        KIND_ARRAY => BTF_ARRAY_SIZE,
        KIND_STRUCT | KIND_UNION => (vlen as usize) * BTF_MEMBER_SIZE,
        KIND_ENUM => (vlen as usize) * BTF_ENUM_RECORD_SIZE,
        KIND_ENUM64 => (vlen as usize) * BTF_ENUM64_RECORD_SIZE,
        KIND_FUNC_PROTO => (vlen as usize) * BTF_PARAM_SIZE,
        KIND_VAR => BTF_VAR_SIZE,
        KIND_DATASEC => (vlen as usize) * BTF_VAR_SECINFO_SIZE,
        KIND_DECL_TAG => BTF_DECL_TAG_SIZE,
        // 未知 kind:可能是 BTF 规范向前扩展。我们不知道 trailing 多长,无法续读后续
        // type record——只能 bail。这种情况通常意味着 caretta 编译时跟跑时内核 BTF 规
        // 范分叉,值得运维一眼看到。
        other => bail!("unsupported BTF kind {other}"),
    };

    if body_offset + trailing > types.len() {
        bail!("BTF type record body exceeds section");
    }

    Ok((
        TypeInfo {
            body_offset,
            name_off,
            kind,
            vlen,
            size_or_type,
        },
        BTF_TYPE_HEADER_SIZE + trailing,
    ))
}

#[derive(Debug)]
struct Member {
    name_off: u32,
    type_id: u32,
    bit_offset: u32,
}

fn parse_members(types: &[u8], info: &TypeInfo) -> anyhow::Result<Vec<Member>> {
    let mut out = Vec::with_capacity(info.vlen as usize);
    for i in 0..info.vlen as usize {
        let off = info.body_offset + i * BTF_MEMBER_SIZE;
        if off + BTF_MEMBER_SIZE > types.len() {
            bail!("BTF member record exceeds type section");
        }
        let name_off = u32::from_le_bytes(types[off..off + 4].try_into().unwrap());
        let type_id = u32::from_le_bytes(types[off + 4..off + 8].try_into().unwrap());
        // KFLAG=1 时 offset 高 8 位是 bitfield size,但 sock_common 我们关心的字段都不是
        // bitfield;为了防御万一,这里也只取低 24 位作为 bit offset。
        let raw_offset = u32::from_le_bytes(types[off + 8..off + 12].try_into().unwrap());
        let bit_offset = raw_offset & 0x00ff_ffff;
        out.push(Member {
            name_off,
            type_id,
            bit_offset,
        });
    }
    Ok(out)
}

/// 平展开后的 named field——name 是已解出的字符串,bit_offset 已经累加到外层 struct
/// 的坐标系。匿名 union/struct 自身不出现在结果里,只贡献它们带名的子字段。
#[derive(Debug)]
struct FlatMember {
    name: String,
    type_id: u32,
    bit_offset: u32,
}

/// 沿 anonymous struct/union 递归把所有 named 字段拍平。anonymous 成员的 bit_offset
/// 会作为 base 累加给它的子字段——这是 C 标准里 anonymous member 字段对外可见的
/// 那个语义。
///
/// `max_depth` 防御 BTF 异常;sock_common 实际嵌套深度不超过 3。
fn flatten_named_members(
    types: &[u8],
    strings: &[u8],
    by_id: &HashMap<u32, TypeInfo>,
    info: &TypeInfo,
    base_bit_offset: u32,
    max_depth: u32,
) -> anyhow::Result<Vec<FlatMember>> {
    if max_depth == 0 {
        bail!("BTF anonymous member nesting too deep");
    }
    let mut out = Vec::new();
    let raw = parse_members(types, info)?;
    for m in raw {
        let abs_off = base_bit_offset
            .checked_add(m.bit_offset)
            .ok_or_else(|| anyhow!("BTF member offset overflow"))?;
        let name = read_string(strings, m.name_off)?;
        if name.is_empty() {
            // 匿名 member——递归进它指向的 STRUCT/UNION,base 累加。
            let inner = by_id
                .get(&m.type_id)
                .ok_or_else(|| anyhow!("BTF anonymous member references unknown type id"))?;
            if inner.kind == KIND_STRUCT || inner.kind == KIND_UNION {
                let mut nested = flatten_named_members(
                    types,
                    strings,
                    by_id,
                    inner,
                    abs_off,
                    max_depth - 1,
                )?;
                out.append(&mut nested);
            }
            // 匿名但既不是 struct 也不是 union 的成员理论上不存在——直接跳过。
        } else {
            out.push(FlatMember {
                name: name.to_string(),
                type_id: m.type_id,
                bit_offset: abs_off,
            });
        }
    }
    Ok(out)
}

/// follow typedef / const / volatile / restrict 链路直到落到 INT / FLOAT,返回那一层
/// 的 size。`max_depth` 防御循环 typedef(BTF 实际上保证无环,但 defensive 一些)。
fn resolve_int_size(
    by_id: &HashMap<u32, TypeInfo>,
    mut type_id: u32,
    max_depth: u32,
) -> anyhow::Result<u32> {
    for _ in 0..max_depth {
        let ty = by_id
            .get(&type_id)
            .ok_or_else(|| anyhow!("dangling BTF type id {type_id}"))?;
        match ty.kind {
            KIND_INT | KIND_FLOAT | KIND_ENUM | KIND_ENUM64 | KIND_STRUCT | KIND_UNION => {
                return Ok(ty.size_or_type);
            }
            KIND_TYPEDEF | KIND_CONST | KIND_VOLATILE | KIND_RESTRICT | KIND_TYPE_TAG => {
                type_id = ty.size_or_type;
            }
            // 指针字段在 sock_common 里不是我们关心的字段,但若被传进来给个明确 size:
            // x86_64 / aarch64 都是 8。这里写死 8 满足 caretta 的目标平台,32-bit 平台
            // 永远不会跑到这条 caretta 路径。
            KIND_PTR => return Ok(8),
            other => bail!("cannot resolve size for BTF kind {other}"),
        }
    }
    bail!("BTF typedef chain too deep at type id {type_id}")
}

/// 读 string 段里 NUL 终止的字符串。BTF 字符串都是 ASCII,直接当 utf-8 解。
fn read_string(strings: &[u8], offset: u32) -> anyhow::Result<&str> {
    let off = offset as usize;
    if off >= strings.len() {
        bail!("BTF string offset {off} out of range");
    }
    let end = strings[off..]
        .iter()
        .position(|b| *b == 0)
        .ok_or_else(|| anyhow!("BTF string at offset {off} not nul-terminated"))?;
    std::str::from_utf8(&strings[off..off + end])
        .map_err(|e| anyhow!("BTF string at offset {off} not utf-8: {e}"))
}

#[cfg(test)]
mod tests {
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
        let off = parse_struct_field_offsets(
            &blob,
            "demo",
            &[("a", 4), ("b", 2)],
        )
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

        let off = parse_struct_field_offsets(&blob, "demo", &[("x", 4)])
            .expect("demo.x should resolve");
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

        let off = parse_struct_field_offsets(
            &blob,
            "outer",
            &[("skc_daddr", 4), ("skc_rcv_saddr", 4)],
        )
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
            &path,
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
}
