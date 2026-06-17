//! BTF 二进制层解析:头部 / type record / member / 字符串段。
//!
//! 这一层只懂 BTF 字节布局,不知道"我们要拿哪个 struct 的哪个字段"——那个语义在
//! `lookup.rs` 里。拆出来主要是让 `lookup.rs` 的高层逻辑(找 struct、平展 anonymous
//! 嵌套、跟 typedef、字段 size 校验)读起来不被字节解码细节淹没。
//!
//! 所有 `pub(super)` 项都给 `btf` 模块内部用——`lookup.rs` 与它的测试 fixture 都靠
//! 这里的常量+解析函数。

use anyhow::{anyhow, bail};
use std::collections::HashMap;

pub(super) const BTF_MAGIC_LE: u16 = 0xeB9F;
pub(super) const BTF_HEADER_SIZE: usize = 24;
const BTF_TYPE_HEADER_SIZE: usize = 12;
pub(super) const BTF_MEMBER_SIZE: usize = 12;
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
pub(super) const KIND_INT: u32 = 1;
const KIND_PTR: u32 = 2;
const KIND_ARRAY: u32 = 3;
pub(super) const KIND_STRUCT: u32 = 4;
pub(super) const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_FWD: u32 = 7;
pub(super) const KIND_TYPEDEF: u32 = 8;
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

#[derive(Debug)]
pub(super) struct BtfHeader {
    pub(super) hdr_len: u32,
    pub(super) type_off: u32,
    pub(super) type_len: u32,
    pub(super) str_off: u32,
    pub(super) str_len: u32,
}

pub(super) fn parse_header(data: &[u8]) -> anyhow::Result<BtfHeader> {
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
pub(super) struct TypeInfo {
    /// type record 头之后 trailing 数据在 type 段里的起始 byte offset(用于解 STRUCT 的
    /// members)。
    pub(super) body_offset: usize,
    pub(super) name_off: u32,
    pub(super) kind: u32,
    pub(super) vlen: u32,
    /// 对 INT/ENUM/STRUCT/UNION/DATASEC: size,以 byte 计。
    /// 对 PTR/TYPEDEF/CONST/VOLATILE/RESTRICT/FUNC/FUNC_PROTO: type id。
    pub(super) size_or_type: u32,
}

/// 读 cursor 处的 btf_type record 头与 trailing,返回 TypeInfo 与该 record 的总长度。
pub(super) fn read_type_at(types: &[u8], cursor: usize) -> anyhow::Result<(TypeInfo, usize)> {
    if cursor + BTF_TYPE_HEADER_SIZE > types.len() {
        bail!("BTF type record header exceeds section");
    }
    let name_off = u32::from_le_bytes(types[cursor..cursor + 4].try_into().unwrap());
    let info = u32::from_le_bytes(types[cursor + 4..cursor + 8].try_into().unwrap());
    let size_or_type = u32::from_le_bytes(types[cursor + 8..cursor + 12].try_into().unwrap());

    let vlen = info & 0xffff;
    let kind = (info >> 24) & 0x1f;

    let body_offset = cursor + BTF_TYPE_HEADER_SIZE;
    let trailing = match kind {
        KIND_VOID => 0,
        KIND_INT => BTF_INT_SIZE,
        KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT
        | KIND_FUNC | KIND_FLOAT | KIND_TYPE_TAG => 0,
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
pub(super) struct FlatMember {
    pub(super) name: String,
    pub(super) type_id: u32,
    pub(super) bit_offset: u32,
}

/// 沿 anonymous struct/union 递归把所有 named 字段拍平。anonymous 成员的 bit_offset
/// 会作为 base 累加给它的子字段——这是 C 标准里 anonymous member 字段对外可见的
/// 那个语义。
///
/// `max_depth` 防御 BTF 异常;sock_common 实际嵌套深度不超过 3。
pub(super) fn flatten_named_members(
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
                let mut nested =
                    flatten_named_members(types, strings, by_id, inner, abs_off, max_depth - 1)?;
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
pub(super) fn resolve_int_size(
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
pub(super) fn read_string(strings: &[u8], offset: u32) -> anyhow::Result<&str> {
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
