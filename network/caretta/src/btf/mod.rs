//! 最小 BTF 二进制 parser。
//!
//! 这是 caretta 用户态读取 vmlinux BTF 拿 `struct sock_common` 字段偏移的专用工具。
//!
//! ## 模块拆分
//!
//!   - [`parser`]:BTF 字节布局的低层解码——header、type record、member、string 段。
//!     不知道"我们要拿哪个字段",纯字节驱动。
//!   - [`lookup`]:在 parser 之上做"按 struct 名 + 字段名找 byte offset",并给
//!     caretta 暴露一条便捷的 [`parse_sock_offsets`] 入口。
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

mod lookup;
mod parser;

pub use lookup::{DEFAULT_VMLINUX_BTF_PATH, parse_sock_offsets, parse_tcp_sock_offsets};
