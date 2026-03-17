//! Step 4.1: copy 约束到 sigma 映射。
//!
//! 这个模块做两件事：
//! - 根据 copy 约束把位置分成等价类
//! - 把每个等价类按固定顺序连成一个 cycle，得到 sigma 置换

use std::collections::BTreeMap;

use crate::{
    error::{PlonkError, Result},
    permutation::position::{Pos, WireId, pos_to_wire_id},
    validate::ensure,
};

/// 一条 copy 约束，表示两个位置的值必须相等。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopyConstraint {
    pub left: Pos,
    pub right: Pos,
}

/// sigma 映射，满足 `sigma_ids[id] = sigma(id)`。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SigmaMapping {
    domain_size: usize,
    sigma_ids: Vec<WireId>,
}

impl SigmaMapping {
    /// 功能说明：从原始 `(domain_size, sigma_ids)` 构造一个已校验的 sigma。
    /// 输入：domain 大小和长度应为 `3n` 的 sigma 向量。
    /// 输出：合法时返回 `SigmaMapping`，非法时返回错误。
    /// 示例：`let sigma = SigmaMapping::from_raw_parts(2, vec![0, 1, 2, 3, 4, 5])?;`
    pub fn from_raw_parts(domain_size: usize, sigma_ids: Vec<WireId>) -> Result<Self> {
        let mapping = Self::from_raw_parts_unchecked(domain_size, sigma_ids);
        validate_sigma_bijection(&mapping)?;
        Ok(mapping)
    }

    /// 功能说明：返回 sigma 对应的 domain 大小。
    /// 输入：`self`。
    /// 输出：`usize`。
    /// 示例：`assert_eq!(sigma.domain_size(), 8);`
    pub fn domain_size(&self) -> usize {
        self.domain_size
    }

    /// 功能说明：返回 sigma 向量的理论长度 `3n`。
    /// 输入：`self`。
    /// 输出：`usize`。
    /// 示例：`assert_eq!(sigma.expected_sigma_len(), 24);`
    pub fn expected_sigma_len(&self) -> usize {
        3 * self.domain_size
    }

    /// 功能说明：返回 sigma 向量的只读切片。
    /// 输入：`self`。
    /// 输出：`&[WireId]`。
    /// 示例：`let ids = sigma.sigma_ids();`
    pub fn sigma_ids(&self) -> &[WireId] {
        &self.sigma_ids
    }

    /// 功能说明：读取指定 source id 的像。
    /// 输入：source id。
    /// 输出：对应的 target id。
    /// 示例：`let image = sigma.image_at(5)?;`
    pub fn image_at(&self, source_id: WireId) -> Result<WireId> {
        self.sigma_ids
            .get(source_id)
            .copied()
            .ok_or(PlonkError::InvalidInput("sigma source id out of range"))
    }

    /// 功能说明：构造未校验的 sigma，仅供 crate 内部测试显式验证入口校验逻辑。
    /// 输入：domain 大小和原始 sigma 向量。
    /// 输出：未做双射校验的 `SigmaMapping`。
    /// 示例：grand product 单元测试可用它构造坏 sigma，再验证入口拒绝。
    pub(crate) fn from_raw_parts_unchecked(domain_size: usize, sigma_ids: Vec<WireId>) -> Self {
        Self {
            domain_size,
            sigma_ids,
        }
    }
}

/// 功能说明：根据 copy 约束构造 sigma 映射。
/// 输入：`domain_size=n` 和 copy 约束集合。
/// 输出：已校验的 `SigmaMapping`。
/// 示例：若 A0、B1、C2 同属一类，这三个位置会连成一个 cycle。
pub fn build_sigma_from_copy_constraints(
    domain_size: usize,
    constraints: &[CopyConstraint],
) -> Result<SigmaMapping> {
    ensure(domain_size > 0, "domain_size must be positive")?;

    let universe_len = 3 * domain_size;
    let mut dsu = DisjointSet::new(universe_len);

    for constraint in constraints {
        let left_id = pos_to_wire_id(constraint.left, domain_size)?;
        let right_id = pos_to_wire_id(constraint.right, domain_size)?;
        dsu.union(left_id, right_id);
    }

    let mut groups: BTreeMap<WireId, Vec<WireId>> = BTreeMap::new();
    for wire_id in 0..universe_len {
        let root = dsu.find(wire_id);
        groups.entry(root).or_default().push(wire_id);
    }

    let mut sigma_ids = (0..universe_len).collect::<Vec<_>>();
    for group in groups.values_mut() {
        group.sort_by_key(|wire_id| wire_order_key(*wire_id, domain_size));

        if group.len() <= 1 {
            continue;
        }

        for index in 0..group.len() {
            let current = group[index];
            let next = group[(index + 1) % group.len()];
            sigma_ids[current] = next;
        }
    }

    SigmaMapping::from_raw_parts(domain_size, sigma_ids)
}

/// 功能说明：校验 sigma 是否是全集 `[0,3n)` 上的双射。
/// 输入：`SigmaMapping`。
/// 输出：合法返回 `Ok(())`，否则返回错误。
/// 示例：若有重复像或缺失像，会返回错误。
pub fn validate_sigma_bijection(mapping: &SigmaMapping) -> Result<()> {
    ensure(mapping.domain_size > 0, "domain_size must be positive")?;
    let universe_len = 3 * mapping.domain_size;

    if mapping.sigma_ids.len() != universe_len {
        return Err(PlonkError::InconsistentLength(
            "sigma length must equal 3 * domain_size",
        ));
    }

    let mut seen = vec![false; universe_len];
    for image in mapping.sigma_ids.iter().copied() {
        ensure(image < universe_len, "sigma image out of range")?;
        if seen[image] {
            return Err(PlonkError::InvalidInput(
                "sigma is not bijection: duplicated image",
            ));
        }
        seen[image] = true;
    }

    if seen.iter().any(|flag| !flag) {
        return Err(PlonkError::InvalidInput(
            "sigma is not bijection: missing image",
        ));
    }

    Ok(())
}

/// 功能说明：给 wire id 生成稳定排序键，用于构造 cycle 的固定顺序。
/// 输入：wire id 和 domain 大小。
/// 输出：`(row_index, col_index)`。
/// 示例：`wire_order_key(11, 8)` 返回 `(3, 1)`。
fn wire_order_key(wire_id: WireId, domain_size: usize) -> (usize, usize) {
    let col_index = wire_id / domain_size;
    let row_index = wire_id % domain_size;
    (row_index, col_index)
}

#[allow(clippy::struct_field_names)]
/// 最小并查集实现，只服务于 Step 4.1 的等价类合并。
struct DisjointSet {
    parent: Vec<usize>,
    rank: Vec<usize>,
}

impl DisjointSet {
    /// 功能说明：创建 `size` 个彼此独立的集合。
    /// 输入：元素个数。
    /// 输出：新的并查集。
    /// 示例：`let dsu = DisjointSet::new(6);`
    fn new(size: usize) -> Self {
        let parent = (0..size).collect::<Vec<_>>();
        let rank = vec![0; size];
        Self { parent, rank }
    }

    /// 功能说明：查找某个元素当前所在集合的根。
    /// 输入：元素编号。
    /// 输出：根节点编号。
    /// 示例：若 2 和 7 已合并，则 `find(2) == find(7)`。
    fn find(&mut self, node: usize) -> usize {
        if self.parent[node] != node {
            let root = self.find(self.parent[node]);
            self.parent[node] = root;
        }
        self.parent[node]
    }

    /// 功能说明：合并两个元素所在的集合。
    /// 输入：两个元素编号。
    /// 输出：无返回值。
    /// 示例：`dsu.union(1, 4);`
    fn union(&mut self, left: usize, right: usize) {
        let left_root = self.find(left);
        let right_root = self.find(right);
        if left_root == right_root {
            return;
        }

        if self.rank[left_root] < self.rank[right_root] {
            self.parent[left_root] = right_root;
        } else if self.rank[left_root] > self.rank[right_root] {
            self.parent[right_root] = left_root;
        } else {
            self.parent[right_root] = left_root;
            self.rank[left_root] += 1;
        }
    }
}
