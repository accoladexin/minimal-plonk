//! Step 0.2 的 Fiat-Shamir transcript。
//!
//! 设计目标：
//! - 默认 Blake2b
//! - 保留 SHA256 选项
//! - 所有输入都先转换为 canonical bytes，再进入 transcript
//! - 同样输入必须给出同样 challenge

use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use blake2::{Blake2b512, Digest as BlakeDigest};
use sha2::Sha256;

use crate::{
    curve::Fr,
    types::{Commitment, TranscriptHash},
};

const TAG_BYTES: u8 = 0;
const TAG_SCALAR: u8 = 1;
const TAG_COMMITMENT: u8 = 2;
const TAG_CHALLENGE: u8 = 3;

/// 最小版 transcript。
/// 后续就是state+challenge_counter的哈希结果来生成挑战值
/// 跟进hash来选择hash算法
#[derive(Clone, Debug)]
pub struct Transcript {
    hash: TranscriptHash,   // 选择使用哪种哈希算法 (Blake2b 或 SHA256)
    state: Vec<u8>,         // 核心：所有历史信息的“汇总字节流”
    challenge_counter: u64, // 计数器，确保生成的挑战值序列是唯一的
}

impl Transcript {
    /// 创建 transcript，并先写入协议域分离标签。
    pub fn new(protocol_label: &[u8], hash: TranscriptHash) -> Self {
        let mut transcript = Self {
            hash,
            state: Vec::new(),
            challenge_counter: 0,
        };
        transcript.append_frame(TAG_BYTES, b"protocol", protocol_label);
        transcript
    }

    /// 追加原始字节消息。
    pub fn append_bytes(&mut self, label: &[u8], bytes: &[u8]) {
        self.append_frame(TAG_BYTES, label, bytes);
    }

    /// 追加一个域元素，编码方式使用 arkworks canonical serialization。
    pub fn append_scalar(&mut self, label: &[u8], scalar: &Fr) {
        let scalar_bytes = serialize_to_bytes(scalar);
        self.append_frame(TAG_SCALAR, label, &scalar_bytes);
    }

    /// 追加一个承诺点，编码方式同样使用 canonical serialization。
    pub fn append_commitment(&mut self, label: &[u8], commitment: &Commitment) {
        let commitment_bytes = serialize_to_bytes(commitment);
        self.append_frame(TAG_COMMITMENT, label, &commitment_bytes);
    }

    /// 基于当前 transcript 状态导出一个新的挑战值。
    pub fn challenge_scalar(&mut self, label: &[u8]) -> Fr {
        let digest = self.hash_current_state(label);
        let challenge = Fr::from_le_bytes_mod_order(&digest);
        self.append_frame(TAG_CHALLENGE, label, &digest);
        self.challenge_counter += 1;
        challenge
    }

    /// 统一写入一帧消息，避免不同类型消息的边界混淆。
    fn append_frame(&mut self, tag: u8, label: &[u8], payload: &[u8]) {
        self.state.push(tag); // 写入类型标签 (Bytes, Scalar, 还是 Commitment)
        self.state
            .extend_from_slice(&(label.len() as u64).to_le_bytes()); // 写入标签长度
        self.state.extend_from_slice(label); // 写入标签内容
        self.state
            .extend_from_slice(&(payload.len() as u64).to_le_bytes()); // 写入数据长度
        self.state.extend_from_slice(payload); // 写入数据内容
    }
    /// 对当前状态做一次哈希，并把 label 与 challenge 计数器也纳入输入。
    fn hash_current_state(&self, label: &[u8]) -> Vec<u8> {
        let mut preimage = Vec::with_capacity(self.state.len() + label.len() + 16);
        preimage.extend_from_slice(&self.state);
        preimage.extend_from_slice(&(label.len() as u64).to_le_bytes());
        preimage.extend_from_slice(label);
        preimage.extend_from_slice(&self.challenge_counter.to_le_bytes());

        match self.hash {
            TranscriptHash::Blake2b => Blake2b512::digest(preimage).to_vec(),
            TranscriptHash::Sha256 => Sha256::digest(preimage).to_vec(),
        }
    }
}

impl Default for Transcript {
    /// 默认 transcript 使用 Blake2b，并带一个固定协议名。
    fn default() -> Self {
        Self::new(b"minimal-plonk", TranscriptHash::default())
    }
}

/// 把任意支持 canonical serialization 的对象编码成稳定字节串。
fn serialize_to_bytes<T: CanonicalSerialize>(value: &T) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(value.serialized_size(ark_serialize::Compress::Yes));
    value
        .serialize_compressed(&mut bytes)
        .expect("serializing into a Vec<u8> should not fail");
    bytes
}
