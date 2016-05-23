// Copyright 2016 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement, version 1.0.  This, along with the
// Licenses can be found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

use std::mem;
use std::cmp::Ordering;
use xor_name::XorName;

/// A sequence of bits, as a point in XOR space.
///
/// These are considered points in a space with the XOR metric, and need to implement the
/// functionality required by `RoutingTable` to use them as node names.
pub trait Xorable {
    /// Returns the bucket that `other` belongs to, in the routing table of the node with name
    /// `self`. This must be the number of leading bits in which `self` and `other` agree. E. g.
    /// the bucket index of `other = 11110000` for `self = 11111111` is 4, because the fifth bit is
    /// the first one in which they differ.
    fn bucket_index(&self, other: &Self) -> usize;

    /// Compares the distance of the arguments to `self`. Returns `Less` if `lhs` is closer,
    /// `Greater` if `rhs` is closer, and `Equal` if `lhs == rhs`. (The XOR distance can only be
    /// equal if the arguments are equal.)
    fn cmp_distance(&self, lhs: &Self, rhs: &Self) -> Ordering;

    /// Returns `true` if the `i`-th bit of other has a different value than the `i`-th bit of
    /// `self`.
    fn differs_in_bit(&self, other: &Self, i: usize) -> bool;
}

impl Xorable for XorName {
    fn bucket_index(&self, other: &XorName) -> usize {
        self.bucket_index(other)
    }

    fn cmp_distance(&self, lhs: &XorName, rhs: &XorName) -> Ordering {
        self.cmp_distance(lhs, rhs)
    }

    /// Returns whether the `i`-th bit of our and the given name differ.
    fn differs_in_bit(&self, name: &XorName, i: usize) -> bool {
        let byte = i / 8;
        let byte_bit = i % 8;
        (self.0[byte] ^ name.0[byte]) & (0b10000000 >> byte_bit) != 0
    }
}

macro_rules! impl_xorable {
    ($t:ident) => {
        impl Xorable for $t {
            fn bucket_index(&self, other: &Self) -> usize {
                (self ^ other).leading_zeros() as usize
            }

            fn cmp_distance(&self, lhs: &Self, rhs: &Self) -> Ordering {
                Ord::cmp(&(lhs ^ self), &(rhs ^ self))
            }

            fn differs_in_bit(&self, name: &Self, i: usize) -> bool {
                let pow_i = 1 << (mem::size_of::<Self>() * 8 - 1 - i); // 1 on bit i.
                (self ^ name) & pow_i != 0
            }
        }
    }
}

impl_xorable!(usize);
impl_xorable!(u64);
impl_xorable!(u32);
impl_xorable!(u16);
impl_xorable!(u8);
