// Copyright 2015 MaidSafe.net limited.
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

#![doc(html_logo_url =
"https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
html_favicon_url = "http://maidsafe.net/img/favicon.ico",
html_root_url = "http://maidsafe.github.io/kademlia_routing_table")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, clippy_pedantic))]
#![cfg_attr(feature="clippy", allow(use_debug))]

//! A routing table to manage contacts for a node in a [Kademlia][1] distributed hash table.
//!
//! [1]: https://en.wikipedia.org/wiki/Kademlia
//!
//!
//! This crate uses the Kademlia mechanism for routing messages in a peer-to-peer network, and
//! generalises it to provide redundancy in every step: for senders, messages in transit and
//! receivers. It contains the routing table and the functionality to decide via which of its
//! entries to route a message, but not the networking functionality itself.
//!
//!
//! # Addresses and distance functions
//!
//! Nodes in the network are addressed with a [`XorName`][2], a 512-bit unsigned integer. The
//! *[XOR][3] distance* between two nodes with addresses `x` and `y` is `x ^ y`. This
//! [distance function][4] has the property that no two points ever have the same distance from a
//! given point, i. e. if `x ^ y == x ^ z`, then `y == z`. This property allows us to define the
//! *close group* of an address as the [`GROUP_SIZE`][5] closest nodes to that address,
//! guaranteeing that the close group will always have exactly `GROUP_SIZE` members (unless, of
//! course, the whole network has less than `GROUP_SIZE` nodes).
//!
//! [2]: ../xor_name/struct.XorName.html
//! [3]: https://en.wikipedia.org/wiki/Exclusive_or#Bitwise_operation
//! [4]: https://en.wikipedia.org/wiki/Metric_%28mathematics%29
//! [5]: constant.GROUP_SIZE.html
//!
//! The routing table is associated with a node with some name `x`, and manages a number of
//! contacts to other nodes, sorting them into up to 512 *buckets*, depending on their XOR
//! distance from `x`:
//!
//! * If 2<sup>512</sup> > `x ^ y` >= 2<sup>511</sup>, then y is in bucket 0.
//! * If 2<sup>511</sup> > `x ^ y` >= 2<sup>510</sup>, then y is in bucket 1.
//! * If 2<sup>510</sup> > `x ^ y` >= 2<sup>509</sup>, then y is in bucket 2.
//! * ...
//! * If 2 > `x ^ y` >= 1, then y is in bucket 511.
//!
//! Equivalently, `y` is in bucket `n` if the longest common prefix of `x` and `y` has length `n`,
//! i. e. the first binary digit in which `x` and `y` disagree is the `(n + 1)`-th one. We call the
//! length of the remainder, without the common prefix, the *bucket distance* of `x` and `y`. Hence
//! `x` and `y` have bucket distance `512 - n` if and only if `y` belongs in bucket number `n`.
//!
//! The bucket distance is coarser than the XOR distance: Whenever the bucket distance from `y` to
//! `x` is less than the bucket distance from `z` to `x`, then `y ^ x < z ^ x`. But not vice-versa:
//! Often `y ^ x < z ^ x`, even if the bucket distances are equal. The XOR distance ranges from 0
//! to 2<sup>512</sup> (exclusive), while the bucket distance ranges from 0 to 512 (inclusive).
//!
//!
//! # Guarantees
//!
//! The routing table provides functions to decide, for a message with a given destination, which
//! nodes in the table to pass the message on to, so that it is guaranteed that:
//!
//! * If the destination is the address of a node, the message will reach that node after at most
//!   511 hops.
//! * Otherwise the message will reach every member of the close group of the destination address,
//!   i. e. all `GROUP_SIZE` nodes in the network that are XOR-closest to that address, and each
//!   node knows whether it belongs to that group.
//! * Each node in a given address' close group is connected to each other node in that group. In
//!   particular, every node is connected to its own close group.
//! * The number of total hop messages created for each message is at most `PARALLELISM` * 512.
//! * For each node there are at most 512 * `GROUP_SIZE` other nodes in the network for which it can
//!   obtain the IP address, at any point in time.
//!
//! However, to be able to make these guarantees, the routing table must be filled with
//! sufficiently many contacts. Specifically, the following invariant must be ensured:
//!
//! > Whenever a bucket `n` has fewer than `GROUP_SIZE` entries, it contains *all* nodes in the
//! > network with bucket distance `512 - n`.
//!
//! The user of this crate therefore needs to make sure that whenever a node joins or leaves, all
//! affected nodes in the network update their routing tables accordingly.
//!
//!
//! # Resilience against malfunctioning nodes
//!
//! In each hop during routing, messages are passed on to `PARALLELISM` other nodes, so that even
//! if `PARALLELISM - 1` nodes between the source and destination fail, they are still successfully
//! delivered.
//!
//! The concept of close groups exists to provide resilience even against failures of the source or
//! destination itself: If every member of a group tries to send the same message, it will arrive
//! even if some members fail. And if a message is sent to a whole group, it will arrive in most,
//! even if some of them malfunction.
//!
//! Close groups can thus be used as inherently redundant authorities in the network that messages
//! can be sent to and received from, using a consensus algorithm: A message from a group authority
//! is considered to be legitimate, if at least `QUORUM_SIZE` group members have sent a message with
//! the same content.

#[macro_use]
#[allow(unused_extern_crates)]
extern crate maidsafe_utilities;

extern crate itertools;
#[cfg(test)]
extern crate rand;
extern crate xor_name;

mod contact_info;
mod result;

pub use contact_info::ContactInfo;
pub use result::{AddedNodeDetails, DroppedNodeDetails};

use itertools::*;
use std::cmp;
use xor_name::XorName;

/// The size of a close group.
///
/// The `GROUP_SIZE` XOR-closest nodes to an address constitute the *close group* with that
/// address.
pub const GROUP_SIZE: usize = 8;

/// The number of nodes in a group that represent a quorum.
///
/// A message from a close group should be considered legitimate if at least `QUORUM_SIZE` members
/// sent it.
const QUORUM_SIZE: usize = 5;

/// The number of nodes a message is sent to in each hop for redundancy.
///
/// See [`target_nodes`](struct.RoutingTable.html#method.target_nodes) for details.
pub const PARALLELISM: usize = 8;

/// A message destination.
#[derive(Copy, Clone, Debug)]
pub enum Destination {
    /// The close group of the given address. The message should reach `GROUP_SIZE` nodes.
    Group(XorName),
    /// The individual node at the given address. The message should reach exactly one node.
    Node(XorName),
}

/// A routing table to manage contacts for a node.
///
/// It maintains a list of `XorName`s representing connected peer nodes, and provides algorithms for
/// routing messages.
///
/// See the [crate documentation](index.html) for details.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RoutingTable<T: ContactInfo> {
    /// The buckets, by bucket index. Each bucket is sorted by ascending distance from us.
    buckets: Vec<Vec<T>>,
    /// This nodes' own contact info.
    our_info: T,
}

impl<T: ContactInfo> RoutingTable<T> {
    /// Creates a new routing table for the node with the given name.
    pub fn new(our_info: T) -> Self {
        RoutingTable {
            buckets: vec![],
            our_info: our_info,
        }
    }

    /// Adds a contact to the routing table, or updates it.
    ///
    /// Returns `None` if the contact already existed or was denied (see `allow_connection`).
    /// Otherwise it returns `AddedNodeDetails`.
    pub fn add(&mut self, info: T) -> Option<AddedNodeDetails<T>> {
        if !self.allow_connection(info.name()) {
            return None;
        }
        match self.search(info.name()) {
            (_, Ok(_)) => None,
            (bucket_index, Err(i)) => {
                if self.buckets.len() <= bucket_index {
                    self.buckets.resize(bucket_index + 1, vec![]);
                }
                let must_notify = if self.buckets[bucket_index].len() < GROUP_SIZE {
                    self.buckets
                        .iter()
                        .skip(bucket_index + 1)
                        .flat_map(|bucket| bucket.iter().cloned())
                        .collect()
                } else {
                    vec![]
                };

                let common_groups = self.is_in_any_close_group_with(bucket_index);

                self.buckets[bucket_index].insert(i, info);

                let unneeded = if common_groups {
                    vec![]
                } else {
                    self.buckets[bucket_index]
                                   .iter()
                                   .skip(GROUP_SIZE)
                                   .cloned()
                                   .collect()
                };

                Some(AddedNodeDetails {
                    must_notify: must_notify,
                    unneeded: unneeded,
                    common_groups: common_groups,
                })
            }
        }
    }

    /// Returns whether it is desirable to add the given contact to the routing table.
    ///
    /// Returns `false` if adding the contact in question would not bring the routing table closer
    /// to satisfy the invariant. It returns `true` if and only if the new contact would be among
    /// the `GROUP_SIZE` closest nodes in its bucket.
    pub fn need_to_add(&self, name: &XorName) -> bool {
        if name == self.our_name() {
            return false;
        }
        match self.search(name) {
            (_, Ok(_)) => false,           // They already are in our routing table.
            (_, Err(i)) => i < GROUP_SIZE, // We need to add them if the bucket is not full.
        }
    }

    /// Removes `name` from routing table and returns `true` if we no longer need to stay connected.
    ///
    /// We should remain connected iff the entry is among the `GROUP_SIZE` closest nodes in its
    /// bucket or if we have any close groups in common with it.
    pub fn remove_if_unneeded(&mut self, name: &XorName) -> bool {
        if name == self.our_name() {
            return false;
        }

        if let (bucket, Ok(i)) = self.search(name) {
            if i >= GROUP_SIZE && !self.is_in_any_close_group_with(bucket) {
                let _ = self.remove(name);
                return true
            }
        }

        false
    }

    /// Returns whether we can allow the given contact to connect to us.
    ///
    /// The connection is allowed if:
    ///
    /// * they already are one of our contacts,
    /// * we need them in our routing table to satisfy the invariant or
    /// * we are in the close group of one of their bucket addresses.
    pub fn allow_connection(&self, name: &XorName) -> bool {
        if name == self.our_name() {
            return false;
        }
        match self.search(name) {
            (_, Ok(_)) => true,
            (_, Err(i)) => i < GROUP_SIZE || self.is_close_to_bucket_of(name),
        }
    }

    /// Returns the current calculated quorum size.
    ///
    /// If it is known that the network has at least `GROUP_SIZE` nodes, this returns the constant
    /// `QUORUM_SIZE`. For networks smaller than that, the quorum might not be reachable, so a
    /// smaller number is computed which represents a strict majority in the current network.
    pub fn dynamic_quorum_size(&self) -> usize {
        let network_size = self.len() + 1; // Routing table entries plus this node itself.
        if network_size >= GROUP_SIZE {
            QUORUM_SIZE
        } else {
            cmp::max(network_size * QUORUM_SIZE / GROUP_SIZE,
                     network_size / 2 + 1)
        }
    }

    /// Returns the bucket index of the furthest close node, or `0` if the table is empty.
    pub fn furthest_close_bucket(&self) -> usize {
        let mut node_count = 0;
        for (bucket_index, bucket_len) in self.buckets.iter().map(Vec::len).enumerate().rev() {
            node_count += bucket_len;
            if node_count >= GROUP_SIZE {
                return bucket_index;
            }
        }
        match self.buckets.iter().position(|b| !b.is_empty()) {
            None => 0,
            Some(i) => i,
        }
    }

    /// Removes the contact from the table.
    ///
    /// If no entry with that name is found, `None` is returned. Otherwise, the entry is removed
    /// from the routing table and `DroppedNodeDetails` are returned.
    pub fn remove(&mut self, name: &XorName) -> Option<DroppedNodeDetails> {
        match self.search(name) {
            (_, Err(_)) => None,
            (bucket_index, Ok(i)) => {
                let common_groups = self.is_in_any_close_group_with(bucket_index);
                let incomplete_bucket = if self.buckets[bucket_index].len() == GROUP_SIZE {
                    Some(bucket_index)
                } else {
                    None
                };
                let _ = self.buckets[bucket_index].remove(i);
                while self.buckets.last().map_or(false, Vec::is_empty) {
                    let _ = self.buckets.pop();
                }
                // TODO: Remove trailing empty buckets?
                Some(DroppedNodeDetails {
                    incomplete_bucket: incomplete_bucket,
                    common_groups: common_groups,
                })
            }
        }
    }

    /// Returns a collection of nodes to which a message should be sent onwards.
    ///
    /// If the message is addressed at a group we are a member of and the previous `hop` is not,
    /// this returns all other members of that group once, and an empty collection for all further
    /// copies.
    ///
    /// If the message is addressed at an individual node that is directly connected to us, this
    /// returns the destination node once, and an empty collection for all further copies.
    ///
    /// If we are the individual recipient, it also returns an empty collection.
    ///
    /// If none of the above is the case and we are the original sender, it returns the
    /// `PARALLELISM` closest nodes to the target.
    ///
    /// Otherwise it returns the `n`-th closest node to the target if this is the `n`-th copy of
    /// the message we are relaying.
    ///
    /// # Arguments
    ///
    /// * `dst` -   The destination of the message.
    /// * `hop` -   The name of the node that relayed the message to us, or ourselves if we are the
    ///             original sender.
    /// * `count` - The number of times we have seen this message before.
    pub fn target_nodes(&self, dst: Destination, hop: &XorName, count: usize) -> Vec<T> {
        let target = match dst {
            Destination::Group(ref target) => {
                if self.is_close(target) {
                    if count > 0 {
                        return vec![];
                    }
                    let close_group = self.closest_nodes_to(target, GROUP_SIZE - 1, false);
                    return close_group;
                }
                target
            }
            Destination::Node(ref target) => {
                if target == self.our_name() {
                    return vec![];
                } else if let Some(target_contact) = self.get(target) {
                    return if count == 0 {
                        vec![target_contact.clone()]
                    } else {
                        vec![]
                    };
                }
                target
            }
        };
        if hop == self.our_name() {
            self.closest_nodes_to(target, PARALLELISM, false)
        } else {
            self.closest_nodes_to(target, count + 2, false)
                .into_iter()
                .filter(|node| node.name() != hop)
                .skip(count)
                .take(1)
                .collect()
        }
    }

    /// Returns whether the message is addressed to this node.
    ///
    /// If this returns `true`, this node is either the single recipient of the message, or a
    /// member of the group authority to which it is addressed. It therefore needs to handle the
    /// message.
    pub fn is_recipient(&self, dst: Destination) -> bool {
        match dst {
            Destination::Node(ref target) => target == self.our_name(),
            Destination::Group(ref target) => self.is_close(target),
        }
    }

    /// Returns the other members of `name`'s close group, or `None` if we are not a member of it.
    pub fn other_close_nodes(&self, name: &XorName) -> Option<Vec<T>> {
        if self.is_close(name) {
            Some(self.closest_nodes_to(name, GROUP_SIZE - 1, false))
        } else {
            None
        }
    }

    /// Returns the members of `name`'s close group, or `None` if we are not a member of it.
    pub fn close_nodes(&self, name: &XorName) -> Option<Vec<T>> {
        if self.is_close(name) {
            Some(self.closest_nodes_to(name, GROUP_SIZE, true))
        } else {
            None
        }
    }

    /// Returns `true` if there are fewer than `GROUP_SIZE` nodes in our routing table that are
    /// closer to `name` than we are.
    ///
    /// In other words, it returns `true` whenever we cannot rule out that we might be among the
    /// `GROUP_SIZE` closest nodes to `name`.
    ///
    /// If the routing table is filled in such a way that each bucket contains `GROUP_SIZE`
    /// elements unless there aren't enough such nodes in the network, then this criterion is
    /// actually sufficient! In that case, `true` is returned if and only if we are among the
    /// `GROUP_SIZE` closest node to `name` in the network.
    pub fn is_close(&self, name: &XorName) -> bool {
        let mut count = 0;
        for (bucket_index, bucket) in self.buckets.iter().enumerate() {
            if self.differs_in_bit(name, bucket_index) {
                count += bucket.len();
                if count >= GROUP_SIZE {
                    return false;
                }
            }
        }
        true
    }

    /// Number of entries in the routing table.
    pub fn len(&self) -> usize {
        self.buckets.iter().fold(0, |acc, bucket| acc + bucket.len())
    }

    /// Returns `true` if there are no entries in the routing table.
    pub fn is_empty(&self) -> bool {
        self.buckets.iter().all(Vec::is_empty)
    }

    /// Returns the name of the node this routing table is for.
    pub fn our_name(&self) -> &XorName {
        self.our_info.name()
    }

    /// Returns whether the given node is in the routing table.
    pub fn contains(&self, name: &XorName) -> bool {
        self.search(name).1.is_ok()
    }

    /// Returns the contact associated with the given name.
    pub fn get(&self, name: &XorName) -> Option<&T> {
        if let (bucket_index, Ok(node_index)) = self.search(name) {
            Some(&self.buckets[bucket_index][node_index])
        } else if name == self.our_name() {
            Some(&self.our_info)
        } else {
            None
        }
    }

    /// Returns the number of entries in the bucket with the given index.
    pub fn bucket_len(&self, index: usize) -> usize {
        self.buckets.get(index).map_or(0, Vec::len)
    }

    /// Returns the number of buckets.
    ///
    /// This is one more than the index of the bucket containing the closest peer, or `0` if the
    /// routing table is empty.
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Returns an entry that satisfies the given `predicate`.
    pub fn find<F>(&self, predicate: F) -> Option<&T>
        where F: FnMut(&&T) -> bool
    {
        self.buckets.iter().flat_map(|bucket| bucket.iter()).find(predicate)
    }

    /// Returns the `n` nodes in our routing table that are closest to `target`.
    ///
    /// Returns fewer than `n` nodes if the routing table doesn't have enough entries. If
    /// `ourselves` is `true`, this could potentially include ourselves. Otherwise, our own name is
    /// skipped.
    pub fn closest_nodes_to(&self, target: &XorName, n: usize, ourselves: bool) -> Vec<T> {
        let cmp = |a: &&T, b: &&T| target.cmp_distance(a.name(), b.name());
        // If we disagree with target in a bit, that bit's bucket contains contacts that are closer
        // to the target than we are. The lower the bucket index, the closer it is:
        let closer_buckets_iter = self.buckets
                                      .iter()
                                      .enumerate()
                                      .filter(|&(bit, _)| self.differs_in_bit(target, bit))
                                      .flat_map(|(_, b)| b.iter().sorted_by(&cmp).into_iter());
        // Nothing or ourselves, depending on whether we should be include in the result:
        let ourselves_iter = if ourselves {
            Some(&self.our_info).into_iter()
        } else {
            None.into_iter()
        };
        // If we agree with target in a bit, that bit's bucket contains contacts that are further
        // away from the target than we are. The lower the bucket index, the further away it is:
        let further_buckets_iter = self.buckets
                                       .iter()
                                       .enumerate()
                                       .rev()
                                       .filter(|&(bit, _)| !self.differs_in_bit(target, bit))
                                       .flat_map(|(_, b)| b.iter().sorted_by(&cmp).into_iter());
        // Chaining these iterators puts the buckets in the right order, with ascending distance
        // from the target. Finally, we need to sort each bucket's contents and take n:
        closer_buckets_iter.chain(ourselves_iter)
                           .chain(further_buckets_iter)
                           .take(n)
                           .cloned()
                           .collect()
    }

    /// Returns whether we are close to one of `name`'s bucket addresses or to `name` itself.
    fn is_close_to_bucket_of(&self, name: &XorName) -> bool {
        // We are close to `name` if the buckets where `name` disagrees with us have less than
        // GROUP_SIZE entries in total. Therefore we are close to a bucket address of `name`, if
        // removing the largest such bucket gets us below GROUP_SIZE.
        let mut closer_contacts: usize = 0;
        let mut largest_bucket: usize = 0;
        for (bit, bucket) in self.buckets.iter().enumerate() {
            if self.differs_in_bit(name, bit) {
                largest_bucket = cmp::max(largest_bucket, bucket.len());
                closer_contacts += bucket.len();
                if closer_contacts >= largest_bucket + GROUP_SIZE {
                    return false;
                }
            }
        }
        true
    }

    /// Returns whether the `i`-th bit of our and the given name differ.
    fn differs_in_bit(&self, name: &XorName, i: usize) -> bool {
        let byte = i / 8;
        let byte_bit = i % 8;
        (self.our_name().0[byte] ^ name.0[byte]) & (0b10000000 >> byte_bit) != 0
    }

    // This is equivalent to the common leading bits of `self.our_name` and `name` where "leading
    // bits" means the most significant bits.
    fn bucket_index(&self, name: &XorName) -> usize {
        self.our_name().bucket_index(name)
    }

    /// Searches the routing table for the given name.
    ///
    /// Returns a tuple with the bucket index of `name` as the first entry. The second entry is
    /// `Ok(i)` if the node has index `i` in that bucket, or `Err(i)` if it isn't there yet and `i`
    /// is the index inside the bucket where it would be inserted.
    fn search(&self, name: &XorName) -> (usize, Result<usize, usize>) {
        let bucket_index = self.bucket_index(name);
        (bucket_index,
         match self.buckets.get(bucket_index) {
            None => Err(0),
            Some(bucket) => {
                bucket.binary_search_by(|other| self.our_name().cmp_distance(other.name(), name))
            }
        })
    }

    /// Returns whether we share any close groups with the nodes in the given bucket.
    ///
    /// If the bucket is not full or we have less than `GROUP_SIZE - 1` contacts with a greater
    /// bucket index, then for _every_ node in that bucket there exists an address which both that
    /// node and our own node are in the close group of. In that case, the result is `true`.
    ///
    /// Otherwise, no such address exists and `false` is returned.
    fn is_in_any_close_group_with(&self, bucket_index: usize) -> bool {
        if match self.buckets.get(bucket_index) {
            None => return true,
            Some(bucket) => bucket.len(),
        } < GROUP_SIZE {
            return true;
        }
        let mut count = 0;
        for bucket in self.buckets.iter().skip(bucket_index + 1) {
            count += bucket.len();
            if count >= GROUP_SIZE - 1 {
                return false;
            }
        }
        true
    }
}



#[cfg(test)]
mod test {
    use super::*;
    use rand;
    use std::cmp;
    use std::collections::HashMap;
    use itertools::Itertools;
    use xor_name;
    use xor_name::XorName;

    impl ContactInfo for XorName {
        fn name(&self) -> &XorName {
            &self
        }
    }

    const TABLE_SIZE: usize = 100;

    #[test]
    fn constant_constraints() {
        // This is required for the RoutingTable to make its guarantees.
        assert!(GROUP_SIZE >= PARALLELISM);
    }

    /// Creates a name in the `index`-th bucket of the table with the given name, where
    /// `index < 503`. The given `distance` will be added. If `distance == 255`, the furthest
    /// possible name in the given bucket is returned.
    fn get_contact(table_name: &XorName, index: usize, distance: u8) -> XorName {
        let XorName(mut arr) = table_name.clone();
        // Invert all bits starting with the `index`th one, so the bucket distance is `index`.
        arr[index / 8] = arr[index / 8] ^ 0b11111111 >> (index % 8);
        for i in (index / 8 + 1)..(arr.len() - 1) {
            arr[i] = arr[i] ^ 255;
        }
        // Add the desired distance.
        let last = arr.len() - 1;
        arr[last] = arr[last] ^ distance;
        let result = XorName(arr);
        assert_eq!(index, result.bucket_index(table_name));
        result
    }

    struct TestEnvironment {
        table: RoutingTable<XorName>,
        name: XorName,
        initial_count: usize,
        added_names: Vec<XorName>,
    }

    impl TestEnvironment {
        fn new() -> TestEnvironment {
            let name = rand::random::<XorName>();
            TestEnvironment {
                table: RoutingTable::new(name.clone()),
                name: name,
                initial_count: (rand::random::<usize>() % (GROUP_SIZE - 1)) + 1,
                added_names: Vec::new(),
            }
        }

        fn partially_fill_table(&mut self) {
            let count = self.initial_count;
            self.fill_table(0, count)
        }

        fn complete_filling_table(&mut self) {
            let count = self.initial_count;
            self.fill_table(count, TABLE_SIZE)
        }

        fn fill_table(&mut self, first_bucket: usize, total_buckets: usize) {
            for i in first_bucket..total_buckets {
                let name = get_contact(&self.name, i, 1);
                self.added_names.push(name);
                assert!(self.table.add(name).is_some());
            }

            assert_eq!(total_buckets, self.table.len());
            assert!(are_nodes_sorted(&self.table), "Nodes are not sorted");
        }
    }

    fn create_random_routing_tables(num_of_tables: usize) -> Vec<RoutingTable<XorName>> {
        let mut vector = Vec::with_capacity(num_of_tables);
        for _ in 0..num_of_tables {
            vector.push(RoutingTable::new(rand::random()));
        }
        vector
    }

    fn are_nodes_sorted(routing_table: &RoutingTable<XorName>) -> bool {
        routing_table.buckets
                     .iter()
                     .rev()
                     .flat_map(|bucket| bucket.iter())
                     .zip(routing_table.buckets
                                       .iter()
                                       .rev()
                                       .flat_map(|bucket| bucket.iter())
                                       .skip(1))
                     .all(|(lhs, rhs)| {
                         xor_name::closer_to_target(lhs, rhs, routing_table.our_name())
                     })
    }

    fn make_sort_predicate(target: XorName) -> Box<FnMut(&XorName, &XorName) -> cmp::Ordering> {
        Box::new(move |lhs: &XorName, rhs: &XorName| target.cmp_distance(lhs, rhs))
    }

    #[test]
    fn add() {
        let mut test = TestEnvironment::new();

        assert_eq!(test.table.len(), 0);

        // try with our name - should fail
        let contact = test.table.our_name().clone();
        assert!(test.table.add(contact).is_none());
        assert_eq!(test.table.len(), 0);

        // add first contact
        let contact = get_contact(&test.name, 0, 2);
        assert!(test.table.add(contact).is_some());
        assert_eq!(test.table.len(), 1);

        // try with the same contact - should fail
        assert!(test.table.add(contact).is_none());
        assert_eq!(test.table.len(), 1);
    }

    #[test]
    fn add_to_full_bucket() {
        // add node to a full bucket whose nodes share close group with us
        let mut test = TestEnvironment::new();

        for i in 0..GROUP_SIZE {
            let contact = get_contact(&test.name, 1, i as u8);
            assert!(test.table.add(contact).is_some());
        }

        let contact = get_contact(&test.name, 1, 255);

        if let Some(added_node_details) = test.table.add(contact) {
            assert_eq!(added_node_details,
                AddedNodeDetails {
                    must_notify: vec![],
                    unneeded: vec![],
                    common_groups: true,
                });
        } else {
            assert!(false);
        }

        // Adding a node should not remove existing nodes
        assert_eq!(test.table.len(), GROUP_SIZE + 1);

        // add node to a full bucket whose nodes do not share close group with us
        test = TestEnvironment::new();

        for i in 0..GROUP_SIZE {
            let contact = get_contact(&test.name, 1, 1 + i as u8);
            assert!(test.table.add(contact).is_some());
        }

        for i in 0..GROUP_SIZE {
            let contact = get_contact(&test.name, 2, i as u8);
            assert!(test.table.add(contact).is_some());
        }

        let contact = get_contact(&test.name, 1, 0);

        if let Some(added_node_details) = test.table.add(contact) {
            let bucket_index = test.table.bucket_index(&contact);
            let unneeded = test.table
                               .buckets[bucket_index]
                               .iter()
                               .skip(GROUP_SIZE)
                               .cloned()
                               .collect::<Vec<XorName>>();

            assert_eq!(added_node_details,
                AddedNodeDetails {
                    must_notify: vec![],
                    unneeded: unneeded,
                    common_groups: false,
                });
        } else {
            assert!(false);
        }

        // Adding a node should not remove existing nodes
        assert_eq!(test.table.len(), 2 * GROUP_SIZE + 1);
    }

    #[test]
    fn add_to_bucket_that_is_not_full() {
        let mut test = TestEnvironment::new();

        for i in 0..(GROUP_SIZE / 2) {
            let contact = get_contact(&test.name, 1, i as u8);
            assert!(test.table.add(contact).is_some());
        }

        let name_to_notify0 = get_contact(&test.name, 2, 0);
        assert!(test.table.add(name_to_notify0).is_some());

        let name_to_notify1 = get_contact(&test.name, 3, 0);
        assert!(test.table.add(name_to_notify1).is_some());

        let contact = get_contact(&test.name, 1, 255);
        let nodes_to_notify = test.table.add(contact).unwrap().must_notify;
        assert!(nodes_to_notify.len() == 2);
        assert!(nodes_to_notify.iter().any(|n| *n == name_to_notify0));
        assert!(nodes_to_notify.iter().any(|n| *n == name_to_notify1));
    }

    #[test]
    fn need_to_add() {
        let mut test = TestEnvironment::new();

        // Try with our ID
        assert!(!test.table.need_to_add(test.table.our_name()));

        // Should return true for empty routing table
        assert!(test.table.need_to_add(&get_contact(&test.name, 0, 2)));

        // Add the first contact, and check it doesn't allow duplicates
        let new_node_0 = get_contact(&test.name, 0, 2);
        assert!(test.table.add(new_node_0).is_some());
        assert!(!test.table.need_to_add(&get_contact(&test.name, 0, 2)));

        // Shoud return false if the bucket is full
        for i in 0..GROUP_SIZE {
            let contact = get_contact(&test.name, 1, i as u8);
            assert!(test.table.add(contact).is_some());
        }

        assert!(!test.table.need_to_add(&get_contact(&test.name, 1, 255)));
    }

    #[test]
    fn remove() {
        use rand::Rng;

        // Check on empty table
        let mut test = TestEnvironment::new();

        assert_eq!(test.table.len(), 0);

        // Fill the table
        test.partially_fill_table();
        test.complete_filling_table();

        // Try with invalid Address
        assert!(test.table.remove(&XorName::new([0u8; 64])).is_none());
        assert_eq!(TABLE_SIZE, test.table.len());

        // Try with our Name
        let drop_name = test.table.our_name().clone();
        assert!(test.table.remove(&drop_name).is_none());
        assert_eq!(TABLE_SIZE, test.table.len());

        // Try with Address of node not in table
        assert!(test.table.remove(&get_contact(&test.name, 0, 2)).is_none());
        assert_eq!(TABLE_SIZE, test.table.len());

        // Remove all nodes one at a time in random order
        let mut rng = rand::thread_rng();
        rng.shuffle(&mut test.added_names[..]);
        let mut len = test.table.len();
        for name in test.added_names {
            len -= 1;
            assert!(test.table.remove(&name).is_some());
            assert_eq!(len, test.table.len());
        }
    }


    #[test]
    fn target_nodes() {
        // modernise
        let mut test = TestEnvironment::new();

        // Check on empty table
        let mut target_nodes = test.table
                                   .target_nodes(Destination::Group(rand::random()), &test.name, 0);
        assert_eq!(target_nodes.len(), 0);

        // Partially fill the table with <GROUP_SIZE contacts
        test.partially_fill_table();

        // Check we get all contacts returned
        target_nodes = test.table.target_nodes(Destination::Group(rand::random()), &test.name, 0);
        assert_eq!(test.initial_count, target_nodes.len());

        for i in 0..test.initial_count {
            let expected_name = get_contact(&test.name, i, 1);
            assert!(target_nodes.iter().any(|node| *node == expected_name));
        }

        // Complete filling the table up to TABLE_SIZE contacts
        test.complete_filling_table();

        // Try with our ID (should return the rest of the close group)
        target_nodes = test.table
                           .target_nodes(Destination::Group(test.table.our_name().clone()),
                                         &test.name,
                                         0);
        assert_eq!(GROUP_SIZE - 1, target_nodes.len());

        for i in ((TABLE_SIZE - GROUP_SIZE + 1)..TABLE_SIZE - 1).rev() {
            let expected_name = get_contact(&test.name, i, 1);
            assert!(target_nodes.iter().any(|node| *node == expected_name));
        }

        // Try with nodes far from us, first time *not* in table and second time *in* table (should
        // return 'PARALLELISM' contacts closest to target first time and the single actual target
        // the second time)
        let mut target: XorName;
        for count in 0..2 {
            for i in 0..(TABLE_SIZE - GROUP_SIZE) {
                let (target, expected_len) = if count == 0 {
                    (get_contact(&test.name, i, 2).clone(), PARALLELISM)
                } else {
                    (get_contact(&test.name, i, 1).clone(), 1)
                };
                target_nodes = test.table.target_nodes(Destination::Node(target), &test.name, 0);
                assert_eq!(expected_len, target_nodes.len());

                for i in 0..target_nodes.len() {
                    assert!(test.added_names.iter().any(|name| *name == target_nodes[i]));
                }
            }
        }

        // Try with nodes close to us, first time *not* in table and second time *in* table (should
        // return GROUP_SIZE - 1 closest to target)
        for count in 0..2 {
            for i in (TABLE_SIZE - GROUP_SIZE + 2)..TABLE_SIZE {
                target = if count == 0 {
                    get_contact(&test.name, i, 0).clone()
                } else {
                    get_contact(&test.name, i, 1).clone()
                };
                target_nodes = test.table.target_nodes(Destination::Group(target), &test.name, 0);
                assert_eq!(GROUP_SIZE - 1, target_nodes.len());

                for i in 0..target_nodes.len() {
                    assert!(test.added_names.iter().any(|name| *name == target_nodes[i]));
                }
            }
        }
    }

    #[test]
    fn is_recipient() {
        let mut test = TestEnvironment::new();
        test.partially_fill_table();
        test.complete_filling_table();
        assert!(test.table.is_recipient(Destination::Node(test.table.our_name().clone())));
        assert!(test.table.is_recipient(Destination::Group(test.table.our_name().clone())));
        let close_contact = get_contact(&test.name, TABLE_SIZE - 1, 1);
        assert!(test.table.is_recipient(Destination::Group(close_contact)));
        assert!(!test.table.is_recipient(Destination::Node(close_contact)));
        let far_contact = get_contact(&test.name, 1, 1);
        assert!(!test.table.is_recipient(Destination::Group(far_contact)));
        assert!(!test.table.is_recipient(Destination::Node(far_contact)));
    }

    #[test]
    fn close_nodes() {
        // unchecked - could be merged with one below?
        let mut test = TestEnvironment::new();
        assert_eq!(Some(vec![]), test.table.other_close_nodes(&test.name));
        assert_eq!(Some(vec![test.name]), test.table.close_nodes(&test.name));

        test.partially_fill_table();
        assert_eq!(test.initial_count,
                   test.table.other_close_nodes(&test.name).unwrap().len());

        for i in 0..test.initial_count {
            assert!(test.table
                        .other_close_nodes(&test.name)
                        .unwrap()
                        .into_iter()
                        .filter(|node| *node == get_contact(&test.name, i, 1))
                        .count() > 0);
        }

        test.complete_filling_table();
        assert_eq!(GROUP_SIZE - 1,
                   test.table.other_close_nodes(&test.name).unwrap().len());

        for close_node in test.table.other_close_nodes(&test.name).unwrap() {
            assert!(test.added_names.iter().any(|n| *n == close_node));
        }
    }

    #[test]
    fn close_nodes_and_is_close() {
        let mut tables = HashMap::new();
        for _ in 0..TABLE_SIZE {
            let name = rand::random::<XorName>();
            let table = RoutingTable::new(name.clone());
            let _ = tables.insert(name, table);
        }
        let keys: Vec<XorName> = tables.keys().cloned().collect();
        // Add each node to each other node's routing table.
        for name0 in keys.iter() {
            for name1 in keys.iter() {
                if tables[name0].allow_connection(name1) && tables[name1].need_to_add(name0) {
                    let _ = tables.get_mut(name0).unwrap().add(*name1);
                    let _ = tables.get_mut(name1).unwrap().add(*name0);
                }
            }
        }
        // Check close groups of addresses that are not nodes.
        for _ in 0..1000 {
            let name = rand::random();
            let close_group_size = tables.values().filter(|t| t.is_close(&name)).count();
            assert_eq!(GROUP_SIZE, close_group_size);
        }
        // Check close groups of the nodes' addresses.
        for name in keys {
            let close_group: Vec<_> = tables.values()
                                            .filter(|t| t.is_close(&name))
                                            .map(|t| t.our_name())
                                            .cloned()
                                            .sorted_by(&mut *make_sort_predicate(name.clone()));
            assert_eq!(GROUP_SIZE, close_group.len());
            let other_close_nodes = tables[&name].other_close_nodes(&name).unwrap();
            // The node itself is not in `other_close_nodes`, but it is in `close_group`:
            assert_eq!(close_group[1..], other_close_nodes[..]);
            assert_eq!(close_group, tables[&name].close_nodes(&name).unwrap());
            for close_name in other_close_nodes {
                if tables[&close_name].is_close(&name) {
                    assert_eq!(close_group, tables[&close_name].close_nodes(&name).unwrap());
                } else {
                    assert_eq!(None, tables[&close_name].close_nodes(&name));
                }
            }
        }
    }

    #[test]
    fn add_check_close_group_test() {
        // unchecked - could be merged with one above?
        let num_of_tables = 50usize;
        let mut tables = create_random_routing_tables(num_of_tables);
        let mut addresses: Vec<XorName> = Vec::with_capacity(num_of_tables);

        for i in 0..num_of_tables {
            addresses.push(tables[i].our_name().clone());
            for j in 0..num_of_tables {
                let name = tables[j].our_name().clone();
                // TODO: Ask need_to_add first?
                let _ = tables[i].add(name);
            }
        }
        for it in tables.iter() {
            addresses.sort_by(&mut *make_sort_predicate(it.our_name().clone()));
            assert_eq!(it.other_close_nodes(it.our_name()).unwrap()[..],
                       addresses[1..GROUP_SIZE]);
        }
    }

    #[test]
    fn churn_test() {
        // unchecked - purpose?
        let network_len = 200usize;
        let nodes_to_remove = 20usize;

        let mut tables = create_random_routing_tables(network_len);
        let mut addresses: Vec<XorName> = Vec::with_capacity(network_len);

        for i in 0..tables.len() {
            addresses.push(tables[i].our_name().clone());
            for j in 0..tables.len() {
                let name = tables[j].our_name().clone();
                let _ = tables[i].add(name);
            }
        }

        // now remove nodes
        let mut drop_vec: Vec<XorName> = Vec::with_capacity(nodes_to_remove);
        for i in 0..nodes_to_remove {
            drop_vec.push(addresses[i]);
        }

        tables.truncate(nodes_to_remove);

        for i in 0..tables.len() {
            for j in 0..drop_vec.len() {
                let _ = tables[i].remove(&drop_vec[j]).is_some();
            }
        }
        // remove IDs too
        addresses.truncate(nodes_to_remove);

        for i in 0..tables.len() {
            addresses.sort_by(&mut *make_sort_predicate(tables[i].our_name().clone()));
            let group = tables[i].other_close_nodes(tables[i].our_name()).unwrap();
            assert_eq!(group.len(), cmp::min(GROUP_SIZE - 1, tables[i].len()));
        }
    }

    #[test]
    fn target_nodes_group_test() {
        // unchecked - purpose?
        let network_len = 100usize;

        let mut tables = create_random_routing_tables(network_len);
        let mut addresses: Vec<XorName> = Vec::with_capacity(network_len);

        for i in 0..tables.len() {
            addresses.push(tables[i].our_name().clone());
            for j in 0..tables.len() {
                let name = tables[j].our_name().clone();
                let _ = tables[i].add(name);
            }
        }

        let mut tested_close_target = false;
        for i in 0..tables.len() {
            addresses.sort_by(&mut *make_sort_predicate(tables[i].our_name().clone()));
            // if target is in close group return the whole close group excluding target
            for j in 1..GROUP_SIZE {
                if tables[i].is_close(&addresses[j]) {
                    let dst = Destination::Group(addresses[j]);
                    let far_name = get_contact(&tables[i].our_name(), 0, 255);
                    assert!(tables[i].target_nodes(dst, &far_name, 1).is_empty());
                    let target_close_group = tables[i].target_nodes(dst, &far_name, 0);
                    assert_eq!(GROUP_SIZE - 1, target_close_group.len());
                    // TODO: Reconsider re-swarm prevention and enable or delete this.
                    // for close_node in target_close_group {
                    //     assert!(tables[i].target_nodes(dst, &close_node, 0).is_empty());
                    // }
                    tested_close_target = true;
                }
            }
        }
        assert!(tested_close_target, "No node in the sample was close.");
    }

    #[test]
    fn trivial_functions_test() {
        // unchecked - but also check has_node function
        let mut test = TestEnvironment::new();
        assert_eq!(None, test.table.find(|_| true));
        assert_eq!(0, test.table.len());
        assert_eq!(0, test.table.furthest_close_bucket());

        // Check on partially filled the table
        test.partially_fill_table();
        let contact = rand::random();
        assert!(!test.table.contains(&contact));
        assert!(test.table.add(contact).is_some());
        assert!(test.table.contains(&contact));
        assert_eq!(Some(&contact), test.table.find(|c| c == &&contact));

        // Check on fully filled the table
        assert!(test.table.remove(&contact).is_some());
        assert!(!test.table.contains(&contact));
        test.complete_filling_table();
        assert!(test.table.remove(&get_contact(&test.name, 0, 1)).is_some());
        assert!(test.table.add(contact).is_some());
        assert!(test.table.contains(&contact));
        assert_eq!(TABLE_SIZE - GROUP_SIZE, test.table.furthest_close_bucket());
    }

    #[test]
    fn bucket_index() {
        // Set our name for routing table to max possible value (in binary, all `1`s)
        let our_name = XorName::new([255u8; xor_name::XOR_NAME_LEN]);
        let routing_table = RoutingTable::new(our_name);

        // Iterate through each u8 element of a target name identical to ours and set it to each
        // possible value for u8 other than 255 (since that which would a target name identical to
        // our name)
        for index in 0..xor_name::XOR_NAME_LEN {
            let mut array = [255u8; xor_name::XOR_NAME_LEN];
            for modified_element in 0..255u8 {
                array[index] = modified_element;
                let target_name = XorName::new(array);
                // `index` is equivalent to common leading bytes, so the common leading bits (CLBs)
                // is `index` * 8 plus some value for `modified_element`.  Where
                // 0 <= modified_element < 128, the first bit is different so CLBs is 0, and for
                // 128 <= modified_element < 192, the second bit is different, so CLBs is 1, and so
                // on.
                let expected_bucket_index = (index * 8) +
                                            match modified_element {
                    0...127 => 0,
                    128...191 => 1,
                    192...223 => 2,
                    224...239 => 3,
                    240...247 => 4,
                    248...251 => 5,
                    252 | 253 => 6,
                    254 => 7,
                    _ => unreachable!(),
                };
                if expected_bucket_index != routing_table.bucket_index(&target_name) {
                    let as_binary = |name: &XorName| -> String {
                        let mut name_as_binary = String::new();
                        for i in name.0.iter() {
                            name_as_binary.push_str(&format!("{:08b}", i));
                        }
                        name_as_binary
                    };
                    println!("us:   {}", as_binary(&our_name));
                    println!("them: {}", as_binary(&target_name));
                    println!("index:                 {}", index);
                    println!("modified_element:      {}", modified_element);
                    println!("expected bucket_index: {}", expected_bucket_index);
                    println!("actual bucket_index:   {}",
                             routing_table.bucket_index(&target_name));
                }
                assert_eq!(expected_bucket_index,
                           routing_table.bucket_index(&target_name));
            }
        }

        // Check the bucket index of our own name is 512
        assert_eq!(::xor_name::XOR_NAME_LEN * 8,
                   routing_table.bucket_index(&our_name));
    }

    #[test]
    fn allow_connection() {
        let mut test = TestEnvironment::new();

        assert!(test.table.allow_connection(&rand::random()));
        assert!(!test.table.allow_connection(&test.name));

        // Fill the first buckets with [GROUP_SIZE - 1, GROUP_SIZE - 1, GROUP_SIZE, GROUP_SIZE, 1]
        // elements
        for i in 0..(GROUP_SIZE - 1) {
            let contact = get_contact(&test.name, 0, i as u8);
            assert!(test.table.add(contact).is_some());
        }
        for i in 0..(GROUP_SIZE - 1) {
            let contact = get_contact(&test.name, 1, i as u8);
            assert!(test.table.add(contact).is_some());
        }
        for i in 0..GROUP_SIZE {
            let contact = get_contact(&test.name, 2, i as u8);
            assert!(test.table.add(contact).is_some());
        }
        for i in 0..GROUP_SIZE {
            let contact = get_contact(&test.name, 3, i as u8);
            assert!(test.table.add(contact).is_some());
        }
        let contact = get_contact(&test.name, 4, 0);
        assert!(test.table.add(contact).is_some());

        let name = get_contact(&test.name, 2, 1);
        assert!(!test.table.is_close(&name));
        assert!(!test.table.is_close_to_bucket_of(&name));
        assert!(test.table.allow_connection(&name)); // Already connected

        let name = get_contact(&test.name, 2, 255);
        assert!(!test.table.is_close(&name));
        assert!(!test.table.is_close_to_bucket_of(&name));
        assert!(!test.table.allow_connection(&name)); // Bucket 2 has GROUP_SIZE entries.

        let name = get_contact(&test.name, 3, 99);
        assert!(!test.table.is_close(&name));
        assert!(test.table.is_close(&name.with_flipped_bit(3).unwrap()));
        assert!(test.table.is_close_to_bucket_of(&name)); // Close to the 3rd bucket of name.
        assert!(test.table.allow_connection(&name));

        let name = test.name.with_flipped_bit(2).unwrap().with_flipped_bit(3).unwrap();
        assert!(!test.table.is_close(&name));
        assert!(!test.table.is_close_to_bucket_of(&name));
        assert!(test.table.allow_connection(&name)); // Would be closest entry in bucket 2.

        let name = test.name.with_flipped_bit(0).unwrap().with_flipped_bit(1).unwrap();
        assert!(!test.table.is_close(&name));
        assert!(test.table.is_close(&name.with_flipped_bit(1).unwrap()));
        assert!(test.table.is_close_to_bucket_of(&name)); // Close to the 1st bucket of name.
        assert!(test.table.allow_connection(&name));
    }
}
