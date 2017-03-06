// Copyright 2015 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under (1) the MaidSafe.net Commercial License,
// version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
// licence you accepted on initial access to the Software (the "Licences").
//
// By contributing code to the SAFE Network Software, or to this project generally, you agree to be
// bound by the terms of the MaidSafe Contributor Agreement.  This, along with the Licenses can be
// found in the root directory of this project at LICENSE, COPYING and CONTRIBUTOR.
//
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.
//
// Please review the Licences for the specific language governing permissions and limitations
// relating to use of the SAFE Network Software.

#![doc(html_logo_url =
           "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
       html_favicon_url = "https://maidsafe.net/img/favicon.ico",
       html_root_url = "https://docs.rs/kademlia_routing_table")]

// For explanation of lint checks, run `rustc -W help` or see
// https://github.com/maidsafe/QA/blob/master/Documentation/Rust%20Lint%20Checks.md
#![forbid(bad_style, exceeding_bitshifts, mutable_transmutes, no_mangle_const_items,
          unknown_crate_types, warnings)]
#![deny(deprecated, improper_ctypes, missing_docs,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unsafe_code, unused, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused_extern_crates, unused_import_braces,
        unused_qualifications, unused_results)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
         missing_debug_implementations, variant_size_differences)]

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
//! It also provides methods to decide which other nodes to connect to, depending on a parameter
//! `bucket_size` (see below).
//!
//!
//! # Addresses and distance functions
//!
//! Nodes in the network are addressed with a [`Xorable`][2] type, an unsigned integer with `B`
//! bits. The *[XOR][3] distance* between two nodes with addresses `x` and `y` is `x ^ y`. This
//! [distance function][4] has the property that no two points ever have the same distance from a
//! given point, i. e. if `x ^ y == x ^ z`, then `y == z`. This property allows us to define the
//! `k`-*close group* of an address as the `k` closest nodes to that address, guaranteeing that the
//! close group will always have exactly `k` members (unless, of course, the whole network has less
//! than `k` nodes).
//!
//! [2]: trait.Xorable.html
//! [3]: https://en.wikipedia.org/wiki/Exclusive_or#Bitwise_operation
//! [4]: https://en.wikipedia.org/wiki/Metric_%28mathematics%29
//!
//! The routing table is associated with a node with some name `x`, and manages a number of
//! contacts to other nodes, sorting them into up to `B` *buckets*, depending on their XOR
//! distance from `x`:
//!
//! * If 2<sup>`B`</sup> > `x ^ y` >= 2<sup>`B - 1`</sup>, then y is in bucket 0.
//! * If 2<sup>`B - 1`</sup> > `x ^ y` >= 2<sup>`B - 2`</sup>, then y is in bucket 1.
//! * If 2<sup>`B - 2`</sup> > `x ^ y` >= 2<sup>`B - 3`</sup>, then y is in bucket 2.
//! * ...
//! * If 2 > `x ^ y` >= 1, then y is in bucket `B - 1`.
//!
//! Equivalently, `y` is in bucket `n` if the longest common prefix of `x` and `y` has length `n`,
//! i. e. the first binary digit in which `x` and `y` disagree is the `(n + 1)`-th one. We call the
//! length of the remainder, without the common prefix, the *bucket distance* of `x` and `y`. Hence
//! `x` and `y` have bucket distance `B - n` if and only if `y` belongs in bucket number `n`.
//!
//! The bucket distance is coarser than the XOR distance: Whenever the bucket distance from `y` to
//! `x` is less than the bucket distance from `z` to `x`, then `y ^ x < z ^ x`. But not vice-versa:
//! Often `y ^ x < z ^ x`, even if the bucket distances are equal. The XOR distance ranges from 0
//! to 2<sup>`B`</sup> (exclusive), while the bucket distance ranges from 0 to `B` (inclusive).
//!
//!
//! # Guarantees
//!
//! The routing table provides functions to decide, for a message with a given destination, which
//! nodes in the table to pass the message on to, so that it is guaranteed that:
//!
//! * If the destination is the address of a node, the message will reach that node after at most
//!   `B - 1` hops.
//! * Otherwise, if the destination is a `k`-close group with `k <= bucket_size`, the message will
//!   reach every member of the `k`-close group of the destination address, i. e. all `k` nodes in
//!   the network that are XOR-closest to that address, and each node knows whether it belongs to
//!   that group.
//! * Each node in a given address' close group is connected to each other node in that group. In
//!   particular, every node is connected to its own close group.
//! * The number of total hop messages created for each message is at most `B`.
//! * For each node there are at most `B * bucket_size` other nodes in the network that would
//!   accept a connection, at any point in time. All other nodes do not need to disclose their IP
//!   address.
//! * There are `bucket_size` different paths along which a message can be sent, to provide
//!   redundancy.
//!
//! However, to be able to make these guarantees, the routing table must be filled with
//! sufficiently many contacts. Specifically, the following invariant must be ensured:
//!
//! > Whenever a bucket `n` has fewer than `bucket_size` entries, it contains *all* nodes in the
//! > network with bucket distance `B - n`.
//!
//! The user of this crate therefore needs to make sure that whenever a node joins or leaves, all
//! affected nodes in the network update their routing tables accordingly.
//!
//!
//! # Resilience against malfunctioning nodes
//!
//! The sender may choose to send a message via up to `bucket_size` distinct paths to provide
//! redundancy against malfunctioning hop nodes. These paths are likely, but not guaranteed, to be
//! disjoint.
//!
//! The concept of close groups exists to provide resilience even against failures of the source or
//! destination itself: If every member of a group tries to send the same message, it will arrive
//! even if some members fail. And if a message is sent to a whole group, it will arrive in most,
//! even if some of them malfunction.
//!
//! Close groups can thus be used as inherently redundant authorities in the network that messages
//! can be sent to and received from, using a consensus algorithm: A message from a group authority
//! is considered to be legitimate, if a majority of group members have sent a message with the same
//! content.

extern crate itertools;

mod contact_info;
mod result;
mod xorable;

pub use contact_info::ContactInfo;

use itertools::*;
pub use result::{AddedNodeDetails, DroppedNodeDetails};
use std::{cmp, iter, slice};
pub use xorable::Xorable;

type SliceFn<T> = fn(&Vec<T>) -> slice::Iter<T>;

/// Immutable iterator over the entries of a `RoutingTable`.
pub struct Iter<'a, T: 'a> {
    inner: iter::FlatMap<iter::Rev<slice::Iter<'a, Vec<T>>>, slice::Iter<'a, T>, SliceFn<T>>,
}

impl<'a, T> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}


/// A message destination.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Destination<N> {
    /// The `k`-group of the given address. The message should reach the `k` closest nodes.
    Group(N, usize),
    /// The individual node at the given address. The message should reach exactly one node.
    Node(N),
}

impl<N> Destination<N> {
    /// Returns the name of the destination, i. e. the node or group address.
    pub fn name(&self) -> &N {
        match *self {
            Destination::Group(ref name, _) |
            Destination::Node(ref name) => name,
        }
    }

    /// Returns `true` if the destination os a group, and `false` if it is an individual node.
    pub fn is_group(&self) -> bool {
        match *self {
            Destination::Group(_, _) => true,
            Destination::Node(_) => false,
        }
    }
}


/// A routing table to manage contacts for a node.
///
/// It maintains a list of `T::Name`s representing connected peer nodes, and provides algorithms for
/// routing messages.
///
/// See the [crate documentation](index.html) for details.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RoutingTable<T: ContactInfo> {
    /// The buckets, by bucket index. Each bucket is sorted by ascending distance from us.
    buckets: Vec<Vec<T>>,
    /// This nodes' own contact info.
    our_info: T,
    /// The minimum bucket size.
    bucket_size: usize,
    /// The bucket size above which entries are considered undesirable.
    max_bucket_size: usize,
}

impl<T> RoutingTable<T>
    where T: ContactInfo,
          T::Name: PartialEq + Xorable
{
    /// Creates a new routing table for the node with the given info.
    ///
    /// `bucket_size` specifies the minimum number of bucket entries: Whenever a new node joins the
    /// network which belongs to a bucket with `< bucket_size` entries, it _must_ be added to that
    /// bucket. This guarantees that all nodes know which `k`-groups they belong to, for each
    /// `k <= bucket_size`.
    ///
    /// In excess of `bucket_size`, `extra_entries` are considered desired in each bucket. After
    /// that, additional entries are considered unneeded: If both sides agree, they should
    /// disconnect.
    pub fn new(our_info: T, bucket_size: usize, extra_entries: usize) -> Self {
        RoutingTable {
            buckets: vec![],
            our_info: our_info,
            bucket_size: bucket_size,
            max_bucket_size: bucket_size + extra_entries,
        }
    }

    /// Adds a contact to the routing table, or updates it.
    ///
    /// Returns `None` if the contact already existed or was denied (see `allow_connection`).
    /// Otherwise it returns `AddedNodeDetails`.
    pub fn add(&mut self, info: T) -> Option<AddedNodeDetails<T>> {
        match self.search(info.name()) {
            (bucket_index, Ok(i)) => {
                self.buckets[bucket_index][i] = info;
                None
            }
            (bucket_index, Err(i)) => {
                if !self.allow_connection(info.name()) {
                    return None;
                }
                if self.buckets.len() <= bucket_index {
                    self.buckets.resize(bucket_index + 1, vec![]);
                }
                let must_notify = if self.buckets[bucket_index].len() < self.bucket_size {
                    self.buckets
                        .iter()
                        .skip(bucket_index + 1)
                        .flat_map(|bucket| bucket.iter().cloned())
                        .collect()
                } else {
                    vec![]
                };

                let common_groups = self.is_in_any_close_group_with(bucket_index, self.bucket_size);

                self.buckets[bucket_index].insert(i, info);

                let unneeded = if common_groups {
                    vec![]
                } else {
                    self.buckets[bucket_index]
                        .iter()
                        .skip(self.max_bucket_size)
                        .cloned()
                        .collect()
                };

                Some(AddedNodeDetails {
                         must_notify: must_notify,
                         unneeded: unneeded,
                     })
            }
        }
    }

    /// Returns whether it is desirable to add the given contact to the routing table.
    ///
    /// Returns `false` if adding the contact in question would not bring the routing table closer
    /// to satisfy the invariant. It returns `true` if and only if the new contact would be among
    /// the `bucket_size` closest nodes in its bucket.
    pub fn need_to_add(&self, name: &T::Name) -> bool {
        if name == self.our_name() {
            return false;
        }
        match self.search(name) {
            (_, Ok(_)) => false,                 // They already are in our routing table.
            (_, Err(i)) => i < self.bucket_size, // We need to add them if the bucket is not full.
        }
    }

    /// Removes `name` from routing table and returns `true` if we no longer need to stay connected.
    ///
    /// We should remain connected iff the entry is among the `self.max_bucket_size` closest nodes
    /// in its bucket or if we have any close groups in common with it.
    pub fn remove_if_unneeded(&mut self, name: &T::Name) -> bool {
        if name == self.our_name() {
            return false;
        }

        if let (bucket, Ok(i)) = self.search(name) {
            if i >= self.max_bucket_size &&
               !self.is_in_any_close_group_with(bucket, self.bucket_size) {
                return self.remove(name).is_some();
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
    /// * we are in the `bucket_size`-group of one of their bucket addresses.
    pub fn allow_connection(&self, name: &T::Name) -> bool {
        if name == self.our_name() {
            return false;
        }
        match self.search(name) {
            (_, Ok(_)) => true,
            (_, Err(i)) => i < self.bucket_size || self.is_close_to_bucket_of(name),
        }
    }

    /// Removes the contact from the table.
    ///
    /// If no entry with that name is found, `None` is returned. Otherwise, the entry is removed
    /// from the routing table and `DroppedNodeDetails` are returned.
    pub fn remove(&mut self, name: &T::Name) -> Option<DroppedNodeDetails> {
        if let (bucket_index, Ok(i)) = self.search(name) {
            let incomplete_bucket = if self.buckets[bucket_index].len() == self.bucket_size {
                Some(bucket_index)
            } else {
                None
            };
            let _ = self.buckets[bucket_index].remove(i);
            while self.buckets.last().map_or(false, Vec::is_empty) {
                let _ = self.buckets.pop();
            }
            Some(DroppedNodeDetails { incomplete_bucket: incomplete_bucket })
        } else {
            None
        }
    }

    /// Returns a collection of nodes to which a message should be sent onwards.
    ///
    /// If the message is addressed at a group we are a member of, this returns all other members of
    /// that group.
    ///
    /// If the message is addressed at an individual node that is directly connected to us, this
    /// returns the destination node.
    ///
    /// If we are the individual recipient, it also returns an empty collection.
    ///
    /// Otherwise it returns the `n`-th closest node to the target if route is `n`.
    ///
    /// # Arguments
    ///
    /// * `dst` -   The destination of the message.
    /// * `hop` -   The name of the node that relayed the message to us, or ourselves if we are the
    ///             original sender.
    /// * `route` - The route number.
    pub fn target_nodes(&self, dst: Destination<T::Name>, hop: &T::Name, route: usize) -> Vec<T> {
        let target = match dst {
            Destination::Group(ref target, group_size) => {
                if let Some(mut group) = self.other_close_nodes(target, group_size) {
                    group.retain(|t| t.name() != hop);
                    return group;
                }
                target
            }
            Destination::Node(ref target) => {
                if target == self.our_name() {
                    return vec![];
                } else if let Some(target_contact) = self.get(target) {
                    return vec![target_contact.clone()];
                } else if self.is_close(target, self.bucket_size) {
                    return self.closest_nodes_to(target, self.bucket_size - 1, false);
                }
                target
            }
        };
        self.closest_nodes_to(target, route + 2, false)
            .into_iter()
            .filter(|node| node.name() != hop)
            .skip(route)
            .take(1)
            .collect()
    }

    /// Returns whether the message is addressed to this node.
    ///
    /// If this returns `true`, this node is either the single recipient of the message, or a
    /// member of the group authority to which it is addressed. It therefore needs to handle the
    /// message.
    pub fn is_recipient(&self, dst: Destination<T::Name>) -> bool {
        match dst {
            Destination::Node(ref target) => target == self.our_name(),
            Destination::Group(ref target, group_size) => self.is_close(target, group_size),
        }
    }

    /// Returns the other members of `name`'s close group, or `None` if we are not a member of it.
    pub fn other_close_nodes(&self, name: &T::Name, group_size: usize) -> Option<Vec<T>> {
        if self.is_close(name, group_size) {
            Some(self.closest_nodes_to(name, group_size - 1, false))
        } else {
            None
        }
    }

    /// Returns the members of `name`'s close group, or `None` if we are not a member of it.
    pub fn close_nodes(&self, name: &T::Name, group_size: usize) -> Option<Vec<T>> {
        if self.is_close(name, group_size) {
            Some(self.closest_nodes_to(name, group_size, true))
        } else {
            None
        }
    }

    /// Returns `true` if there are fewer than `GROUP_SIZE` nodes in our routing table that are
    /// closer to `name` than we are.
    ///
    /// In other words, it returns `true` whenever we cannot rule out that we might be among the
    /// `group_size` closest nodes to `name`.
    ///
    /// If the routing table is filled in such a way that each bucket contains `group_size`
    /// elements unless there aren't enough such nodes in the network, then this criterion is
    /// actually sufficient! In that case, `true` is returned if and only if we are among the
    /// `group_size` closest node to `name` in the network.
    pub fn is_close(&self, name: &T::Name, group_size: usize) -> bool {
        let mut count = 0;
        for (bucket_index, bucket) in self.buckets.iter().enumerate() {
            if self.our_name().differs_in_bit(name, bucket_index) {
                count += bucket.len();
                if count >= group_size {
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

    /// Removes all entries from the routing table.
    pub fn clear(&mut self) {
        self.buckets.clear();
    }

    /// Returns the name of the node this routing table is for.
    pub fn our_name(&self) -> &T::Name {
        self.our_info.name()
    }

    /// Returns whether the node with this `name` is in the routing table.
    pub fn contains(&self, name: &T::Name) -> bool {
        self.search(name).1.is_ok()
    }

    /// Returns the bucket size constant, i. e. the minimum number of entries that need to be added
    /// to each bucket, if possible.
    pub fn bucket_size(&self) -> usize {
        self.bucket_size
    }

    /// Returns the maximum bucket size constant, i. e. the number of entries above which bucket
    /// entries are considered unneeded.
    pub fn max_bucket_size(&self) -> usize {
        self.max_bucket_size
    }

    /// Returns the contact associated with the given name.
    pub fn get(&self, name: &T::Name) -> Option<&T> {
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

    /// Returns an iterator over all entries, sorted by distance.
    pub fn iter(&self) -> Iter<T> {
        #[cfg_attr(feature="cargo-clippy", allow(ptr_arg))] // Need to use `&Vec<S>` for `flat_map`.
        fn vec_iter<S>(vec: &Vec<S>) -> slice::Iter<S> {
            vec.iter()
        };
        // `flat_map(Vec::iter)` or `map(Vec::as_slice).flat_map(<[T]>::iter)` don't seem to work.
        Iter {
            inner: self.buckets
                .iter()
                .rev()
                .flat_map(vec_iter),
        }
    }

    /// Returns the `n` nodes in our routing table that are closest to `target`.
    ///
    /// Returns fewer than `n` nodes if the routing table doesn't have enough entries. If
    /// `ourselves` is `true`, this could potentially include ourselves. Otherwise, our own name is
    /// skipped.
    pub fn closest_nodes_to(&self, target: &T::Name, n: usize, ourselves: bool) -> Vec<T> {
        let cmp = |a: &&T, b: &&T| target.cmp_distance(a.name(), b.name());
        // If we disagree with target in a bit, that bit's bucket contains contacts that are closer
        // to the target than we are. The lower the bucket index, the closer it is:
        let closer_buckets_iter = self.buckets
            .iter()
            .enumerate()
            .filter(|&(bit, _)| self.our_name().differs_in_bit(target, bit))
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
            .filter(|&(bit, _)| !self.our_name().differs_in_bit(target, bit))
            .flat_map(|(_, b)| b.iter().sorted_by(&cmp).into_iter());
        // Chaining these iterators puts the buckets in the right order, with ascending distance
        // from the target. Finally, we need to sort each bucket's contents and take n:
        closer_buckets_iter.chain(ourselves_iter)
            .chain(further_buckets_iter)
            .take(n)
            .cloned()
            .collect()
    }

    /// Returns whether we share any close groups with the nodes in the given bucket.
    ///
    /// If the bucket is not full or we have less than `group_size - 1` contacts with a greater
    /// bucket index, then for _every_ node in that bucket there exists an address which both that
    /// node and our own node are in the close group of. In that case, the result is `true`.
    ///
    /// Otherwise, no such address exists and `false` is returned.
    pub fn is_in_any_close_group_with(&self, bucket_index: usize, group_size: usize) -> bool {
        if self.buckets.get(bucket_index).map_or(0, Vec::len) < group_size {
            return true;
        }
        let mut count = 0;
        for bucket in self.buckets.iter().skip(bucket_index + 1) {
            count += bucket.len();
            if count >= group_size - 1 {
                return false;
            }
        }
        true
    }

    /// Returns whether we are `bucket_size`-close to one of `name`'s bucket addresses or to `name`
    /// itself.
    fn is_close_to_bucket_of(&self, name: &T::Name) -> bool {
        // We are close to `name` if the buckets where `name` disagrees with us have less than
        // `bucket_size` entries in total. Therefore we are close to a bucket address of `name`, if
        // removing the largest such bucket gets us below `bucket_size`.
        let mut closer_contacts: usize = 0;
        let mut largest_bucket: usize = 0;
        for (bit, bucket) in self.buckets.iter().enumerate() {
            if self.our_name().differs_in_bit(name, bit) {
                largest_bucket = cmp::max(largest_bucket, bucket.len());
                closer_contacts += bucket.len();
                if closer_contacts >= largest_bucket + self.bucket_size {
                    return false;
                }
            }
        }
        true
    }

    /// This is equivalent to the common leading bits of `self.our_name` and `name` where "leading
    /// bits" means the most significant bits.
    fn bucket_index(&self, name: &T::Name) -> usize {
        self.our_name().bucket_index(name)
    }

    /// Searches the routing table for the given name.
    ///
    /// Returns a tuple with the bucket index of `name` as the first entry. The second entry is
    /// `Ok(i)` if the node has index `i` in that bucket, or `Err(i)` if it isn't there yet and `i`
    /// is the index inside the bucket where it would be inserted.
    fn search(&self, name: &T::Name) -> (usize, Result<usize, usize>) {
        let bucket_index = self.bucket_index(name);
        (bucket_index,
         match self.buckets.get(bucket_index) {
             None => Err(0),
             Some(bucket) => {
                 bucket.binary_search_by(|other| self.our_name().cmp_distance(other.name(), name))
             }
         })
    }
}

impl<T: ContactInfo> RoutingTable<T>
    where T::Name: ContactInfo + Clone
{
    /// Converts all entries to `T::Name`s and returns a new `RoutingTable` with them.
    pub fn to_names(&self) -> RoutingTable<T::Name> {
        RoutingTable {
            buckets: self.buckets
                .iter()
                .map(|bucket| bucket.iter().map(|node| node.name().clone()).collect())
                .collect(),
            our_info: self.our_info.name().clone(),
            bucket_size: self.bucket_size,
            max_bucket_size: self.max_bucket_size,
        }
    }
}


#[cfg(test)]
mod test {
    use super::*;

    fn extend_table<'a, T, I>(table: &mut RoutingTable<T>, entries: I)
        where I: IntoIterator<Item = T>,
              T: ContactInfo + 'a,
              T::Name: PartialEq + Xorable
    {
        for entry in entries {
            let _ = table.add(entry);
        }
    }

    // Since XOR space is symmetric and XORing with the table's own name is an isometry, we choose
    // 0 as the table name in most tests, for simplicity. Then each address _is_ its distance and:
    // 1          belongs in bucket 7
    // 2   and  3 belong  in bucket 6
    // 4   to   7 belong  in bucket 5
    // 8   to  15 belong  in bucket 4
    // 16  to  31 belong  in bucket 3
    // 32  to  63 belong  in bucket 2
    // 64  to 127 belong  in bucket 1
    // 128 to 255 belong  in bucket 0
    #[test]
    fn basic_collection_functionality() {
        let mut table = RoutingTable::new(0u8, 3, 2);
        assert_eq!(3, table.bucket_size());
        assert_eq!(5, table.max_bucket_size());

        assert_eq!(table.len(), 0);
        assert!(table.is_empty());

        // Try with own name - should fail.
        assert!(table.add(0).is_none());
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());

        // Add first contact.
        assert!(table.add(1).is_some());
        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());
        assert!(table.add(1).is_none());
        assert_eq!(table.len(), 1);
        assert!(table.contains(&1));
        assert_eq!(Some(&1), table.get(&1));

        // Add another contact.
        assert!(table.add(5).is_some());
        assert_eq!(table.len(), 2);

        // Remove first contact.
        assert!(table.remove(&1).is_some());
        assert_eq!(table.len(), 1);
        assert!(!table.contains(&1));
        assert!(table.remove(&1).is_none());
        assert_eq!(table.len(), 1);
        assert!(!table.is_empty());

        // Clear the table.
        table.clear();
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
    }

    #[test]
    fn bucket_len() {
        let network = vec![0b10000000, 0b11000000, 0b11100000, 0b00100000, 0b00110000, 0b00000100,
                           0b00001000];
        let mut table = RoutingTable::new(0u8, 2, 1);
        extend_table(&mut table, network);
        assert_eq!(3, table.bucket_len(0));
        assert_eq!(0, table.bucket_len(1));
        assert_eq!(2, table.bucket_len(2));
        assert_eq!(0, table.bucket_len(3));
        assert_eq!(1, table.bucket_len(4));
        assert_eq!(1, table.bucket_len(5));
        assert_eq!(0, table.bucket_len(6));
        assert_eq!(0, table.bucket_len(7));
        assert_eq!(6, table.bucket_count());
    }

    #[test]
    fn add() {
        let network = vec![128, 32, 4];
        let mut table = RoutingTable::new(0u8, 2, 1); // Bucket size 2, max bucket size 3.
        extend_table(&mut table, network);
        // Bucket 2 contains [32]. We will add 33, 48 and 34 to it.
        assert_eq!(None, table.add(32)); // Contact already present.
        // Bucket 2 wasn't full yet: [32]. Notify closer nodes.
        assert_eq!(Some(AddedNodeDetails {
                            must_notify: vec![4],
                            unneeded: vec![],
                        }),
                   table.add(33));
        assert_eq!(Some(AddedNodeDetails {
                            must_notify: vec![], // Bucket 2 is full now.
                            unneeded: vec![],
                        }),
                   table.add(48));
        assert_eq!(Some(AddedNodeDetails {
                            must_notify: vec![], // Bucket 2 is full.
                            unneeded: vec![48], // Bucket 2 is overfull: 48 is furthest from us.
                        }),
                   table.add(34));
    }

    #[test]
    fn need_to_add() {
        let network = vec![128, 32, 33, 4];
        let mut table = RoutingTable::new(0u8, 2, 1); // Bucket size 2, max bucket size 3.
        extend_table(&mut table, network);
        assert!(table.need_to_add(&2)); // Bucket 6 has no entry yet.
        assert!(table.need_to_add(&64)); // Bucket 1 has no entry yet.
        assert!(!table.need_to_add(&128)); // Entry is already present.
        assert!(table.need_to_add(&129)); // Bucket 0 has only one entry.
        assert!(table.need_to_add(&6)); // Bucket 5 has only one entry.
        assert!(!table.need_to_add(&34)); // Bucket 2 has already two entries.
    }

    #[test]
    fn remove_if_unneeded() {
        let mut table = RoutingTable::new(0u8, 2, 1); // Bucket size 2, max bucket size 3.
        assert!(!table.remove_if_unneeded(&0)); // Own name.
        extend_table(&mut table, vec![64, 65, 67]); // Bucket 1 now has `max_bucket_size` entries.
        assert!(!table.remove_if_unneeded(&67));
        assert!(table.add(66).is_some()); // Now bucket 1 has one excess entry.
        assert!(!table.remove_if_unneeded(&67)); // We have a common close group.
        extend_table(&mut table, vec![1, 2]); // No common close group with 67 anymore.
        assert!(!table.remove_if_unneeded(&3)); // Entry doesn't exist.
        assert!(!table.remove_if_unneeded(&66)); // 66 is closer than 67.
        assert!(table.remove_if_unneeded(&67)); // 64 is furthest in bucket 1.
    }

    #[test]
    fn allow_connection() {
        let mut table = RoutingTable::new(0u8, 2, 1); // Bucket size 2, max bucket size 3.
        extend_table(&mut table, vec![64, 66, 67, 32, 4, 5, 6, 1]);
        assert!(!table.allow_connection(&68)); // Bucket 1 is already full.
        assert!(table.allow_connection(&65)); // Closer than other bucket 1 entries.
        assert!(table.allow_connection(&37)); // Bucket 2 is not full.
        assert!(table.allow_connection(&7)); // Common close group. (7 is close to us.)
    }

    #[test]
    fn remove() {
        let mut table = RoutingTable::new(0u8, 2, 1); // Bucket size 2, max bucket size 3.
        extend_table(&mut table, vec![64, 66, 67, 32, 4, 5, 6, 1]);
        assert_eq!(None, table.remove(&100)); // Entry does not exist.
        // `incomplete_bucket` is the bucket number only when we pass from 2 to 1 entries.
        assert_eq!(Some(DroppedNodeDetails { incomplete_bucket: None }),
                   table.remove(&67));
        assert_eq!(Some(DroppedNodeDetails { incomplete_bucket: Some(1) }),
                   table.remove(&66));
        assert_eq!(Some(DroppedNodeDetails { incomplete_bucket: None }),
                   table.remove(&64));
    }

    #[test]
    fn target_nodes() {
        let mut table = RoutingTable::new(0u8, 3, 1); // Bucket size 3, max bucket size 4.
        extend_table(&mut table, vec![64, 66, 67, 68, 32, 4, 5, 1]);
        // If the destination node is known, return it.
        assert_eq!(vec![5], table.target_nodes(Destination::Node(5), &4, 0));
        assert_eq!(vec![64], table.target_nodes(Destination::Node(64), &1, 2));
        assert_eq!(vec![4], table.target_nodes(Destination::Group(4, 2), &5, 0));
        assert_eq!(vec![64],
                   table.target_nodes(Destination::Group(64, 2), &1, 0));
        assert_eq!(vec![66],
                   table.target_nodes(Destination::Group(64, 2), &1, 1));
        assert_eq!(vec![5], table.target_nodes(Destination::Group(5, 2), &1, 0));
        // If the destination is a group we are a member of, return the other members.
        assert_eq!(vec![4, 5],
                   table.target_nodes(Destination::Group(4, 3), &1, 0));
        // If the destination is a node we don't know, return the `route`-th closest contact.
        assert_eq!(vec![64], table.target_nodes(Destination::Node(96), &4, 0));
        assert_eq!(vec![66], table.target_nodes(Destination::Node(96), &4, 1));
        assert_eq!(vec![67], table.target_nodes(Destination::Node(96), &4, 2));
        // If we are the only recipient, return an empty vector.
        assert_eq!(Vec::<u8>::new(),
                   table.target_nodes(Destination::Node(0), &4, 2));
    }

    #[test]
    fn is_recipient_and_is_close() {
        let mut table = RoutingTable::new(0u8, 3, 1); // Bucket size 3, max bucket size 4.
        extend_table(&mut table, vec![64, 66, 67, 68, 32, 4, 5, 1]);
        assert!(table.is_recipient(Destination::Node(0))); // That's us!
        assert!(!table.is_recipient(Destination::Node(1))); // That's someone else.
        // We are a member of these groups.
        assert!(table.is_recipient(Destination::Group(0, 1)));
        assert!(table.is_close(&0, 1));
        assert!(table.is_recipient(Destination::Group(0, 3)));
        assert!(table.is_close(&0, 3));
        assert!(table.is_recipient(Destination::Group(4, 3)));
        assert!(table.is_close(&4, 3));
        // We are not a member of these groups.
        assert!(!table.is_recipient(Destination::Group(64, 3)));
        assert!(!table.is_close(&64, 3));
        assert!(!table.is_recipient(Destination::Group(4, 2)));
        assert!(!table.is_close(&4, 2));
    }

    #[test]
    fn close_nodes_and_other_close_nodes() {
        let mut table = RoutingTable::new(0u8, 3, 1); // Bucket size 3, max bucket size 4.
        extend_table(&mut table, vec![64, 66, 67, 68, 32, 4, 5, 1]);
        // We are a member of these groups.
        assert_eq!(Some(vec![1, 0]), table.close_nodes(&1, 2));
        assert_eq!(Some(vec![1]), table.other_close_nodes(&1, 2));
        assert_eq!(Some(vec![4, 5, 0]), table.close_nodes(&4, 3));
        assert_eq!(Some(vec![4, 5]), table.other_close_nodes(&4, 3));
        assert_eq!(Some(vec![4, 5, 0]), table.close_nodes(&6, 3));
        assert_eq!(Some(vec![4, 5]), table.other_close_nodes(&6, 3));
        // We are not a member of these groups.
        assert_eq!(None, table.close_nodes(&1, 1));
        assert_eq!(None, table.other_close_nodes(&1, 1));
        assert_eq!(None, table.close_nodes(&5, 3)); // 1 is closer to 5 than we are.
        assert_eq!(None, table.other_close_nodes(&5, 3));
        assert_eq!(None, table.close_nodes(&7, 3));
        assert_eq!(None, table.other_close_nodes(&7, 3));
        assert_eq!(None, table.close_nodes(&70, 3));
        assert_eq!(None, table.other_close_nodes(&70, 3));
    }

    #[test]
    fn iter() {
        let mut table = RoutingTable::new(0u8, 3, 1);
        extend_table(&mut table, vec![67, 64, 66, 68, 32, 4, 5, 1]);
        assert_eq!(vec![1, 4, 5, 32, 64, 66, 67, 68],
                   table.iter().cloned().collect::<Vec<_>>());
    }

    #[test]
    fn closest_nodes_to() {
        let mut table = RoutingTable::new(0u8, 3, 1); // Bucket size 3, max bucket size 4.
        extend_table(&mut table, vec![64, 66, 67, 68, 32, 33, 4, 5, 6, 1]);
        assert!(!table.is_in_any_close_group_with(1, 3));
        assert!(!table.is_in_any_close_group_with(2, 2));
        assert!(!table.is_in_any_close_group_with(5, 2));
        assert!(table.is_in_any_close_group_with(2, 3)); // 3-group of 32: [32, 33, 0]
        assert!(table.is_in_any_close_group_with(5, 3)); // 3-group of 1: [1, 0, 5]
    }

    #[test]
    fn is_in_any_close_group_with() {
        let mut table = RoutingTable::new(4u8, 3, 1);
        extend_table(&mut table, vec![1, 2, 3, 5, 6, 7]);
        assert_eq!(vec![1, 2, 3, 4, 5], table.closest_nodes_to(&0, 5, true));
        assert_eq!(vec![1, 2, 3, 5, 6], table.closest_nodes_to(&0, 5, false));
    }
}
