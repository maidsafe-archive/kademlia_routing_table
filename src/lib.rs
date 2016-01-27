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
unused_qualifications, unused_results, variant_size_differences)]
#![allow(box_pointers, fat_ptr_transmutes, missing_copy_implementations,
missing_debug_implementations)]

//! A routing table to manage connections for a node in a [Kademlia][1] distributed hash table.
//!
//! [1]: https://en.wikipedia.org/wiki/Kademlia
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
//! connections to other nodes, sorting them into up to 512 *buckets*, depending on their XOR
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
//! # Guarantees for routing
//!
//! The routing table provides functions to decide, for a message with a given destination, which
//! nodes in the table to pass the message on to, so that it is guaranteed that:
//!
//! * If the destination is the address of a node, the message will reach that node after at most
//!   511 hops.
//! * Otherwise the message will reach every member of the close group of the destination address,
//!   i. e. all `GROUP_SIZE` nodes in the network that are XOR-closest to that address, and each
//!   node knows whether it belongs to that group.
//!
//! However, to be able to make these guarantees, the routing table must be filled with
//! sufficiently many connections. Specifically, for the first property to be true, the first of
//! the following invariants is needed, and for the second property, the second, stronger one, must
//! be ensured:
//!
//! * Each bucket `n` must have an entry if a node with bucket distance `512 - n` exists in the
//!   network.
//! * Whenever a bucket `n` has fewer than `GROUP_SIZE` entries, it contains *all* nodes in the
//!   network with bucket distance `512 - n`.
//!
//! The user of this crate therefore needs to make sure that whenever a node joins or leaves, all
//! affected nodes in the network update their routing tables accordingly.
//!
//!
//! # Resilience against malicious or malfunctioning nodes
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
//! is considered to be legitimate, if at least `QUORUM_SIZE` group members have sent (and
//! cryptographically signed) a message with the same content.

#[macro_use]
extern crate log;

#[macro_use]
#[allow(unused_extern_crates)]
extern crate maidsafe_utilities;

extern crate itertools;
#[cfg(test)]
extern crate rand;
extern crate xor_name;

use itertools::*;
use std::cmp;
use std::fmt;
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
pub const PARALLELISM: usize = 4;

/// A trait for anything that has a `XorName` and can thus be addressed in the network.
///
/// The node information in the routing table is required to implement this.
pub trait HasName {
    /// Returns the `XorName` representing this item's address in the network.
    fn name(&self) -> &XorName;
}

/// A routing table entry representing a node and the connections to that node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInfo<T, U> {
    /// The information identifying the node.
    pub public_id: T,
    /// The connections to the node, e. g. sockets or other kinds of connection handles.
    pub connections: Vec<U>,
    bucket_index: usize,
}

impl<T: PartialEq + HasName + fmt::Debug, U: PartialEq> NodeInfo<T, U> {
    /// Creates a new node entry with the given ID and connections.
    pub fn new(public_id: T, connections: Vec<U>) -> NodeInfo<T, U> {
        NodeInfo {
            public_id: public_id,
            connections: connections,
            bucket_index: 0,
        }
    }

    /// Returns the `XorName` of the peer node.
    pub fn name(&self) -> &XorName {
        self.public_id.name()
    }
}

/// A message destination.
pub enum Destination<'a> {
    /// The close group of the given address. The message should reach `GROUP_SIZE` nodes.
    Group(&'a XorName),
    /// The individual node at the given address. The message should reach exactly one node.
    Node(&'a XorName),
}

/// Specifies the number of times we have already passed on a particular message.
pub enum HopType {
    /// We are the original sender. The message should be sent to `PARALLELISM` contacts.
    OriginalSender,
    /// We have already relayed the given number of copies of this message.
    CopyNr(usize),
}

/// A routing table to manage connections for a node.
///
/// It maintains a list of `NodeInfo`s representing connections to peer nodes, and provides
/// algorithms for routing messages.
///
/// See the [crate documentation](index.html) for details.
pub struct RoutingTable<T, U> {
    nodes: Vec<NodeInfo<T, U>>,
    our_name: XorName,
}

impl<T, U> RoutingTable<T, U>
    where T: PartialEq + HasName + fmt::Debug + Clone,
          U: PartialEq + fmt::Debug + Clone
{
    /// Creates a new routing table for the node with the given name.
    pub fn new(our_name: &XorName) -> RoutingTable<T, U> {
        RoutingTable {
            nodes: vec![],
            our_name: our_name.clone(),
        }
    }

    /// Adds a contact to the routing table, or updates it.
    ///
    /// Returns `None` if the contact already existed. Otherwise it returns a tuple:
    ///
    /// * The list of contacts that need to be notified about the new node: If the bucket was
    ///   already full, that's nobody, but if it wasn't, everyone with a bucket index greater than
    ///   the new nodes' must be notified.
    /// * Whether we are together in any close group with that contact.
    pub fn add_node(&mut self, mut node: NodeInfo<T, U>) -> Option<(Vec<NodeInfo<T, U>>, bool)> {
        if node.name() == &self.our_name {
            return None;
        }
        match self.binary_search(node.name()) {
            Ok(i) => {
                // Node already exists! Update the entry:
                self.nodes[i].connections.extend(node.connections);
                None
            }
            Err(i) => {
                // No existing entry, so set the node's bucket distance and insert it.
                let bucket_index = self.bucket_index(&node.name());
                node.bucket_index = bucket_index;
                let nodes_to_notify = if self.is_bucket_full(bucket_index) {
                    vec!()
                } else {
                    self.nodes
                        .iter()
                        .take_while(|n| n.bucket_index > bucket_index)
                        .cloned()
                        .collect()
                };
                self.nodes.insert(i, node);
                Some((nodes_to_notify, self.is_in_any_close_group_with(bucket_index)))
            }
        }
    }

    /// Adds a connection to an existing entry.
    ///
    /// Should be called after `has_node`. Returns `true` if the given connection was added to an
    /// existing `NodeInfo`, and `false` if no such entry exists.
    pub fn add_connection(&mut self, their_name: &XorName, connection: U) -> bool {
        match self.nodes.iter_mut().find(|node_info| node_info.name() == their_name) {
            Some(mut node_info) => {
                if node_info.connections.iter().any(|elt| *elt == connection) {
                    return false;
                }

                node_info.connections.push(connection);
                true
            }
            None => {
                error!("The NodeInfo should already exist here.");
                false
            }
        }
    }

    /// Returns whether it is desirable to add the given contact to the routing table.
    ///
    /// Returns `false` if adding the contact in question would not bring the routing table closer
    /// to satisfy the invariant. It returns `true` if and only if the new contact would be among
    /// the `GROUP_SIZE` closest nodes in its bucket.
    pub fn want_to_add(&self, their_name: &XorName) -> bool {
        if their_name == &self.our_name {
            return false;
        }
        let i = match self.binary_search(their_name) {
            Ok(_) => return false, // They already are in our routing table.
            Err(i) => i,
        };
        let index = self.bucket_index(their_name);
        self.nodes
            .iter()
            .take(i)
            .filter(|node| node.bucket_index == index)
            .take(GROUP_SIZE)
            .count() < GROUP_SIZE
    }

    /// Returns the current calculated quorum size.
    ///
    /// If it is known that the network has at least `GROUP_SIZE` nodes, this returns the constant
    /// `QUORUM_SIZE`. For networks smaller than that, the quorum might not be reachable, so a
    /// smaller number is computed which represents a strict majority in the current network.
    pub fn dynamic_quorum_size(&self) -> usize {
        let network_size = self.nodes.len() + 1; // Routing table entries plus this node itself.
        if network_size >= GROUP_SIZE {
            QUORUM_SIZE
        } else {
            cmp::max(network_size * QUORUM_SIZE / GROUP_SIZE,
                     network_size / 2 + 1)
        }
    }

    /// Returns the bucket index of the furthest close node.
    pub fn furthest_close_bucket(&self) -> usize {
        match self.nodes.iter().take(GROUP_SIZE - 1).last() {
            None => xor_name::XOR_NAME_BITS - 1,
            Some(node) => self.bucket_index(node.name()),
        }
    }

    /// Removes the contact from the table.
    ///
    /// Returns the dropped node if the contact was present in the table.
    #[cfg(test)]
    fn drop_node(&mut self, node_to_drop: &XorName) -> Option<NodeInfo<T, U>> {
        self.binary_search(node_to_drop).ok().map(|i| self.nodes.remove(i))
    }

    /// This should be called when a connection has dropped.
    ///
    /// If no entry with that connection is found, `None` is returned. If the affected entry still
    /// has connections left after removing this one, the entry remains in the table and the result
    /// is also `None`. Otherwise, the entry is removed from the routing table and a tuple with
    /// three components is returned:
    ///
    /// * The name of the dropped node.
    /// * `Some(i)` if the entry has been removed from a full bucket with index `i`, indicating that
    ///   an attempt to refill that bucket has to be made.
    /// * Whether we were together in any close group with that contact.
    pub fn drop_connection(&mut self, lost_connection: &U)
            -> Option<(XorName, Option<usize>, bool)> {
        let remove_connection = |node_info: &mut NodeInfo<T, U>| {
            if let Some(index) = node_info.connections
                                          .iter()
                                          .position(|connection| connection == lost_connection) {
                let _ = node_info.connections.remove(index);
                true
            } else {
                false
            }
        };
        if let Some(node_index) = self.nodes.iter_mut().position(remove_connection) {
            if self.nodes[node_index].connections.is_empty() {
                let bucket_index = self.nodes[node_index].bucket_index;
                let opt_bucket_index = if self.is_bucket_full(bucket_index) {
                    Some(bucket_index)
                } else {
                    None
                };
                let common_groups = self.is_in_any_close_group_with(bucket_index);
                let name = self.nodes.remove(node_index).name().clone();
                return Some((name, opt_bucket_index, common_groups));
            }
        }
        None
    }

    /// Returns `true` if the bucket with the given index has at least `GROUP_SIZE` entries.
    fn is_bucket_full(&self, index: usize) -> bool {
        self.nodes.iter().filter(|n| n.bucket_index == index).take(GROUP_SIZE).count() == GROUP_SIZE
    }

    /// Returns the `n` nodes in our routing table that are closest to `target`.
    ///
    /// Returns fewer than `n` nodes if the routing table doesn't have enough entries.
    pub fn closest_nodes_to(&self, target: &XorName, n: usize) -> Vec<NodeInfo<T, U>> {
        // TODO: Sorting *all* the nodes to get the n closest ones is inefficient!
        let mut result = self.nodes
                             .iter()
                             .cloned()
                             .sorted_by(|a, b| target.cmp_distance(&a.name(), &b.name()));
        result.truncate(n);
        result
    }

    /// Returns whether we are close to one of `name`'s bucket addresses or to `name` itself.
    pub fn is_close_to_bucket_of(&self, name: &XorName) -> bool {
        // We are close to `name` if all buckets where `name` disagrees with us have less than
        // GROUP_SIZE entries in total. Therefore we are close to a bucket address of `name`, if
        // removing the largest such bucket gets us below GROUP_SIZE.
        let mut closer_contacts: usize = 0;
        let mut largest_bucket: usize = 0;
        let mut current_bucket: usize = 0;
        let mut current_bucket_index: usize = 0;
        for node in self.nodes.iter() {
            let i = node.bucket_index;
            if (self.our_name().0[i / 8] ^ name.0[i / 8]) & (1 << (7 - i % 8)) != 0 {
                if i != current_bucket_index {
                    largest_bucket = cmp::max(largest_bucket, current_bucket);
                    current_bucket = 0;
                    current_bucket_index = i;
                    if closer_contacts >= largest_bucket + GROUP_SIZE {
                        return false;
                    }
                }
                closer_contacts += 1;
                current_bucket += 1;
            }
        }
        closer_contacts < largest_bucket + GROUP_SIZE
    }

    /// Returns a collection of nodes to which a message should be sent onwards.
    ///
    /// If the message is addressed at a group and we are a member of that group, this returns all
    /// other members of that group once, and an empty collection for all further copies.
    ///
    /// If the message is addressed at an individual node that is directly connected to us, this
    /// returns the destination node once, and an empty collection for all further copies.
    ///
    /// If none of the above is the case and we are the original sender, it returns the
    /// `PARALLELISM` closest nodes to the target.
    ///
    /// Otherwise it returns the `n`-th closest node to the target if this is the `n`-th copy of
    /// the message we are relaying.
    pub fn target_nodes(&self, dst: Destination, hop_type: HopType) -> Vec<NodeInfo<T, U>> {
        let target = match dst {
            Destination::Group(target) => {
                if self.is_close(target) {
                    return match hop_type {
                        HopType::OriginalSender | HopType::CopyNr(0) => {
                            self.closest_nodes_to(target, GROUP_SIZE - 1)
                        }
                        HopType::CopyNr(_) => vec![],
                    };
                }
                target
            }
            Destination::Node(target) => {
                if let Ok(i) = self.binary_search(target) {
                    return match hop_type {
                        HopType::OriginalSender | HopType::CopyNr(0) => vec![self.nodes[i].clone()],
                        HopType::CopyNr(_) => vec![],
                    };
                }
                target
            }
        };
        match hop_type {
            HopType::OriginalSender => self.closest_nodes_to(target, PARALLELISM),
            HopType::CopyNr(nr) => {
                self.closest_nodes_to(target, nr + 1)
                    .last()
                    .into_iter()
                    .cloned()
                    .collect()
            }
        }
    }

    /// Returns the rest of our close group, i. e. the `GROUP_SIZE - 1` nodes closest to our name.
    ///
    /// If the network is smaller than that, *all* nodes are returned.
    pub fn our_close_group(&self) -> Vec<NodeInfo<T, U>> {
        self.nodes.iter().take(GROUP_SIZE).cloned().collect()
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
        // TODO: It shouldn't be necessary to iterate through all nodes to count the closest ones.
        //       Instead, just add up the buckets i where our i-th bit differs from the target's.
        self.nodes
            .iter()
            .filter(|node| xor_name::closer_to_target_or_equal(node.name(), &self.our_name, name))
            .take(GROUP_SIZE)
            .count() < GROUP_SIZE
    }

    /// Number of entries in the routing table.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Returns `true` if there are no entries in the routing table.
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Returns the name of the node this routing table is for.
    pub fn our_name(&self) -> &XorName {
        &self.our_name
    }

    /// Returns the `NodeInfo` with the given name, if it is in the routing table.
    pub fn get(&self, name: &XorName) -> Option<&NodeInfo<T, U>> {
        match self.binary_search(name) {
            Ok(i) => self.nodes.get(i),
            Err(_) => None,
        }
    }

    // This is equivalent to the common leading bits of `self.our_name` and `name` where "leading
    // bits" means the most significant bits.
    fn bucket_index(&self, name: &XorName) -> usize {
        self.our_name.bucket_index(name)
    }

    /// Returns `Ok(i)` if `self.nodes[i]` has the given `name`, or `Err(i)` if no node with that
    /// `name` exists and `i` is the index where it would be inserted into the ordered node list.
    fn binary_search(&self, name: &XorName) -> Result<usize, usize> {
        self.nodes.binary_search_by(|other| self.our_name.cmp_distance(other.name(), name))
    }

    /// Returns whether we share any close groups with the nodes in the given bucket.
    ///
    /// If the bucket is not full or we have less than `GROUP_SIZE - 1` contacts with a greater
    /// bucket index, then for _every_ node in that bucket there exists an address which both that
    /// node and our own node are in the close group of. In that case, the result is `true`.
    ///
    /// Otherwise, no such address exists and `false` is returned.
    fn is_in_any_close_group_with(&self, bucket_index: usize) -> bool {
        !self.is_bucket_full(bucket_index)
            || self.nodes
                   .iter()
                   .take(GROUP_SIZE - 1)
                   .take_while(|n| n.bucket_index > bucket_index)
                   .count() < GROUP_SIZE - 1
    }
}



#[cfg(test)]
mod test {
    use super::*;
    use rand;
    use std::cmp;
    use std::collections;
    use itertools::Itertools;
    use xor_name;
    use xor_name::XorName;

    const TABLE_SIZE: usize = 100;

    #[test]
    fn constant_constraints() {
        // This is required for the RoutingTable to make its guarantees.
        assert!(GROUP_SIZE >= PARALLELISM);
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestPublicId {
        name: XorName,
    }

    impl TestPublicId {
        fn new() -> TestPublicId {
            TestPublicId { name: rand::random::<XorName>() }
        }
        fn set_name(&mut self, name: XorName) {
            self.name = name;
        }
    }

    impl HasName for TestPublicId {
        fn name(&self) -> &XorName {
            &self.name
        }
    }

    fn to_node_info(name: &XorName) -> NodeInfo<TestPublicId, u64> {
        NodeInfo::new(TestPublicId { name: name.clone() }, vec![])
    }

    /// Creates a name in the `index`-th bucket of the table with the given name, where
    /// `index < 503`. The given `distance` will be added. If `distance == 255`, the furthest
    /// possible name in the given bucket is returned.
    fn get_contact(table_name: &XorName, index: usize, distance: u8) -> XorName {
        let XorName(mut arr) = table_name.clone();
        // Invert all bits starting with the `index`th one, so the bucket distance is `index`.
        arr[index / 8] = arr[index / 8] ^ match index % 8 {
            0 => 0b11111111,
            1 => 0b01111111,
            2 => 0b00111111,
            3 => 0b00011111,
            4 => 0b00001111,
            5 => 0b00000111,
            6 => 0b00000011,
            _ => 0b00000001,
        };
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
        table: RoutingTable<TestPublicId, u64>,
        node_info: NodeInfo<TestPublicId, u64>,
        name: XorName,
        initial_count: usize,
        added_names: Vec<XorName>,
    }

    impl TestEnvironment {
        fn new() -> TestEnvironment {
            let node_info = create_random_node_info();
            let name = node_info.name().clone();
            TestEnvironment {
                table: RoutingTable::new(node_info.name()),
                node_info: node_info,
                name: name,
                initial_count: (rand::random::<usize>() % (GROUP_SIZE - 1)) + 1,
                added_names: Vec::new(),
            }
        }

        fn partially_fill_table(&mut self) {
            for i in 0..self.initial_count {
                self.node_info.public_id.set_name(get_contact(&self.name, i, 1));
                self.added_names.push(self.node_info.name().clone());
                assert!(self.table.add_node(self.node_info.clone()).is_some());
            }

            assert_eq!(self.initial_count, self.table.len());
            assert!(are_nodes_sorted(&self.table), "Nodes are not sorted");
        }

        fn complete_filling_table(&mut self) {
            for i in self.initial_count..TABLE_SIZE {
                self.node_info.public_id.set_name(get_contact(&self.name, i, 1));
                self.added_names.push(self.node_info.name().clone());
                assert!(self.table.add_node(self.node_info.clone()).is_some());
            }

            assert_eq!(TABLE_SIZE, self.table.len());
            assert!(are_nodes_sorted(&self.table), "Nodes are not sorted");
        }

        fn public_id(&self, name: &XorName) -> Option<TestPublicId> {
            assert!(are_nodes_sorted(&self.table), "Nodes are not sorted");
            self.table
                .nodes
                .iter()
                .find(|node_info| node_info.name() == name)
                .map(|node| node.public_id.clone())
        }
    }

    fn create_random_node_info() -> NodeInfo<TestPublicId, u64> {
        NodeInfo {
            public_id: TestPublicId::new(),
            connections: Vec::new(),
            bucket_index: 0,
        }
    }

    fn create_random_routing_tables(num_of_tables: usize) -> Vec<RoutingTable<TestPublicId, u64>> {
        use rand;
        let mut vector: Vec<RoutingTable<TestPublicId, u64>> = Vec::with_capacity(num_of_tables);
        for _ in 0..num_of_tables {
            vector.push(RoutingTable::new(&rand::random()));
        }
        vector
    }

    fn are_nodes_sorted(routing_table: &RoutingTable<TestPublicId, u64>) -> bool {
        if routing_table.nodes.len() < 2 {
            true
        } else {
            routing_table.nodes.windows(2).all(|window| {
                xor_name::closer_to_target(window[0].name(),
                                           window[1].name(),
                                           &routing_table.our_name)
            })
        }
    }

    fn make_sort_predicate(target: XorName) -> Box<FnMut(&XorName, &XorName) -> cmp::Ordering> {
        Box::new(move |lhs: &XorName, rhs: &XorName| target.cmp_distance(lhs, rhs))
    }

    #[test]
    fn add_node() {
        let mut test = TestEnvironment::new();

        assert_eq!(test.table.len(), 0);

        // try with our name - should fail
        test.node_info.public_id.set_name(test.table.our_name);
        assert!(test.table.add_node(test.node_info.clone()).is_none());
        assert_eq!(test.table.len(), 0);

        // add first contact
        test.node_info.public_id.set_name(get_contact(&test.name, 0, 2));
        assert!(test.table.add_node(test.node_info.clone()).is_some());
        assert_eq!(test.table.len(), 1);

        // try with the same contact - should fail
        assert!(test.table.add_node(test.node_info.clone()).is_none());
        assert_eq!(test.table.len(), 1);
    }

    #[test]
    fn add_node_to_full_bucket() {
        // add node to a full bucket whose nodes share close group with us
        let mut test = TestEnvironment::new();

        for i in 0..GROUP_SIZE {
            test.node_info.public_id.set_name(get_contact(&test.name, 1, i as u8));
            assert!(test.table.add_node(test.node_info.clone()).is_some());
        }

        test.node_info.public_id.set_name(get_contact(&test.name, 1, 255));
        let r = test.table.add_node(test.node_info.clone()).unwrap();
        assert_eq!(r.0, Vec::new());
        assert_eq!(r.1, true);

        // add node to a full bucket whose nodes do not share close group with us
        test = TestEnvironment::new();

        for i in 0..GROUP_SIZE {
            test.node_info.public_id.set_name(get_contact(&test.name, 1, i as u8));
            assert!(test.table.add_node(test.node_info.clone()).is_some());
        }

        for i in 0..GROUP_SIZE {
            test.node_info.public_id.set_name(get_contact(&test.name, 2, i as u8));
            assert!(test.table.add_node(test.node_info.clone()).is_some());
        }

        test.node_info.public_id.set_name(get_contact(&test.name, 1, 255));
        let r = test.table.add_node(test.node_info.clone()).unwrap();
        assert_eq!(r.0, Vec::new());
        assert_eq!(r.1, false);
    }

    #[test]
    fn add_node_to_bucket_that_is_not_full() {
        let mut test = TestEnvironment::new();

        for i in 0..(GROUP_SIZE / 2) {
            test.node_info.public_id.set_name(get_contact(&test.name, 1, i as u8));
            assert!(test.table.add_node(test.node_info.clone()).is_some());
        }

        let name_to_notify0 = get_contact(&test.name, 2, 0);
        test.node_info.public_id.set_name(name_to_notify0);
        assert!(test.table.add_node(test.node_info.clone()).is_some());

        let name_to_notify1 = get_contact(&test.name, 3, 0);
        test.node_info.public_id.set_name(name_to_notify1);
        assert!(test.table.add_node(test.node_info.clone()).is_some());

        test.node_info.public_id.set_name(get_contact(&test.name, 1, 255));
        let r = test.table.add_node(test.node_info.clone()).unwrap();
        assert!(r.0.len() == 2);
        assert!(r.0.iter().any(|n| *n.name() == name_to_notify0));
        assert!(r.0.iter().any(|n| *n.name() == name_to_notify1));
    }

    #[test]
    fn add_connection() {
        let mut test = TestEnvironment::new();
        let mut node0 = create_random_node_info();
        let name0 = node0.name().clone();
        node0.connections.push(1);

        assert!(test.table.add_node(node0).is_some());

        // try adding connection to non-existing node - should fail
        let name1 = rand::random();
        assert!(!test.table.add_connection(&name1, 2));

        // try adding connection that already exist - should fail
        assert!(!test.table.add_connection(&name0, 1));

        // try adding new connection
        assert!(test.table.add_connection(&name0, 2));
    }

    #[test]
    fn want_to_add() {
        let mut test = TestEnvironment::new();

        // Try with our ID
        assert!(!test.table.want_to_add(&test.table.our_name));

        // Should return true for empty routing table
        assert!(test.table.want_to_add(&get_contact(&test.name, 0, 2)));

        // Add the first contact, and check it doesn't allow duplicates
        let mut new_node_0 = create_random_node_info();
        new_node_0.public_id.set_name(get_contact(&test.name, 0, 2));
        assert!(test.table.add_node(new_node_0).is_some());
        assert!(!test.table.want_to_add(&get_contact(&test.name, 0, 2)));
    }

    #[test]
    fn drop_node() {
        use rand::Rng;

        // Check on empty table
        let mut test = TestEnvironment::new();

        assert_eq!(test.table.len(), 0);

        // Fill the table
        test.partially_fill_table();
        test.complete_filling_table();

        // Try with invalid Address
        assert!(test.table.drop_node(&XorName::new([0u8; 64])).is_none());
        assert_eq!(TABLE_SIZE, test.table.len());

        // Try with our Name
        let drop_name = test.table.our_name.clone();
        assert!(test.table.drop_node(&drop_name).is_none());
        assert_eq!(TABLE_SIZE, test.table.len());

        // Try with Address of node not in table
        assert!(test.table.drop_node(&get_contact(&test.name, 0, 2)).is_none());
        assert_eq!(TABLE_SIZE, test.table.len());

        // Remove all nodes one at a time in random order
        let mut rng = rand::thread_rng();
        rng.shuffle(&mut test.added_names[..]);
        let mut len = test.table.len();
        for name in test.added_names {
            len -= 1;
            assert!(test.table.drop_node(&name).is_some());
            assert_eq!(len, test.table.len());
        }
    }

    #[test]
    fn drop_connection() {
        let mut test = TestEnvironment::new();
        let mut node = create_random_node_info();
        node.connections.push(1);
        node.connections.push(2);
        let name = node.name().clone();
        assert!(test.table.add_node(node).is_some());

        // Try to drop non-existing connection.
        assert_eq!(test.table.drop_connection(&3), None);

        // The node still has some connection left after the drop
        assert_eq!(test.table.drop_connection(&1), None);
        assert!(test.table.get(&name).unwrap().connections.len() > 0);

        // The node has no more connections and should be removed.
        assert_eq!(test.table.drop_connection(&2), Some((name, None, true)));
        assert!(test.table.get(&name).is_none());

        // Try dropping connection of a node in full bucket
        let bucket_index = 100;
        for i in 0..GROUP_SIZE {
            let name = get_contact(&test.name, bucket_index, i as u8);
            test.node_info.public_id.set_name(name);
            test.node_info.connections = vec![1 + i as u64];

            assert!(test.table.add_node(test.node_info.clone()).is_some());
        }

        let r = test.table.drop_connection(&1).unwrap();
        assert_eq!(r.1, Some(bucket_index));
        assert_eq!(r.2, true);

        // Try dropping connection of node in full bucket whose nodes do not share
        // close group with us.
        test = TestEnvironment::new();
        let mut connection_assigned = false;

        // ...full bucket, close to us
        for i in 0..GROUP_SIZE {
            let name = get_contact(&test.name, 1, i as u8);
            test.node_info.public_id.set_name(name);
            test.node_info.connections = Vec::new();
            assert!(test.table.add_node(test.node_info.clone()).is_some());
        }
        assert!(test.table.is_bucket_full(1));

        // ...full bucket, further away from us
        for i in 0..GROUP_SIZE {
            let name = get_contact(&test.name, 0, i as u8);
            test.node_info.public_id.set_name(name);

            if !connection_assigned {
                test.node_info.connections = vec![1];
                connection_assigned = true;
            } else {
                test.node_info.connections = Vec::new();
            }

            assert!(test.table.add_node(test.node_info.clone()).is_some());
        }
        assert!(test.table.is_bucket_full(0));

        let r = test.table.drop_connection(&1).unwrap();
        assert_eq!(r.1, Some(0));
        assert_eq!(r.2, false);
    }

    #[test]
    fn target_nodes() {
        // modernise
        use rand;
        let mut test = TestEnvironment::new();

        // Check on empty table
        let mut target_nodes = test.table.target_nodes(Destination::Group(&rand::random()),
                                                       HopType::OriginalSender);
        assert_eq!(target_nodes.len(), 0);

        // Partially fill the table with <GROUP_SIZE contacts
        test.partially_fill_table();

        // Check we get all contacts returned
        target_nodes = test.table.target_nodes(Destination::Group(&rand::random()),
                                               HopType::OriginalSender);
        assert_eq!(test.initial_count, target_nodes.len());

        for i in 0..test.initial_count {
            let mut assert_checker = 0;
            for j in 0..target_nodes.len() {
                if *target_nodes[j].name() == get_contact(&test.name, i, 1) {
                    assert_checker = 1;
                    break;
                }
            }
            assert!(assert_checker == 1);
        }

        // Complete filling the table up to TABLE_SIZE contacts
        test.complete_filling_table();

        // Try with our ID (should return the rest of the close group)
        target_nodes = test.table.target_nodes(Destination::Group(&test.table.our_name),
                                               HopType::OriginalSender);
        assert_eq!(GROUP_SIZE - 1, target_nodes.len());

        for i in ((TABLE_SIZE - GROUP_SIZE + 1)..TABLE_SIZE - 1).rev() {
            let mut assert_checker = 0;
            for j in 0..target_nodes.len() {
                if *target_nodes[j].name() == get_contact(&test.name, i, 1) {
                    assert_checker = 1;
                    break;
                }
            }
            assert!(assert_checker == 1);
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
                target_nodes = test.table.target_nodes(Destination::Node(&target),
                                                       HopType::OriginalSender);
                assert_eq!(expected_len, target_nodes.len());
                for i in 0..target_nodes.len() {
                    let mut assert_checker = 0;
                    for j in 0..test.added_names.len() {
                        if *target_nodes[i].name() == test.added_names[j] {
                            assert_checker = 1;
                            continue;
                        }
                    }
                    assert!(assert_checker == 1);
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
                target_nodes = test.table.target_nodes(Destination::Group(&target),
                                                       HopType::OriginalSender);
                assert_eq!(GROUP_SIZE - 1, target_nodes.len());
                for i in 0..target_nodes.len() {
                    let mut assert_checker = 0;
                    for j in 0..test.added_names.len() {
                        if *target_nodes[i].name() == test.added_names[j] {
                            assert_checker = 1;
                            continue;
                        }
                    }
                    assert!(assert_checker == 1);
                }
            }
        }
    }

    #[test]
    fn our_close_group_test() {
        // unchecked - could be merged with one below?
        let mut test = TestEnvironment::new();
        assert!(test.table.our_close_group().is_empty());

        test.partially_fill_table();
        assert_eq!(test.initial_count, test.table.our_close_group().len());

        for i in 0..test.initial_count {
            assert!(test.table
                        .our_close_group()
                        .iter()
                        .filter(|node| *node.name() == get_contact(&test.name, i, 1))
                        .count() > 0);
        }

        test.complete_filling_table();
        assert_eq!(GROUP_SIZE, test.table.our_close_group().len());

        for close_node in test.table.our_close_group() {
            assert_eq!(1,
                       test.added_names.iter().filter(|n| *n == close_node.name()).count());
        }
    }

    #[test]
    fn our_close_group_and_is_close() {
        let mut tables = collections::HashMap::new();
        for _ in 0..TABLE_SIZE {
            let node_info = create_random_node_info();
            let table = RoutingTable::<TestPublicId, u64>::new(node_info.name());
            let _ = tables.insert(node_info.name().clone(), table);
        }
        let keys: Vec<XorName> = tables.keys().cloned().collect();
        // Add each node to each other node's routing table.
        for name0 in keys.iter() {
            for name1 in keys.iter() {
                if tables[name0].want_to_add(name1) {
                    let _ = tables.get_mut(name0).unwrap().add_node(to_node_info(name1));
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
                                            .map(|t| t.our_name().clone())
                                            .sorted_by(&mut *make_sort_predicate(name.clone()));
            assert_eq!(GROUP_SIZE, close_group.len());
            let our_close_group: Vec<_> = tables[&name]
                                              .our_close_group()
                                              .into_iter()
                                              .map(|ni| ni.name().clone())
                                              .collect();
            // The node itself is not in `our_close_group`, but it is in `close_group`:
            assert_eq!(close_group[1..].to_vec(),
                       our_close_group[..(GROUP_SIZE - 1)].to_vec());
        }
    }

    #[test]
    fn add_check_close_group_test() {
        // unchecked - could be merged with one above?
        let num_of_tables = 50usize;
        let mut tables = create_random_routing_tables(num_of_tables);
        let mut addresses: Vec<XorName> = Vec::with_capacity(num_of_tables);

        for i in 0..num_of_tables {
            addresses.push(tables[i].our_name.clone());
            for j in 0..num_of_tables {
                let mut node_info = create_random_node_info();
                node_info.public_id.set_name(tables[j].our_name);
                // TODO: Ask want_to_add first?
                let _ = tables[i].add_node(node_info);
            }
        }
        for it in tables.iter() {
            addresses.sort_by(&mut *make_sort_predicate(it.our_name.clone()));
            let group = it.our_close_group();
            assert_eq!(group.len(), GROUP_SIZE);
            for i in 0..GROUP_SIZE {
                assert_eq!(group[i].name(), &addresses[i + 1]);
            }
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
            addresses.push(tables[i].our_name.clone());
            for j in 0..tables.len() {
                let mut node_info = create_random_node_info();
                node_info.public_id.set_name(tables[j].our_name);
                let _ = tables[i].add_node(node_info);
            }
        }

        // now remove nodes
        let mut drop_vec: Vec<XorName> = Vec::with_capacity(nodes_to_remove);
        for i in 0..nodes_to_remove {
            drop_vec.push(addresses[i].clone());
        }

        tables.truncate(nodes_to_remove);

        for i in 0..tables.len() {
            for j in 0..drop_vec.len() {
                let _ = tables[i].drop_node(&drop_vec[j]).is_some();
            }
        }
        // remove IDs too
        addresses.truncate(nodes_to_remove);

        for i in 0..tables.len() {
            addresses.sort_by(&mut *make_sort_predicate(tables[i].our_name.clone()));
            let group = tables[i].our_close_group();
            assert_eq!(group.len(), cmp::min(GROUP_SIZE, tables[i].len()));
        }
    }

    #[test]
    fn target_nodes_group_test() {
        // unchecked - purpose?
        let network_len = 100usize;

        let mut tables = create_random_routing_tables(network_len);
        let mut addresses: Vec<XorName> = Vec::with_capacity(network_len);

        for i in 0..tables.len() {
            addresses.push(tables[i].our_name.clone());
            for j in 0..tables.len() {
                let mut node_info = create_random_node_info();
                node_info.public_id.set_name(tables[j].our_name);
                let _ = tables[i].add_node(node_info);
            }
        }

        let mut tested_close_target = false;
        for i in 0..tables.len() {
            addresses.sort_by(&mut *make_sort_predicate(tables[i].our_name.clone()));
            // if target is in close group return the whole close group excluding target
            for j in 1..GROUP_SIZE {
                if tables[i].is_close(&addresses[j]) {
                    let dst = Destination::Group(&addresses[j]);
                    let target_close_group = tables[i].target_nodes(dst, HopType::CopyNr(0));
                    assert_eq!(GROUP_SIZE - 1, target_close_group.len());
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
        assert!(test.public_id(&get_contact(&test.name, 0, 1)).is_none());
        assert_eq!(0, test.table.nodes.len());

        // Check on partially filled the table
        test.partially_fill_table();
        let test_node = create_random_node_info();
        test.node_info = test_node.clone();
        assert!(test.table.add_node(test.node_info.clone()).is_some());

        match test.public_id(test.node_info.name()) {
            Some(_) => {}
            None => panic!("PublicId None"),
        }
        // EXPECT_TRUE(asymm::MatchingKeys(info_.dht_public_id.public_key(),
        //                                 *table_.GetPublicKey(info_.name())));
        match test.public_id(&get_contact(&test.name, 99, 2)) {
            Some(_) => panic!("PublicId Exists"),
            None => {}
        }
        assert_eq!(test.initial_count + 1, test.table.nodes.len());

        // Check on fully filled the table
        assert!(test.table.drop_node(test_node.name()).is_some());
        test.complete_filling_table();
        assert!(test.table.drop_node(&get_contact(&test.name, 0, 1)).is_some());
        test.node_info = test_node.clone();
        assert!(test.table.add_node(test.node_info.clone()).is_some());

        match test.public_id(test.node_info.name()) {
            Some(_) => {}
            None => panic!("PublicId None"),
        }
        match test.public_id(&get_contact(&test.name, 99, 2)) {
            Some(_) => panic!("PublicId Exists"),
            None => {}
        }
        // EXPECT_TRUE(asymm::MatchingKeys(info_.dht_public_id.public_key(),
        //                                 *table_.GetPublicKey(info_.name())));
    }

    #[test]
    fn bucket_index() {
        // Set our name for routing table to max possible value (in binary, all `1`s)
        let our_name = XorName::new([255u8; xor_name::XOR_NAME_LEN]);
        let routing_table = RoutingTable::<TestPublicId, u64>::new(&our_name);

        // Iterate through each u8 element of a target name identical to ours and set it to each
        // possible value for u8 other than 255 (since that which would a target name identical to
        // our name)
        for index in 0..::xor_name::XOR_NAME_LEN {
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
    fn is_close_to_bucket_of() {
        let mut test = TestEnvironment::new();

        assert!(test.table.is_close_to_bucket_of(&rand::random()));

        // Fill the first buckets with [GROUP_SIZE - 1, GROUP_SIZE - 1, GROUP_SIZE, GROUP_SIZE, 1]
        // elements
        for i in 0..(GROUP_SIZE - 1) {
            test.node_info.public_id.set_name(get_contact(&test.name, 0, i as u8));
            assert!(test.table.add_node(test.node_info.clone()).is_some());
        }
        for i in 0..(GROUP_SIZE - 1) {
            test.node_info.public_id.set_name(get_contact(&test.name, 1, i as u8));
            assert!(test.table.add_node(test.node_info.clone()).is_some());
        }
        for i in 0..GROUP_SIZE {
            test.node_info.public_id.set_name(get_contact(&test.name, 2, i as u8));
            assert!(test.table.add_node(test.node_info.clone()).is_some());
        }
        for i in 0..GROUP_SIZE {
            test.node_info.public_id.set_name(get_contact(&test.name, 3, i as u8));
            assert!(test.table.add_node(test.node_info.clone()).is_some());
        }
        test.node_info.public_id.set_name(get_contact(&test.name, 4, 0));
        assert!(test.table.add_node(test.node_info.clone()).is_some());

        let name = get_contact(&test.name, 2, 1);
        assert!(!test.table.is_close(&name));
        assert!(!test.table.is_close_to_bucket_of(&name));

        let name = get_contact(&test.name, 3, 99);
        assert!(!test.table.is_close(&name));
        assert!(test.table.is_close(&name.with_flipped_bit(3).unwrap()));
        assert!(!test.table.is_close_to_bucket_of(&name));

        let name = test.name.with_flipped_bit(2).unwrap().with_flipped_bit(3).unwrap();
        assert!(!test.table.is_close(&name));
        assert!(!test.table.is_close_to_bucket_of(&name));

        let name = test.name.with_flipped_bit(0).unwrap().with_flipped_bit(1).unwrap();
        assert!(!test.table.is_close(&name));
        assert!(test.table.is_close(&name.with_flipped_bit(1).unwrap()));
        assert!(test.table.is_close_to_bucket_of(&name));
    }
}
