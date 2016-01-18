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

//! # Kademlia Routing Table
//!
//! Kademlia Routing Table implementation.
///
/// Note: Bucket index and distance refers to the common leading bits between two addreses
/// Therefor the largest bucket index is the closest "distance" and the lowest bucket  index
/// covers the most number of potential nodes (xor address space)
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

/// Defines the size of close group
pub const GROUP_SIZE: u8 = 8;

/// Defines the size of close group
pub fn group_size() -> usize {
    GROUP_SIZE as usize
}

/// Used as number of nodes agreed to represnet a quorum
const QUORUM_SIZE: u8 = 5;
// Quorum size as usize
fn quorum_size() -> usize {
    QUORUM_SIZE as usize
}
/// Defines the number of contacts which should be returned by the `target_nodes` function for a
/// target which is outwith our close group and is not a contact in the table.
pub const PARALLELISM: u8 = 4;

/// parallelism as u64
pub fn parallelism() -> usize {
    PARALLELISM as usize
}
/// Defines the target max number of contacts per bucket.  This is not a hard limit; buckets can
/// exceed this size if required.
const BUCKET_SIZE: u8 = 2;

/// Bucket size
pub fn bucket_size() -> usize {
    BUCKET_SIZE as usize
}

/// Defines the target max number of contacts for the whole routing table. This is not a hard limit;
/// the table size can exceed this size if required.
const OPTIMAL_TABLE_SIZE: u8 = 64;

/// optimal table size as usize
pub fn optimal_table_size() -> usize {
    OPTIMAL_TABLE_SIZE as usize
}
/// required trait for the info held on a node by routing_table
pub trait HasName {
    /// return xor_name for this type
    fn name(&self) -> &::xor_name::XorName;
}

/// Allows user defined data for routing table
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeInfo<T, U> {
    /// container for node in routing table
    pub public_id: T,
    /// connection object, may be socket etc.
    pub connections: Vec<U>,
    bucket_index: usize,
}

impl<T: PartialEq + HasName + ::std::fmt::Debug, U: PartialEq> NodeInfo<T, U> {
    /// constructor
    pub fn new(public_id: T, connections: Vec<U>) -> NodeInfo<T, U> {
        NodeInfo {
            public_id: public_id,
            connections: connections,
            bucket_index: 0,
        }
    }

    /// name of routing table entry
    pub fn name(&self) -> &::xor_name::XorName {
        self.public_id.name()
    }
}

/// The RoutingTable class is used to maintain a list of contacts to which the node is connected.
pub struct RoutingTable<T, U> {
    nodes: Vec<NodeInfo<T, U>>,
    our_name: ::xor_name::XorName,
    group_bucket_index: usize,
}

impl <T : PartialEq + HasName + ::std::fmt::Debug + ::std::clone::Clone,
      U : PartialEq + ::std::fmt::Debug + ::std::clone::Clone>RoutingTable<T, U> {
    /// Creates a new routing table for the node with the given name.
	pub fn new(our_name: &::xor_name::XorName) -> RoutingTable<T, U> {
        RoutingTable {
            nodes: vec![],
            our_name: our_name.clone(),
            group_bucket_index: 0, // 0 leading bits in common
        }
    }

    /// Adds a contact to the routing table.  If the contact is added, the first return arg is true,
    /// otherwise false.  If adding the contact caused another contact to be dropped, the dropped
    /// one is returned in the second field, otherwise the optional field is empty.
    pub fn add_node(&mut self, their_info: NodeInfo<T, U>) -> (bool, Option<NodeInfo<T, U>>) {
        if self.our_name == *their_info.name() {
            return (false, None)
        } else if self.get(&their_info.name()).is_some() {
            debug!("Routing table {:?} has node {:?}. not adding", self.nodes, their_info);
            return (false, None)
        } else if self.nodes.len() < optimal_table_size() {
            self.push_back_then_sort(their_info);
            return (true, None)
        } else if self.furthest_close_node()
                      .map_or(true, |node| self.is_closer(their_info.name(), node.name())) {
            self.push_back_then_sort(their_info);
            return match self.find_candidate_for_removal() {
                None => (true, None),
                Some(node_index) => (true, Some(self.nodes.remove(node_index))),
            }
        }

        let removal_node_index = self.find_candidate_for_removal();
        if self.new_node_is_better_than_existing(their_info.name(), removal_node_index) {
            let removal_node = self.nodes.remove(removal_node_index.expect(
                    "Could not remove a value we just calculated, perhaps non atomic "));
            self.push_back_then_sort(their_info);
            return (true, Some(removal_node))
        }

        (false, None)
    }

    /// Adds a connection to an existing entry.  Should be called after `has_node`. The return
    /// indicates if the given connection was added to an existing NodeInfo.
    pub fn add_connection(&mut self,
                          their_name: &::xor_name::XorName,
                          connection: U) -> bool {
        match self.nodes.iter_mut().find(|node_info| node_info.name() == their_name) {
            Some(mut node_info) => {
                if node_info.connections.iter().any(|elt| *elt == connection) {
                    return false
                }

                node_info.connections.push(connection);
                true
            },
            None => {
                error!("The NodeInfo should already exist here.");
                false
            },
        }
    }

    /// This is used to check whether it is worthwhile trying to connect to the peer with a view to
    /// adding the contact to our routing table, i.e. would this contact improve our table.  The
    /// checking procedure is the same as for `add_node`, except for the lack of a public key to
    /// check in step 1.
    pub fn want_to_add(&self, their_name: &::xor_name::XorName) -> bool {
        if self.our_name == *their_name || self.get(&their_name).is_some()  {
            false
        } else if self.nodes.len() < optimal_table_size() {
            true
        } else if self.furthest_close_node()
                      .map_or(true, |node| self.is_closer(their_name, node.name())) {
            true
        } else {
            self.new_node_is_better_than_existing(&their_name, self.find_candidate_for_removal())
        }
    }

    /// Returns the current calculated quorum size. This is dependent on the current routing table
    /// size.
	pub fn dynamic_quorum_size(&self) -> usize {
		let factor :f32 = QUORUM_SIZE as f32 / GROUP_SIZE as f32;
		::std::cmp::min((
        self.nodes.len() as f32 * factor).round() as usize, quorum_size())
	}

    /// This unconditionally removes the contact from the table.
    pub fn drop_node(&mut self, node_to_drop: &::xor_name::XorName) {
        self.nodes.retain(|node_info| node_info.name() != node_to_drop);
		self.set_group_bucket_index();
    }

    /// This should be called when a connection has dropped.  If the
    /// affected entry has no connections after removing this one, the entry is removed from the
    /// routing table and its name is returned.  If the entry still has at least one connection, or
    /// an entry cannot be found for 'lost_connection', the function returns 'None'.
    pub fn drop_connection(&mut self, lost_connection: &U) -> Option<::xor_name::XorName> {
        let remove_connection = |node_info: &mut NodeInfo<T,U>| {
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
               return Some(self.nodes.remove(node_index).name().clone())
            }
        }
        None
    }

    /// Returns the `n` nodes in our routing table that are closest to `target`.
    fn closest_nodes_to(&self, target: &::xor_name::XorName, n: usize) -> Vec<NodeInfo<T, U>> {
        self.nodes.iter()
                  .sorted_by(|a, b| if ::xor_name::closer_to_target(&a.name(), &b.name(), &target) {
                                        ::std::cmp::Ordering::Less
                                    } else {
                                        ::std::cmp::Ordering::Greater
                                    })
                  .into_iter()
                  .take(n)
                  .cloned()
                  .collect()
    }

    /// Returns a collection of nodes to which a message should be sent onwards.
    ///
    /// It will return `group_size()` contacts if we are close to the `target`. Otherwise, it will
    /// return only the target node itself, if it is in our contacts. If not, it returns the
    /// `parallelism()` closest contacts to the target.
    pub fn target_nodes(&self, target: &::xor_name::XorName) -> Vec<NodeInfo<T, U>> {
        // if in range of close_group send to all close_group
        if self.is_close(target) {
            return self.closest_nodes_to(target, group_size());
        }

        // if not in close group but connected then send direct
        if let Some(ref found) = self.nodes.iter().find(|ref node| node.name() == target) {
            return vec![(*found).clone()]
        }

        // not in close group or routing table so send to closest known nodes up to parallelism
        // count
        self.closest_nodes_to(target, parallelism())
    }

    /// This returns our close group, i.e. the 'group_size()' contacts closest to our name (or the
    /// entire table if we hold less than 'group_size()' contacts in total) sorted by closeness to us.
    pub fn our_close_group(&self) -> Vec<NodeInfo<T, U>> {
        self.nodes.iter().take(group_size()).cloned().collect()
    }

    /// Returns `true` if there are fewer than `group_size()` nodes in our routing table that are
    /// closer to `name` than we are.
    ///
    /// In other words, it returns `true` whenever we cannot rule out that we might be among the
    /// `group_size()` closest nodes to `name`.
    ///
    /// If the routing table is filled in such a way that each bucket contains `group_size()`
    /// elements unless there aren't enough such nodes in the network, then this criterion is
    /// actually sufficient! In that case, `true` is returned if and only if we are among the
    /// `group_size()` closest node to `name` in the network.
    pub fn is_close(&self, name: &::xor_name::XorName) -> bool {
        self.nodes.iter()
            .filter(|node| ::xor_name::closer_to_target_or_equal(node.name(), &self.our_name, name))
            .count() < group_size()
    }

    /// Returns `true` if `lhs` is closer to this node's name that `rhs`.
    fn is_closer(&self, lhs: &::xor_name::XorName, rhs: &::xor_name::XorName) -> bool {
        ::xor_name::closer_to_target(lhs, rhs, &self.our_name)
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
    pub fn our_name(&self) -> &::xor_name::XorName {
        &self.our_name
    }

    /// Returns the `NodeInfo` with the given name, if it is in the routing table.
    pub fn get(&self, name: &::xor_name::XorName) ->Option<&NodeInfo<T,U>> {
        match self.binary_search(name) {
            Ok(i) => self.nodes.get(i),
            Err(_) => None,
        }
    }

    /// Use this to calculate incoming messages for instance "fit" in this bucket distance
    /// when confirming a group is who it says it is. This is a partial check, not full
    /// security.
    pub fn try_confirm_safe_group_distance(&self,
                                          address1: &::xor_name::XorName,
                                          address2: &::xor_name::XorName) -> bool {
        self.group_bucket_index >= address1.bucket_index(&address2)
    }

    // The node in your close group furthest from you
    fn furthest_close_node(&self) -> Option<&NodeInfo<T, U>> {
        self.nodes.get(group_size() - 1).or(self.nodes.last())
    }

    // set the index number of the furthest close node and memoise it in the Routingtable struct
    fn set_group_bucket_index(&mut self) {
        let index = match self.furthest_close_node() {
        Some(node) => self.bucket_index(&node.name()),
        None       => 0,
        };
        self.group_bucket_index = index;
    }

    // This effectively reverse iterates through all non-empty buckets (i.e. starts at furthest
    // bucket from us) checking for overfilled ones and returning the table index of the furthest
    // contact within that bucket.  No contacts within our close group will be considered.
    fn find_candidate_for_removal(&self) -> Option<usize> {
        assert!(self.nodes.len() >= optimal_table_size());

        let mut number_in_bucket = 0usize;
        let mut current_bucket = 0usize;

        // Start iterating from the end, i.e. the furthest from our ID.
        let mut counter = self.nodes.len() - 1;
        let mut furthest_in_this_bucket = counter;

        // Stop iterating at our furthest close group member since we won't remove any peer in our
        // close group
        let finish = group_size();

        while counter >= finish {
            let bucket_index = self.nodes[counter].bucket_index;

            // If we're entering a new bucket, reset details.
            if bucket_index != current_bucket {
                current_bucket = bucket_index;
                number_in_bucket = 0;
                furthest_in_this_bucket = counter;
            }

            // Check for an excess of contacts in this bucket.
            number_in_bucket += 1;
            if number_in_bucket > bucket_size() {
                break;
            }

            counter -= 1;
        }

        if counter < finish {
            None
        } else {
            Some(furthest_in_this_bucket)
        }
    }

    // This is equivalent to the common leading bits of `self.our_name` and `name` where "leading
    // bits" means the most significant bits.
    fn bucket_index(&self, name: &::xor_name::XorName) -> usize {
        self.our_name.bucket_index(name)
    }

    /// Returns `Ok(i)` if `self.nodes[i]` has the given `name`, or `Err(i)` if no node with that
    /// `name` exists and `i` is the index where it would be inserted into the ordered node list.
    fn binary_search(&self, name: &::xor_name::XorName) -> Result<usize, usize> {
        self.nodes.binary_search_by(|other| if self.is_closer(other.name(), name) {
                                                ::std::cmp::Ordering::Less
                                            } else if other.name() == name {
                                                ::std::cmp::Ordering::Equal
                                            } else {
                                                ::std::cmp::Ordering::Greater
                                            })
    }

    fn push_back_then_sort(&mut self, mut node: NodeInfo<T, U>) {
        match self.binary_search(node.name()) {
            Ok(i) => {
                // Node already exists! Update the entry:
                self.nodes[i].connections.extend(node.connections);
            },
            Err(i) => {
                // No existing entry, so set the node's bucket distance and insert it.
                let index = self.bucket_index(&node.name());
		        node.bucket_index = index;
                self.nodes.insert(i, node);
                self.set_group_bucket_index();
            }
        }
    }

    // Returns true if 'removal_node_index' is Some and the new node is in a closer bucket than the
    // removal candidate.
    fn new_node_is_better_than_existing(&self,
                                        new_node: &::xor_name::XorName,
                                        removal_node_index: Option<usize>)
                                        -> bool {
        match removal_node_index {
            Some(index) => {
                let removal_node = &self.nodes[index];
                self.bucket_index(new_node) > self.bucket_index(removal_node.name())
            },
            None => false,
        }
    }
}



#[cfg(test)]
mod test {
    use super::{BUCKET_SIZE, bucket_size, group_size, HasName, NodeInfo, RoutingTable,
                optimal_table_size, parallelism};
    use std::collections;
    use itertools::Itertools;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TestNodeInfo {
        name: ::xor_name::XorName,
    }

    impl TestNodeInfo {
        fn new() -> TestNodeInfo {
            TestNodeInfo { name: ::rand::random::<::xor_name::XorName>() }
        }
        fn set_name(&mut self, name: ::xor_name::XorName) {
            self.name = name;
        }
    }

    impl HasName for TestNodeInfo {
        fn name(&self) -> &::xor_name::XorName {
            &self.name
        }
    }

    fn to_node_info(name: &::xor_name::XorName) -> NodeInfo<TestNodeInfo, u64> {
        NodeInfo::new(TestNodeInfo { name: name.clone() }, vec!())
    }

    /// Creates a name in the `index`-th bucket of the table with the given name, where
    /// `index < 503`. The given `distance` will be added. If `distance == 255`, the furthest
    /// possible name in the given bucket is returned.
    fn get_contact(table_name: &::xor_name::XorName, index: usize, distance: u8)
            -> ::xor_name::XorName {
        let ::xor_name::XorName(mut arr) = table_name.clone();
        // Invert all bits starting with the `index`th one, so the bucket distance is `index`.
        arr[index / 8] = arr[index / 8] ^ (1 << (8 - index % 8) - 1);
        for i in (index / 8 + 1)..(arr.len() - 1) {
            arr[i] = arr[i] ^ 255;
        }
        // Add the desired distance.
        let last = arr.len() - 1;
        arr[last] = arr[last] ^ distance;
        let result = ::xor_name::XorName(arr);
        assert_eq!(index, result.bucket_index(table_name));
        result
    }

    struct TestEnvironment {
        table: RoutingTable<TestNodeInfo, u64>,
        node_info: NodeInfo<TestNodeInfo, u64>,
        name: ::xor_name::XorName,
        initial_count: usize,
        added_names: Vec<::xor_name::XorName>,
    }

    impl TestEnvironment {
        fn new() -> TestEnvironment {
            let node_info = create_random_node_info();
            let name = node_info.name().clone();
            TestEnvironment {
                table: RoutingTable::new(node_info.name()),
                node_info: node_info,
                name: name,
                initial_count: (::rand::random::<usize>() % (group_size() - 1)) + 1,
                added_names: Vec::new(),
            }
        }

        fn partially_fill_table(&mut self) {
            for i in 0..self.initial_count {
                self.node_info.public_id.set_name(get_contact(&self.name, i, 1));
                self.added_names.push(self.node_info.name().clone());
                assert!(self.table.add_node(self.node_info.clone()).0);
            }

            assert_eq!(self.initial_count, self.table.len());
            assert!(are_nodes_sorted(&self.table), "Nodes are not sorted");
        }

        fn complete_filling_table(&mut self) {
            for i in self.initial_count..optimal_table_size() {
                self.node_info.public_id.set_name(get_contact(&self.name, i, 1));
                self.added_names.push(self.node_info.name().clone());
                assert!(self.table.add_node(self.node_info.clone()).0);
            }

            assert_eq!(optimal_table_size(), self.table.len());
            assert!(are_nodes_sorted(&self.table), "Nodes are not sorted");
        }

        fn public_id(&self, name: &::xor_name::XorName) -> Option<TestNodeInfo> {
            assert!(are_nodes_sorted(&self.table), "Nodes are not sorted");
            match self.table.nodes.iter().find(|node_info| node_info.name() == name) {
                Some(node) => Some(node.public_id.clone()),
                None => None,
            }
        }
    }

    fn create_random_node_info() -> NodeInfo<TestNodeInfo, u64> {
        NodeInfo {
            public_id: TestNodeInfo::new(),
            connections: Vec::new(),
            bucket_index: 0,
        }
    }

    fn create_random_routing_tables(num_of_tables: usize) -> Vec<RoutingTable<TestNodeInfo, u64>> {
        use rand;
        let mut vector: Vec<RoutingTable<TestNodeInfo, u64>> = Vec::with_capacity(num_of_tables);
        for _ in 0..num_of_tables {
            vector.push(RoutingTable::new(&rand::random()));
        }
        vector
    }

    fn are_nodes_sorted(routing_table: &RoutingTable<TestNodeInfo, u64>) -> bool {
        if routing_table.nodes.len() < 2 {
            true
        } else {
            routing_table.nodes.windows(2).all(|window| {
                ::xor_name::closer_to_target(window[0].name(),
                                             window[1].name(),
                                             &routing_table.our_name)
            })
        }
    }

    fn make_sort_predicate(target: ::xor_name::XorName)
            -> Box<FnMut(&::xor_name::XorName, &::xor_name::XorName) -> ::std::cmp::Ordering> {
        Box::new(move |lhs: &::xor_name::XorName, rhs: &::xor_name::XorName| {
            match ::xor_name::closer_to_target(lhs, rhs, &target) {
                true => ::std::cmp::Ordering::Less,
                false => ::std::cmp::Ordering::Greater,
            }
        })
    }

    #[test]
    fn add_node() {
        let mut test = TestEnvironment::new();

        assert_eq!(test.table.len(), 0);

        // try with our name - should fail
        test.node_info.public_id.set_name(test.table.our_name);
        assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(test.table.len(), 0);

        // add first contact
        test.node_info.public_id.set_name(get_contact(&test.name, 0, 2));
        assert_eq!((true, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(test.table.len(), 1);

        // try with the same contact - should fail
        assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(test.table.len(), 1);

        // Add further 'optimal_table_size()' - 1 contacts (should all succeed with no removals).
        // Set this up so that buckets 1 and 2 have BUCKET_SIZE + 2 contacts each and all others
        // have 0 or 1 contacts.

        // Fill buckets 1 and 2 with two excess contacts each.
        for bucket_nr in 1..3 {
            for d in 0..(bucket_size() + 2) {
                test.node_info.public_id.set_name(get_contact(&test.name, bucket_nr, d as u8));
                assert_eq!((true, None), test.table.add_node(test.node_info.clone()));
                assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
            }
            assert_eq!(bucket_nr * (bucket_size() + 2) + 1, test.table.len());
        }

        let len_with_3_buckets = test.table.len();
        let optimal_len = optimal_table_size();

        // Add remaining contacts
        for bucket_nr in 3..(3 + optimal_len - len_with_3_buckets) {
            test.node_info.public_id.set_name(get_contact(&test.name, bucket_nr, 1));
            assert_eq!((true, None), test.table.add_node(test.node_info.clone()));
            assert_eq!(bucket_nr - 2 + len_with_3_buckets, test.table.len());
            assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
            assert_eq!(bucket_nr - 2 + len_with_3_buckets, test.table.len());
        }

        assert_eq!(optimal_len, test.table.len());

        // Check next 4 closer additions return the furthest two contacts in each of buckets 1 and
        // 2.
        let mut dropped: Vec<::xor_name::XorName> = Vec::new();
        for i in (optimal_len - 4)..optimal_len {
            test.node_info.public_id.set_name(get_contact(&test.name, i, 1));
            let (added, dropped_node) = test.table.add_node(test.node_info.clone());
            assert!(added);
            dropped.push(unwrap_option!(dropped_node, "").name().clone());
            assert_eq!(optimal_len, test.table.len());
            assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
            assert_eq!(optimal_len, test.table.len());
        }
        assert_eq!(get_contact(&test.name, 1, BUCKET_SIZE + 1), dropped[0]);
        assert_eq!(get_contact(&test.name, 1, BUCKET_SIZE), dropped[1]);
        assert_eq!(get_contact(&test.name, 2, BUCKET_SIZE + 1), dropped[2]);
        assert_eq!(get_contact(&test.name, 2, BUCKET_SIZE), dropped[3]);

        // Try to add far contacts again (should fail)
        for far_contact in dropped {
            test.node_info.public_id.set_name(far_contact);
            assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
            assert_eq!(optimal_len, test.table.len());
        }

        // Add final close contact to push len() of table above optimal_table_size()
        test.node_info.public_id.set_name(get_contact(&test.name, optimal_len, 1));
        assert_eq!((true, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(optimal_len + 1, test.table.len());
        assert_eq!((false, None), test.table.add_node(test.node_info.clone()));
        assert_eq!(optimal_len + 1, test.table.len());
    }

    #[test]
    fn add_connection() {
        // implement
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
        assert!(test.table.add_node(new_node_0).0);
        assert!(!test.table.want_to_add(&get_contact(&test.name, 0, 2)));

        // Add further 'optimal_table_size()' - 1 contacts (should all succeed with no removals).
        // Set this up so that buckets 1 and 2 have BUCKET_SIZE + 2 contacts each and all others
        // have 0 or 1 contacts.

        // Fill buckets 1 and 2 with two excess contacts each.
        for bucket_nr in 1..3 {
            for d in 0..(bucket_size() + 2) {
                let mut new_node = create_random_node_info();
                new_node.public_id.set_name(get_contact(&test.name, bucket_nr, d as u8));
                assert!(test.table.want_to_add(new_node.name()));
                assert!(test.table.add_node(new_node).0);
                assert!(!test.table.want_to_add(&get_contact(&test.name, bucket_nr, d as u8)));
            }
            assert_eq!(bucket_nr * (bucket_size() + 2) + 1, test.table.len());
        }

        let len_with_3_buckets = test.table.len();
        let optimal_len = optimal_table_size();

        // Add remaining contacts
        for bucket_nr in 3..(3 + optimal_len - len_with_3_buckets) {
            let mut new_node = create_random_node_info();
            new_node.public_id.set_name(get_contact(&test.name, bucket_nr, 1));
            assert!(test.table.want_to_add(new_node.name()));
            assert!(test.table.add_node(new_node).0);
            assert!(!test.table.want_to_add(&get_contact(&test.name, bucket_nr, 1)));
        }

        assert_eq!(optimal_len, test.table.nodes.len());

        for i in (optimal_len - 4)..optimal_len {
            let mut new_node = create_random_node_info();
            new_node.public_id.set_name(get_contact(&test.name, i, 1));
            assert!(test.table.want_to_add(new_node.name()));
            assert!(test.table.add_node(new_node).0);
            assert!(!test.table.want_to_add(&get_contact(&test.name, i, 1)));
            assert_eq!(optimal_len, test.table.nodes.len());
        }

        // Check for contacts again which are now not in the table
        assert!(!test.table.want_to_add(&get_contact(&test.name, 0, 2)));
        assert!(!test.table.want_to_add(&get_contact(&test.name, 0, 1)));
        assert!(!test.table.want_to_add(&get_contact(&test.name, 1, 2)));
        assert!(!test.table.want_to_add(&get_contact(&test.name, 1, 1)));

        // Check final close contact which would push len() of table above optimal_table_size()
        assert!(test.table.want_to_add(&get_contact(&test.name, optimal_len, 1)));
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
        test.table.drop_node(&::xor_name::XorName::new([0u8; 64]));
        assert_eq!(optimal_table_size(), test.table.len());

        // Try with our Name
        let drop_name = test.table.our_name.clone();
        test.table.drop_node(&drop_name);
        assert_eq!(optimal_table_size(), test.table.len());

        // Try with Address of node not in table
        test.table.drop_node(&get_contact(&test.name, 0, 2));
        assert_eq!(optimal_table_size(), test.table.len());

        // Remove all nodes one at a time in random order
        let mut rng = ::rand::thread_rng();
        rng.shuffle(&mut test.added_names[..]);
        let mut len = test.table.len();
        for name in test.added_names {
            len -= 1;
            test.table.drop_node(&name);
            assert_eq!(len, test.table.len());
        }
    }

    #[test]
    fn drop_connection() {
        // implement
    }

    #[test]
    fn target_nodes() {
        // modernise
        use rand;
        let mut test = TestEnvironment::new();

        // Check on empty table
        let mut target_nodes = test.table.target_nodes(&rand::random());
        assert_eq!(target_nodes.len(), 0);

        // Partially fill the table with <group_size() contacts
        test.partially_fill_table();

        // Check we get all contacts returned
        target_nodes = test.table.target_nodes(&rand::random());
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

        // Complete filling the table up to optimal_table_size() contacts
        test.complete_filling_table();

        // Try with our ID (should return closest to us, i.e. buckets 63 to 32)
        target_nodes = test.table.target_nodes(&test.table.our_name);
        assert_eq!(group_size(), target_nodes.len());

        for i in ((optimal_table_size() - group_size())..optimal_table_size() - 1).rev() {
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
        // return 'parallelism()' contacts closest to target first time and the single actual target
        // the second time)
        let mut target: ::xor_name::XorName;
        for count in 0..2 {
            for i in 0..(optimal_table_size() - group_size()) {
                let (target, expected_len) = if count == 0 {
                    (get_contact(&test.name, i, 2).clone(), parallelism())
                } else {
                    (get_contact(&test.name, i, 1).clone(), 1)
                };
                target_nodes = test.table.target_nodes(&target);
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
        // return group_size() closest to target)
        for count in 0..2 {
            for i in (optimal_table_size() - group_size() + 1)..optimal_table_size() {
                target = if count == 0 {
                    get_contact(&test.name, i, 0).clone()
                } else {
                    get_contact(&test.name, i, 1).clone()
                };
                target_nodes = test.table.target_nodes(&target);
                assert_eq!(group_size(), target_nodes.len());
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
        assert_eq!(group_size(), test.table.our_close_group().len());

        for close_node in &test.table.our_close_group() {
            assert_eq!(1,
                       test.added_names.iter().filter(|n| *n == close_node.name()).count());
        }
    }

    #[test]
    fn our_close_group_and_is_close() {
        let mut tables = collections::HashMap::new();
        // Create nodes such that each can exactly fill up its routing table.
        for _ in 0..(optimal_table_size() + 1) {
            let node_info = create_random_node_info();
            let table = RoutingTable::<TestNodeInfo, u64>::new(node_info.name());
            let _ = tables.insert(node_info.name().clone(), table);
        }
        let keys: Vec<::xor_name::XorName> = tables.keys().cloned().collect();
        // Add each node to each other node's routing table.
        for name0 in keys.iter() {
            for name1 in keys.iter() {
                if tables[name0].want_to_add(name1) {
                    let _ = tables.get_mut(name0).unwrap().add_node(to_node_info(name1));
                }
            }
            assert_eq!(optimal_table_size(), tables[name0].len());
        }
        // Check close groups of addresses that are not nodes.
        for _ in 0..1000 {
            let name = ::rand::random();
            let close_group_size = tables.values().filter(|t| t.is_close(&name)).count();
            assert_eq!(group_size(), close_group_size);
            // TODO: Find a way to ensure at least the following for more than 65 nodes.
            // assert!(quorum_size() <= close_group_size && close_group_size < 2 * quorum_size(),
            //         "Close group has {} elements", close_group_size);
        }
        // Check close groups of the nodes' addresses.
        for name in keys {
            let close_group: Vec<_> = tables.values()
                                            .filter(|t| t.is_close(&name))
                                            .map(|t| t.our_name().clone())
                                            .sorted_by(&mut *make_sort_predicate(name.clone()));
            assert_eq!(group_size(), close_group.len());
            let our_close_group: Vec<_> = tables[&name].our_close_group()
                                                       .into_iter()
                                                       .map(|ni| ni.name().clone())
                                                       .collect();
            // The node itself is not in `our_close_group`, but it is in `close_group`:
            assert_eq!(close_group[1..].to_vec(), our_close_group[..(group_size() - 1)].to_vec());
        }
    }

    #[test]
    fn add_check_close_group_test() {
        // unchecked - could be merged with one above?
        let num_of_tables = 50usize;
        let mut tables = create_random_routing_tables(num_of_tables);
        let mut addresses: Vec<::xor_name::XorName> = Vec::with_capacity(num_of_tables);

        for i in 0..num_of_tables {
            addresses.push(tables[i].our_name.clone());
            for j in 0..num_of_tables {
                let mut node_info = create_random_node_info();
                node_info.public_id.set_name(tables[j].our_name);
                let _ = tables[i].add_node(node_info);
            }
        }
        for it in tables.iter() {
            addresses.sort_by(&mut *make_sort_predicate(it.our_name.clone()));
            let mut groups = it.our_close_group();
            assert_eq!(groups.len(), group_size());

            // TODO(Spandan) vec.dedup does not compile - manually doing it
            if groups.len() > 1 {
                let mut new_end = 1usize;
                for i in 1..groups.len() {
                    if groups[new_end - 1].name() != groups[i].name() {
                        if new_end != i {
                            groups[new_end] = groups[i].clone();
                        }
                        new_end += 1;
                    }
                }
                assert_eq!(new_end, groups.len());
            }

            assert_eq!(groups.len(), group_size());

            for i in 0..group_size() {
                assert!(groups[i].name() == &addresses[i + 1]);
            }
        }
    }

    #[test]
    fn churn_test() {
        // unchecked - purpose?
        let network_len = 200usize;
        let nodes_to_remove = 20usize;

        let mut tables = create_random_routing_tables(network_len);
        let mut addresses: Vec<::xor_name::XorName> = Vec::with_capacity(network_len);

        for i in 0..tables.len() {
            addresses.push(tables[i].our_name.clone());
            for j in 0..tables.len() {
                let mut node_info = create_random_node_info();
                node_info.public_id.set_name(tables[j].our_name);
                let _ = tables[i].add_node(node_info);
            }
        }

        // now remove nodes
        let mut drop_vec: Vec<::xor_name::XorName> = Vec::with_capacity(nodes_to_remove);
        for i in 0..nodes_to_remove {
            drop_vec.push(addresses[i].clone());
        }

        tables.truncate(nodes_to_remove);

        for i in 0..tables.len() {
            for j in 0..drop_vec.len() {
                tables[i].drop_node(&drop_vec[j]);
            }
        }
        // remove IDs too
        addresses.truncate(nodes_to_remove);

        for i in 0..tables.len() {
            addresses.sort_by(&mut *make_sort_predicate(tables[i].our_name.clone()));
            let group = tables[i].our_close_group();
            assert_eq!(group.len(), ::std::cmp::min(group_size(), tables[i].len()));
        }
    }

    #[test]
    fn target_nodes_group_test() {
        // unchecked - purpose?
        let network_len = 100usize;

        let mut tables = create_random_routing_tables(network_len);
        let mut addresses: Vec<::xor_name::XorName> = Vec::with_capacity(network_len);

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
            for j in 1..group_size() {
                if tables[i].is_close(&addresses[j]) {
                    let target_close_group = tables[i].target_nodes(&addresses[j]);
                    assert_eq!(group_size(), target_close_group.len());
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
        assert!(test.table.add_node(test.node_info.clone()).0);

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
        test.table.drop_node(test_node.name());
        test.complete_filling_table();
        test.table.drop_node(&get_contact(&test.name, 0, 1));
        test.node_info = test_node.clone();
        assert!(test.table.add_node(test.node_info.clone()).0);

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
        assert_eq!(optimal_table_size(), test.table.nodes.len());
    }

    #[test]
    fn bucket_index() {
        // Set our name for routing table to max possible value (in binary, all `1`s)
        let our_name = ::xor_name::XorName::new([255u8; ::xor_name::XOR_NAME_LEN]);
        let routing_table = RoutingTable::<TestNodeInfo, u64>::new(&our_name);

        // Iterate through each u8 element of a target name identical to ours and set it to each
        // possible value for u8 other than 255 (since that which would a target name identical to
        // our name)
        for index in 0..::xor_name::XOR_NAME_LEN {
            let mut array = [255u8; ::xor_name::XOR_NAME_LEN];
            for modified_element in 0..255u8 {
                array[index] = modified_element;
                let target_name = ::xor_name::XorName::new(array);
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
                    let as_binary = |name: &::xor_name::XorName| -> String {
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
}
