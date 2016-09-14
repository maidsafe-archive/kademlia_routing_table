//! docs

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

#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy, unicode_not_nfc, wrong_pub_self_convention,
                                   option_unwrap_used))]
#![cfg_attr(feature="clippy", allow(use_debug))]

// TODO - remove these
#![allow(unused, missing_docs)]
#![cfg_attr(feature="clippy", allow(module_inception))]

extern crate itertools;
#[cfg_attr(feature="clippy", allow(useless_attribute))]
#[allow(unused_extern_crates)]
#[macro_use]
extern crate quick_error;
#[macro_use]
extern crate unwrap;

mod error;
mod prefix;
mod xorable;

pub use self::error::Error;
pub use self::xorable::Xorable;

use itertools::Itertools;
use prefix::Prefix;
use std::fmt::{Binary, Debug, Formatter};
use std::fmt::Result as FmtResult;
use std::{iter, mem, slice};
use std::cmp::{self, Ordering};
use std::collections::{hash_map, HashMap, hash_set, HashSet};
use std::hash::Hash;



pub type Groups<T> = HashMap<Prefix<T>, HashSet<T>>;

type MemberIter<'a, T> = hash_set::Iter<'a, T>;
type GroupIter<'a, T> = hash_map::Iter<'a, Prefix<T>, HashSet<T>>;
type FlatMapFn<'a, T> = fn((&Prefix<T>, &'a HashSet<T>)) -> MemberIter<'a, T>;

// Amount added to `min_group_size` when deciding whether a bucket split can happen.  This helps
// protect against rapid splitting and merging in the face of moderate churn.
const SPLIT_BUFFER: usize = 1;

// Immutable iterator over the entries of a `RoutingTable`.
pub struct Iter<'a, T: 'a + Binary + Clone + Copy + Default + Hash + Xorable> {
    inner: iter::FlatMap<GroupIter<'a, T>, MemberIter<'a, T>, FlatMapFn<'a, T>>,
}

impl<'a, T: 'a + Binary + Clone + Copy + Default + Hash + Xorable> Iter<'a, T> {
    fn iterate(item: (&Prefix<T>, &'a HashSet<T>)) -> hash_set::Iter<'a, T> {
        item.1.iter()
    }
}

impl<'a, T: 'a + Binary + Clone + Copy + Default + Hash + Xorable> Iterator for Iter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<&'a T> {
        self.inner.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}



// A message destination.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Destination<N> {
    // The `k`-group of the given name. The message should reach the `k` closest nodes.
    Group(N, usize),
    // The individual node at the given name. The message should reach exactly one node.
    Node(N),
}

impl<N> Destination<N> {
    // Returns the name of the destination, i.e. the node or group name.
    pub fn name(&self) -> &N {
        match *self {
            Destination::Group(ref name, _) |
            Destination::Node(ref name) => name,
        }
    }

    // Returns `true` if the destination is a group, and `false` if it is an individual node.
    pub fn is_group(&self) -> bool {
        match *self {
            Destination::Group(_, _) => true,
            Destination::Node(_) => false,
        }
    }

    // Returns `true` if the destination is an individual node, and `false` if it is a group.
    pub fn is_node(&self) -> bool {
        !self.is_group()
    }
}



// Used when removal of a contact triggers the need to merge two or more groups
pub struct OwnMergeDetails<T: Binary + Clone + Copy + Default + Hash + Xorable> {
    prefix: Prefix<T>,
    groups: Groups<T>,
}



// Used when merging our own group to send to peers outwith the new group
#[derive(Debug)]
pub struct OtherMergeDetails<T: Binary + Clone + Copy + Default + Hash + Xorable> {
    prefix: Prefix<T>,
    group: HashSet<T>,
}



// A routing table to manage contacts for a node.
//
// It maintains a list of `T`s representing connected peer nodes, and provides algorithms for
// routing messages.
//
// See the [crate documentation](index.html) for details.
#[derive(Clone, Eq, PartialEq)]
pub struct RoutingTable<T: Binary + Clone + Copy + Default + Hash + Xorable> {
    our_name: T,
    min_group_size: usize,
    our_group_prefix: Prefix<T>,
    groups: Groups<T>,
    needed: HashSet<T>,
}

impl<T: Binary + Clone + Copy + Default + Hash + Xorable> RoutingTable<T> {
    pub fn new(our_name: T, min_group_size: usize) -> Self {
        let mut groups = HashMap::new();
        let our_group_prefix = Prefix::new(0, our_name);
        let _ = groups.insert(our_group_prefix, HashSet::new());
        RoutingTable {
            our_name: our_name,
            min_group_size: min_group_size,
            our_group_prefix: our_group_prefix,
            groups: groups,
            needed: HashSet::new(),
        }
    }

    // Total number of entries in the routing table.
    pub fn len(&self) -> usize {
        self.groups.values().fold(0, |acc, group| acc + group.len())
    }

    pub fn is_empty(&self) -> bool {
        self.groups.values().all(HashSet::is_empty)
    }

    pub fn iter(&self) -> Iter<T> {
        Iter { inner: self.groups.iter().flat_map(Iter::<T>::iterate) }
    }

    // Returns the list of contacts as a result of a merge to which we aren't currently connected,
    // but should be.
    pub fn needed(&self) -> &HashSet<T> {
        &self.needed
    }

    // Returns whether the given contact should be added to the routing table.
    //
    // Returns `false` if `name` already exists in the routing table, or it doesn't fall within any
    // of our groups, or it's our own name.  Otherwise it returns `true`.
    pub fn need_to_add(&self, name: &T) -> bool {
        if *name == self.our_name {
            return false;
        }
        if let Some(group) = self.get_group(name) {
            !group.contains(name)
        } else {
            false
        }
    }

    // Adds a contact to the routing table.
    //
    // Returns `Err` if `name` already existed in the routing table, or it doesn't fall within any
    // of our groups, or it's our own name.  Otherwise it returns `Ok(Some(prefix))` if the addition
    // succeeded and should cause our group to split (where `prefix` is the one which should split)
    // or `Ok(None)` if the addition succeeded and shouldn't cause a split.
    pub fn add(&mut self, name: T) -> Result<Option<Prefix<T>>, Error> {
        if name == self.our_name {
            return Err(Error::OwnNameDisallowed);
        }

        {
            if let Some(group) = self.get_mut_group(&name) {
                if !group.insert(name) {
                    return Err(Error::AlreadyExists);
                }
            } else {
                return Err(Error::PeerNameUnsuitable);
            }
        }

        let _ = self.needed.remove(&name);

        let our_group = unwrap!(self.groups.get(&self.our_group_prefix));
        // Count the number of names which will end up in our group if it is split
        let new_group_size = our_group.iter()
            .filter(|name| self.our_name.common_prefix(name) > self.our_group_prefix.bit_count())
            .count();
        // If either of the two new groups will not contain enough entries, return `None`.
        let min_size = self.min_group_size + SPLIT_BUFFER;
        Ok(if our_group.len() - new_group_size < min_size || new_group_size < min_size {
            None
        } else {
            Some(self.our_group_prefix)
        })
    }

    // Splits a group.
    //
    // If the group exists in the routing table, it is split, otherwise this function is a no-op.
    // If one of the two new groups doesn't satisfy the invariant (i.e. only differs in one bit from
    // our own prefix), it is removed and those contacts are returned.
    pub fn split(&mut self, mut prefix: Prefix<T>) -> Vec<T> {
        let mut result = vec![];
        if prefix == self.our_group_prefix {
            self.split_our_group();
            return result;
        }

        if let Some(to_split) = self.groups.remove(&prefix) {
            let new_prefix = prefix.split();
            let (group1, group2) = to_split.into_iter()
                .partition::<HashSet<_>, _>(|name| prefix.matches(name));

            if self.our_group_prefix.is_neighbour(&prefix) {
                assert!(self.groups.insert(prefix, group1).is_none());
            } else {
                result = group1.into_iter().collect_vec();
            }

            if self.our_group_prefix.is_neighbour(&new_prefix) {
                assert!(self.groups.insert(new_prefix, group2).is_none());
            } else {
                assert!(result.is_empty());
                result = group2.into_iter().collect_vec();
            }
        }
        result
    }

    // Removes a contact from the routing table.
    //
    // If no entry with that name is found, `None` is returned.  Otherwise, the entry is removed
    // from the routing table.  If, after removal, our group needs to merge, the appropriate targets
    // (all members of the merging groups) and the merge details they each need to receive (the new
    // prefix and all groups in the table) is returned, else `None` is returned.
    pub fn remove(&mut self, name: &T) -> Option<(Vec<T>, OwnMergeDetails<T>)> {
        let mut should_merge = false;
        if let Some(prefix) = self.find_group_prefix(name) {
            if let Some(group) = self.groups.get_mut(&prefix) {
                should_merge = group.remove(name) && prefix == self.our_group_prefix &&
                               group.len() < self.min_group_size;
            }
        }
        if should_merge {
            let mut merged_prefix = self.our_group_prefix;
            merged_prefix.merge();
            let targets = self.groups
                .iter()
                .filter(|&(prefix, _)| merged_prefix.is_compatible(prefix))
                .flat_map(|(_, names)| names.iter())
                .cloned()
                .collect_vec();
            Some((targets,
                  OwnMergeDetails {
                prefix: merged_prefix,
                groups: self.groups.clone(),
            }))
        } else {
            None
        }
    }

    // Merges our own group and all existing compatible groups into the new one defined by
    // `merge_details.prefix`.
    //
    // The appropriate targets (all contacts which are not part of the merging groups) and the merge
    // details they each need to receive (the new prefix and the new group) is returned.
    pub fn merge_own_group(&mut self,
                           merge_details: &OwnMergeDetails<T>)
                           -> (Vec<T>, OtherMergeDetails<T>) {
        self.merge(&merge_details.prefix);

        // For each provided group which is not currently in our routing table and which is not one
        // of the merging groups, add an empty group and cache the corresponding contacts
        for (prefix, contacts) in merge_details.groups
            .iter()
            .filter(|&(prefix, _)| !merge_details.prefix.is_compatible(prefix)) {
            if self.groups.entry(*prefix).or_insert_with(HashSet::new).is_empty() {
                self.needed.extend(contacts.into_iter());
            }
        }

        // Find all contacts outwith the merging group
        let targets = self.groups
            .iter()
            .filter(|&(prefix, _)| !merge_details.prefix.is_compatible(prefix))
            .flat_map(|(_, names)| names.iter())
            .cloned()
            .collect_vec();

        // Return the targets and the new group
        let other_details = OtherMergeDetails {
            prefix: merge_details.prefix,
            group: unwrap!(self.groups.get(&merge_details.prefix)).clone(),
        };
        (targets, other_details)
    }

    // Merges all existing compatible groups into the new one defined by `merge_details.prefix`.
    // Our own group is not included in the merge.
    //
    // The appropriate targets (all contacts from `merge_details.groups` which are not currently
    // held in the routing table) are returned so the caller can establish connections to these
    // peers and subsequently add them.
    pub fn merge_other_group(&mut self, merge_details: &OtherMergeDetails<T>) -> HashSet<T> {
        self.merge(&merge_details.prefix);

        // Establish list of provided contacts which are currently missing from our table.
        let existing_names =
            self.groups.iter().flat_map(|(_, names)| names.iter()).collect::<HashSet<_>>();
        merge_details.group
            .iter()
            .collect::<HashSet<_>>()
            .difference(&existing_names)
            .cloned()
            .cloned()
            .collect()
    }

    fn split_our_group(&mut self) {
        let our_group = unwrap!(self.groups.remove(&self.our_group_prefix));
        let (our_new_group, other_new_group) = our_group.into_iter()
            .partition::<HashSet<_>, _>(|name| {
                self.our_name.common_prefix(name) > self.our_group_prefix.bit_count()
            });
        assert!(self.groups.insert(self.our_group_prefix.split(), other_new_group).is_none());
        assert!(self.groups.insert(self.our_group_prefix, our_new_group).is_none());
    }

    fn merge(&mut self, new_prefix: &Prefix<T>) {
        // Partition the groups into those for merging and the rest
        let mut original_groups = Groups::new();
        mem::swap(&mut original_groups, &mut self.groups);
        let (groups_to_merge, mut groups) = original_groups.into_iter()
            .partition::<HashMap<_, _>, _>(|&(prefix, _)| new_prefix.is_compatible(&prefix));

        // Merge selected groups and add the merged group back in.
        let merged_names = groups_to_merge.into_iter()
            .flat_map(|(_, names)| names.into_iter())
            .collect::<HashSet<_>>();
        assert!(groups.insert(*new_prefix, merged_names).is_none());
        mem::swap(&mut groups, &mut self.groups);
        let merging_our_group = new_prefix.matches(&self.our_name);
        if merging_our_group {
            self.our_group_prefix = Prefix::new(new_prefix.bit_count(), self.our_name);
        }
    }

    fn get_group(&self, name: &T) -> Option<&HashSet<T>> {
        if let Some(prefix) = self.find_group_prefix(name) {
            return self.groups.get(&prefix);
        }
        None
    }

    fn get_mut_group(&mut self, name: &T) -> Option<&mut HashSet<T>> {
        if let Some(prefix) = self.find_group_prefix(name) {
            return self.groups.get_mut(&prefix);
        }
        None
    }

    // Returns the prefix of the group in which `name` belongs, or `None` if there is no such group
    // in the routing table.
    fn find_group_prefix(&self, name: &T) -> Option<Prefix<T>> {
        self.groups.keys().find(|&prefix| prefix.matches(name)).cloned()
    }
}

impl<T: Binary + Clone + Copy + Default + Hash + Xorable> Binary for RoutingTable<T> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        try!(writeln!(formatter,
                      "RoutingTable {{\n\tour_name: {:08b},\n\tmin_group_size: \
                       {},\n\tour_group_prefix: {:?},",
                      self.our_name,
                      self.min_group_size,
                      self.our_group_prefix));
        let mut groups = self.groups.iter().collect_vec();
        groups.sort_by(|&(lhs_prefix, _), &(rhs_prefix, _)| {
            lhs_prefix.max_identical_index(&self.our_name)
                .cmp(&rhs_prefix.max_identical_index(&self.our_name))
        });
        for (group_index, &(prefix, group)) in groups.iter().enumerate() {
            try!(write!(formatter, "\tgroup {} with {:?}: {{\n", group_index, prefix));
            for (name_index, name) in group.iter().enumerate() {
                let comma = if name_index == group.len() - 1 {
                    ""
                } else {
                    ","
                };
                try!(writeln!(formatter, "\t\t{:08b}{}", name, comma));
            }
            let comma = if group_index == groups.len() - 1 {
                "\t}"
            } else {
                "\t},"
            };
            try!(writeln!(formatter, "{}", comma));
        }
        write!(formatter, "}}")
    }
}

impl<T: Binary + Clone + Copy + Default + Hash + Xorable> Debug for RoutingTable<T> {
    fn fmt(&self, formatter: &mut Formatter) -> FmtResult {
        Binary::fmt(self, formatter)
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use prefix::Prefix;

    #[test]
    fn printout() {
        // let mut table = RoutingTable::new(170u8, 3);  // 10101010
        let mut table = RoutingTable::new(85u8, 3);  // 01010101
        for i in 1u16..256 {
            let node = (256u16 - i) as u8;
            if let Ok(Some(prefix)) = table.add(node) {
                let _ = table.split(prefix);
            }
            // print!("{:08b}  {}   ", i, 0u8.bucket_index(&(i as u8)));
            // for b in 0..8 {
            //     print!("{:7}", 0u8.differs_in_bit(&(i as u8), b));
            // }
            // println!("");
        }

        // // let _ = table.remove(&0b10100010);
        // // let _ = table.remove(&0b10100011);
        // // let _ = table.remove(&0b10100000);
        // // let _ = table.remove(&0b10100001);
        // // let _ = table.remove(&0b10100110);
        // // let _ = table.remove(&0b10100111);
        // assert!(unwrap!(table.remove(&0b10101011)).merged_bucket.is_none());
        // assert!(unwrap!(table.remove(&0b10101000)).merged_bucket.is_none());
        // assert!(unwrap!(table.remove(&0b10101001)).merged_bucket.is_none());
        // assert!(unwrap!(table.remove(&0b10101110)).merged_bucket.is_none());
        // // match table.remove(&0b10101111) {
        // //     Some(result) => println!("Merged bucket {}\n{:b}\n", unwrap!(result.merged_bucket), table),
        // //     None => panic!(),
        // // }
        // assert!(unwrap!(table.remove(&0b10101111)).merged_bucket.is_none());
        // assert!(unwrap!(table.remove(&0b10001010)).merged_bucket.is_none());
        // assert!(unwrap!(table.remove(&0b10001011)).merged_bucket.is_none());
        // assert!(unwrap!(table.remove(&0b10001000)).merged_bucket.is_none());
        // assert!(unwrap!(table.remove(&0b10001001)).merged_bucket.is_none());
        // assert!(unwrap!(table.remove(&0b10001110)).merged_bucket.is_none());
        // // match table.remove(&0b10001111) {
        // //     Some(result) => println!("Merged bucket {}\n{:b}\n", unwrap!(result.merged_bucket), table),
        // //     None => panic!(),
        // // }
        // assert!(unwrap!(table.remove(&0b10001111)).merged_bucket.is_none());
        println!("{:?}", table);

        let print = |names: &Vec<u8>| -> String {
            let mut result = "[".to_string();
            for (index, name) in names.iter().enumerate() {
                let comma = if index == names.len() - 1 { "" } else { ", " };
                result = format!("{}{:08b}{}", result, name, comma);
            }
            result.push_str("]");
            result
        };
        let mut prefix = Prefix::new(1, table.our_name.with_flipped_bit(0));
        let mut removed = table.split(prefix);
        println!("\n\nRemoved with {:?}: {}\n\n{:?}", prefix, print(&removed), table);

        prefix = Prefix::new(4, table.our_name.with_flipped_bit(3));
        removed = table.split(prefix);
        println!("\n\nRemoved with {:?}: {}\n\n{:?}", prefix, print(&removed), table);

        prefix = Prefix::new(2, table.our_name.with_flipped_bit(0));
        removed = table.split(prefix);
        println!("\n\nRemoved with {:?}: {}\n\n{:?}", prefix, print(&removed), table);

        prefix = Prefix::new(3, table.our_name.with_flipped_bit(0));
        removed = table.split(prefix);
        println!("\n\nRemoved with {:?}: {}\n\n{:?}", prefix, print(&removed), table);

        prefix = Prefix::new(4, table.our_name.with_flipped_bit(0));
        removed = table.split(prefix);
        println!("\n\nRemoved with {:?}: {}\n\n{:?}", prefix, print(&removed), table);

        prefix = Prefix::new(5, table.our_name.with_flipped_bit(0));
        removed = table.split(prefix);
        println!("\n\nRemoved with {:?}: {}\n\n{:?}", prefix, print(&removed), table);

        prefix = Prefix::new(6, table.our_name.with_flipped_bit(0));
        removed = table.split(prefix);
        println!("\n\nRemoved with {:?}: {}\n\n{:?}", prefix, print(&removed), table);

        let mut name = table.our_name.with_flipped_bit(0);
        name = name.with_flipped_bit(5);
        prefix = Prefix::new(6, name);
        removed = table.split(prefix);
        println!("\n\nRemoved with {:?}: {}\n\n{:?}", prefix, print(&removed), table);

        name = table.our_name.with_flipped_bit(4);
        prefix = Prefix::new(5, name);
        removed = table.split(prefix);
        println!("\n\nRemoved with {:?}: {}\n\n{:?}", prefix, print(&removed), table);

        prefix = Prefix::new(6, name);
        removed = table.split(prefix);
        println!("\n\nRemoved with {:?}: {}\n\n{:?}", prefix, print(&removed), table);

        name = name.with_flipped_bit(5);
        prefix = Prefix::new(6, name);
        removed = table.split(prefix);
        println!("\n\nRemoved with {:?}: {}\n\n{:?}", prefix, print(&removed), table);

        // let mut merged = table.our_group_prefix;
        // let mut p = vec![];
        // for i in 0..5 {
        //     merged.bit_count -= 1;
        //     p.push(merged);
        // }
        // for k in table.groups.keys() {
        //     println!("{:?}\t{:?}: {}\t{:?}: {}\t{:?}: {}\t{:?}: {}\t{:?}: {}  \t{:?}: {}", k, table.our_group_prefix, table.our_group_prefix.is_compatible(k), p[0], p[0].is_compatible(k),
        //         p[1], p[1].is_compatible(k), p[2], p[2].is_compatible(k), p[3], p[3].is_compatible(k), p[4], p[4].is_compatible(k));
        // }

        assert!(table.remove(&0b01010011).is_none());
        assert!(table.remove(&0b01010000).is_none());
        assert!(table.remove(&0b01010001).is_none());
        assert!(table.remove(&0b01010111).is_none());
        match table.remove(&0b01010010) {
            Some((targets, details)) => {
                println!("{:?}\n", table);
                for target in &targets {
                    println!("Sending merge details to {:08b}", target);
                }
                let merge_result = table.merge_own_group(&details);
                println!("{:?}\nMerged {:?} yielding {:?}\n", table, details.prefix, merge_result)
            }
            None => panic!(),
        }
    }
}
