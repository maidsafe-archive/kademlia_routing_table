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

use node_info::NodeInfo;
use std::fmt::Debug;

/// This is returned by `RoutingTable::add_node` if a new node has been added.
#[derive(PartialEq, Eq, Debug)]
pub struct AddedNodeDetails<T> where T: Clone + Debug + Eq {
    /// The list of contacts that need to be notified about the new node: If the bucket was
    /// already full, that's nobody, but if it wasn't, everyone with a bucket index greater than
    /// the new nodes' must be notified.
    pub must_notify: Vec<NodeInfo<T>>,
    /// Whether we are together in any close group with that contact.
    pub common_groups: bool,
}

/// This is returned by `RoutingTable::drop_connection` if a node was dropped.
///
/// If the dropped connection was the last one that connected us to one of the table's entries,
/// that node is removed from the table.
#[derive(PartialEq, Eq, Debug)]
pub struct DroppedNodeDetails {
    /// `Some(i)` if the entry has been removed from a full bucket with index `i`, indicating
    /// that an attempt to refill that bucket has to be made.
    pub incomplete_bucket: Option<usize>,
    /// Whether we were together in any close group with that contact.
    pub common_groups: bool,
}
