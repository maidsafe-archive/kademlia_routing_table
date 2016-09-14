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

quick_error! {
    /// Routing table error variants.
    #[derive(Debug)]
    pub enum Error {
        /// Adding our own name to the routing table is disallowed.
        OwnNameDisallowed {
            description("Own name disallowed")
            display("Our own name is not allowed to be added to the routing table.")
        }
        /// The peer name to be added doesn't fall within any group in the routing table.
        PeerNameUnsuitable {
            description("Peer name unsuitable")
            display("Peer's name can't be added to the routing table as it's outwith all groups.")
        }
        /// The peer name to be added already exists in the routing table.
        AlreadyExists {
            description("Peer name already exists")
            display("Peer's name has already been added to the routing table.")
        }
    }
}
