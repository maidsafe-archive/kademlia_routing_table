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

use xor_name::XorName;

/// Contact info about a node in the network.
pub trait ContactInfo: Clone + Eq {
    /// The type of node names. This should implement the `Xorable` trait.
    type Name;

    /// Returns the name of this contact.
    fn name(&self) -> &Self::Name;
}

impl ContactInfo for XorName {
    type Name = XorName;

    fn name(&self) -> &XorName {
        self
    }
}

impl ContactInfo for u64 {
    type Name = u64;

    fn name(&self) -> &u64 {
        self
    }
}

// This implementation exists mainly to facilitate writing tests. A real network should use enough
// bits to make the probability of name collisions negligible.
impl ContactInfo for u8 {
    type Name = u8;

    fn name(&self) -> &u8 {
        self
    }
}
