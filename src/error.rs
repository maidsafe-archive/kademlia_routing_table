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

//------------------------------------------------------------------------------
#[derive(PartialEq, Eq, Clone, Debug)]
/// InterfaceError.
pub enum InterfaceError {
    /// NotConnected.
    NotConnected,
}

impl ::std::error::Error for InterfaceError {
    fn description(&self) -> &str {
        match *self {
            InterfaceError::NotConnected => "Not Connected",
        }
    }

    fn cause(&self) -> Option<&::std::error::Error> {
        match *self {
            _ => None,
        }
    }
}

impl ::std::fmt::Display for InterfaceError {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self {
            InterfaceError::NotConnected =>
                ::std::fmt::Display::fmt("InterfaceError::NotConnected", formatter),
        }
    }
}

//------------------------------------------------------------------------------
/// ClientError.
pub enum ClientError {
    /// Report Input/Output error.
    Io(::std::io::Error),
    /// Report erialisation error.
    Cbor(::cbor::CborError),
}

impl From<::cbor::CborError> for ClientError {
    fn from(error: ::cbor::CborError) -> ClientError {
        ClientError::Cbor(error)
    }
}

impl From<::std::io::Error> for ClientError {
    fn from(error: ::std::io::Error) -> ClientError {
        ClientError::Io(error)
    }
}

//------------------------------------------------------------------------------
#[allow(variant_size_differences)]
#[derive(Debug)]
/// RoutingError.
pub enum RoutingError {
    /// The node/client has not bootstrapped yet
    NotBootstrapped,
    /// invalid requester or handler authorities
    BadAuthority,
    /// failure to connect to an already connected node
    AlreadyConnected,
    /// received message having unknown type
    UnknownMessageType,
    /// Failed signature check
    FailedSignature,
    /// Not Enough signatures
    NotEnoughSignatures,
    /// Duplicate signatures
    DuplicateSignatures,
    /// duplicate request received
    FilterCheckFailed,
    /// failure to bootstrap off the provided endpoints
    FailedToBootstrap,
    /// unexpected empty routing table
    RoutingTableEmpty,
    /// public id rejected because of unallowed relocated status
    RejectedPublicId,
    /// routing table did not add the node information,
    /// either because it was already added, or because it did not improve the routing table
    RefusedFromRoutingTable,
    /// We received a refresh message but it did not contain group source address
    RefreshNotFromGroup,
    /// String errors
    Utf8(::std::str::Utf8Error),
    /// interface error
    Interface(InterfaceError),
    /// i/o error
    Io(::std::io::Error),
    /// serialisation error
    Cbor(::cbor::CborError),
}

impl From<::std::str::Utf8Error> for RoutingError {
    fn from(error: ::std::str::Utf8Error) -> RoutingError {
        RoutingError::Utf8(error)
    }
}

impl From<::cbor::CborError> for RoutingError {
    fn from(error: ::cbor::CborError) -> RoutingError {
        RoutingError::Cbor(error)
    }
}

impl From<::std::io::Error> for RoutingError {
    fn from(error: ::std::io::Error) -> RoutingError {
        RoutingError::Io(error)
    }
}

impl From<InterfaceError> for RoutingError {
    fn from(error: InterfaceError) -> RoutingError {
        RoutingError::Interface(error)
    }
}

impl ::std::error::Error for RoutingError {
    fn description(&self) -> &str {
        match *self {
            RoutingError::NotBootstrapped => "Not bootstrapped",
            RoutingError::BadAuthority => "Invalid authority",
            RoutingError::AlreadyConnected => "Already connected",
            RoutingError::UnknownMessageType => "Invalid message type",
            RoutingError::FilterCheckFailed => "Filter check failure",
            RoutingError::FailedSignature => "Signature check failure",
            RoutingError::NotEnoughSignatures => "Not enough signatures",
            RoutingError::DuplicateSignatures => "Duplicated signatures",
            RoutingError::FailedToBootstrap => "Could not bootstrap",
            RoutingError::RoutingTableEmpty => "Routing table empty",
            RoutingError::RejectedPublicId => "Rejected Public Id",
            RoutingError::RefusedFromRoutingTable => "Refused from routing table",
            RoutingError::RefreshNotFromGroup => "Refresh message not from group",
            RoutingError::Utf8(_) => "String/Utf8 error",
            RoutingError::Interface(_) => "Interface error",
            RoutingError::Io(_) => "I/O error",
            RoutingError::Cbor(_) => "Serialisation error",
        }
    }

    fn cause(&self) -> Option<&::std::error::Error> {
        match *self {
            RoutingError::Interface(ref err) => Some(err),
            RoutingError::Io(ref err) => Some(err),
            // RoutingError::Cbor(ref err) => Some(err),
            _ => None,
        }
    }
}

impl ::std::fmt::Display for RoutingError {
    fn fmt(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self {
            RoutingError::NotBootstrapped =>
                ::std::fmt::Display::fmt("Not bootstrapped", formatter),
            RoutingError::BadAuthority =>
                ::std::fmt::Display::fmt("Bad authority", formatter),
            RoutingError::AlreadyConnected =>
                ::std::fmt::Display::fmt("Already connected", formatter),
            RoutingError::UnknownMessageType =>
                ::std::fmt::Display::fmt("Unknown message", formatter),
            RoutingError::FilterCheckFailed =>
                ::std::fmt::Display::fmt("Filter check failed", formatter),
            RoutingError::FailedSignature =>
                ::std::fmt::Display::fmt("Signature check failed", formatter),
            RoutingError::NotEnoughSignatures =>
                ::std::fmt::Display::fmt("Not enough signatures (multi-sig)", formatter),
            RoutingError::DuplicateSignatures =>
                ::std::fmt::Display::fmt("Duplicated signatures (multi-sig)", formatter),
            RoutingError::FailedToBootstrap =>
                ::std::fmt::Display::fmt("Could not bootstrap", formatter),
            RoutingError::RoutingTableEmpty =>
                ::std::fmt::Display::fmt("Routing table empty", formatter),
            RoutingError::RejectedPublicId =>
                ::std::fmt::Display::fmt("Rejected Public Id", formatter),
            RoutingError::RefusedFromRoutingTable =>
                ::std::fmt::Display::fmt("Refused from routing table", formatter),
            RoutingError::RefreshNotFromGroup =>
                ::std::fmt::Display::fmt("Refresh message not from group", formatter),
            RoutingError::Utf8(ref error) =>
                ::std::fmt::Display::fmt(error, formatter),
            RoutingError::Interface(ref error) =>
                ::std::fmt::Display::fmt(error, formatter),
            RoutingError::Io(ref error) =>
                ::std::fmt::Display::fmt(error, formatter),
            RoutingError::Cbor(ref error) =>
                ::std::fmt::Display::fmt(error, formatter),
        }
    }
}

