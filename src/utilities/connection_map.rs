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

const _MAX_ENTRIES : usize = 100;

/// validates that the type can be validated with a public id
pub trait Identifiable {
    /// should return true if the public id is the validator for the type
    fn valid_public_id(&self, public_id: &::public_id::PublicId) -> bool;
}

/// ConnectionMap maintains a double directory to look up a connection or a name V
#[allow(unused)]
pub struct ConnectionMap<V> {
    connection_map: ::std::collections::BTreeMap<V, ::public_id::PublicId>,
    lookup_map: ::std::collections::HashMap<::crust::Connection, V>,
}

#[allow(unused)]
impl<V> ConnectionMap<V> where V: Ord + Clone + Identifiable + ::std::fmt::Debug {
    /// Create a new connection map
    pub fn new() -> ConnectionMap<V> {
        ConnectionMap {
            connection_map: ::std::collections::BTreeMap::new(),
            lookup_map: ::std::collections::HashMap::new(),
        }
    }

    /// Returns true if the identifier is unique in the map
    /// and the connection can be added.  Returns false if the public id is not valid
    /// for the given identifier, or if either the connection is already are registered.
    pub fn add_peer(&mut self, connection: ::crust::Connection, identifier: V,
            public_id: ::public_id::PublicId) -> bool {
        if !identifier.valid_public_id(&public_id) {
            debug!("Invalid public id {:?}.\n", public_id);
            return false;
        };
        if self.lookup_map.contains_key(&connection) {
            debug!("Connection map already contains connection {:?}.\n", connection);
            return false;
        };
        match self.connection_map.get(&identifier) {
            Some(stored_public_id) => { if stored_public_id != &public_id { return false; }},
            None => {},
        };
        if self.lookup_map.len() >= _MAX_ENTRIES { warn!("Exceeded maximum number of connections \
            {:?} when adding {:?} on {:?}", self.lookup_map.len(), identifier, connection); };
        let old_value = self.lookup_map.insert(connection, identifier.clone());
        debug!("Inserted {:?} {:?} into lookup map.\n", connection, identifier);
        debug_assert!(old_value.is_none(), "Already verified above the lookup_map does \
            not contain the connection; old identifier is {:?}", identifier);
        let _old_value = self.connection_map.insert(identifier, public_id);
        true
    }

    /// Removes the provided connection and returns the public id of this connection.
    /// If there are other connections still registered for the identity,  None is returned.
    pub fn drop_connection(&mut self, connection_to_drop: &::crust::Connection)
            -> Option<::public_id::PublicId> {
        let affected_identity = match self.lookup_map.remove(connection_to_drop) {
            Some(identity) => identity,
            None => return None,
        };
        if self.lookup_map.iter().find(|&(_, ref i)| **i == affected_identity).is_none() {
            debug!("Removed {:?} from connection map.\n", affected_identity);
            self.connection_map.remove(&affected_identity)
        } else { None }
    }

    /// Removes the given identity from the connection map if it exists, returning the public id
    /// and the connection.
    pub fn drop_identity(&mut self, identity: &V)
        -> (Option<::public_id::PublicId>, Vec<::crust::Connection>) {
        let public_id = self.connection_map.remove(identity);
        let connections = self.lookup_map.iter()
            .filter_map(|(c, i)| if i == identity { Some(c.clone()) } else { None })
            .collect::<Vec<::crust::Connection>>();
        for connection in &connections {
            let old_identity = self.lookup_map.remove(connection);
            debug_assert!( match old_identity {
                Some(ref iden) => iden == identity,
                None => false,
            });
        };
        (public_id, connections)
    }

    /// Returns Option<PublicId> if the connection is registered
    pub fn lookup_connection(&self, connection: &::crust::Connection)
        -> Option<&::public_id::PublicId> {
        match self.lookup_map.get(connection) {
            Some(identity) => self.connection_map.get(&identity),
            None => None,
        }
    }

    /// Returns the registered public id for a given identifier
    pub fn lookup_identity(&self, identity: &V)
        -> (Option<&::public_id::PublicId>, Vec<::crust::Connection>) {
        let public_id = self.connection_map.get(identity);
        let connections = self.lookup_map.iter()
            .filter_map(|(c, i)| if i == identity { Some(c.clone()) } else { None })
            .collect::<Vec<::crust::Connection>>();
        (public_id, connections)
    }

    /// Returns true if more connections are registered than the maximum allowed number of
    /// connections.
    pub fn is_full(&self) -> bool {
        self.lookup_map.len() >= _MAX_ENTRIES
    }

    /// Returns the number of registered unique identities
    pub fn identities_len(&self) -> usize {
        self.connection_map.len()
    }

    /// Returns the number of registered connections
    pub fn connections_len(&self) -> usize {
        self.lookup_map.len()
    }

    /// Returns all identities listed without connections or public identities
    pub fn identities(&self) -> Vec<V> {
        self.connection_map.keys().map(|v| v.clone()).collect::<Vec<V>>()
    }

    /// Returns all connections listed without identities or public identities
    pub fn connections(&self) -> Vec<::crust::Connection> {
        self.lookup_map.keys().map(|c| c.clone()).collect::<Vec<::crust::Connection>>()
    }

    /// Return a borrow to the full lookup_map
    pub fn lookup_map(&self) -> &::std::collections::HashMap<::crust::Connection, V> {
        &self.lookup_map
    }
}

#[cfg(test)]
mod test {

    #[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
    struct TestPeer {
        pub name: ::NameType,
    }

    impl super::Identifiable for TestPeer {
        fn valid_public_id(&self, public_id: &::public_id::PublicId) -> bool {
            self.name == public_id.name()
        }
    }

    // TODO: Use IPv6 and non-TCP
    pub fn random_socket_addr() -> ::std::net::SocketAddr {
        ::std::net::SocketAddr::V4(::std::net::SocketAddrV4::new(
            ::std::net::Ipv4Addr::new(::rand::random::<u8>(),
                                      ::rand::random::<u8>(),
                                      ::rand::random::<u8>(),
                                      ::rand::random::<u8>()),
            ::rand::random::<u16>()))
    }    

    pub fn random_connection() -> ::crust::Connection {
        let local = random_socket_addr();
        let remote = random_socket_addr();
        // TODO: Udt
        ::crust::Connection::new(::crust::Protocol::Tcp, local, remote)
    }

    #[test]
    fn add_max_peers() {
        let mut connection_map : super::ConnectionMap<TestPeer>
            = super::ConnectionMap::new();

        for i in 0..super::_MAX_ENTRIES + 1 {
            let id = ::id::Id::new();
            let public_id = ::public_id::PublicId::new(&id);
            let identity = TestPeer{ name: public_id.name() };
            let connection = random_connection();

            assert!(connection_map.add_peer(connection.clone(), identity.clone(),
                public_id.clone()));
            let (retrieved_from_identity, _) = connection_map.lookup_identity(&identity);
            assert!(retrieved_from_identity.is_some());
            assert_eq!(retrieved_from_identity.unwrap(), &public_id);
            let retrieved_from_connection = connection_map.lookup_connection(&connection);
            assert!(retrieved_from_connection.is_some());
            assert_eq!(retrieved_from_connection.unwrap(), &public_id);

            if i < super::_MAX_ENTRIES - 1 {
                assert!(!connection_map.is_full());
            } else {
                assert!(connection_map.is_full());
            }
        }
    }

    #[test]
    fn drop_connection() {
        let mut connection_map : super::ConnectionMap<TestPeer>
            = super::ConnectionMap::new();
        let public_id = ::public_id::PublicId::new(&::id::Id::new());
        let identity = TestPeer{ name: public_id.name() };
        let connection = random_connection();

        assert!(connection_map.add_peer(connection.clone(), identity.clone(), public_id.clone()));
        assert!(connection_map.lookup_identity(&identity).0.is_some());
        assert!(connection_map.lookup_connection(&connection).is_some());

        assert_eq!(connection_map.drop_connection(&connection).unwrap(), public_id);

        assert!(connection_map.lookup_identity(&identity).0.is_none());
        assert!(connection_map.lookup_connection(&connection).is_none());
    }

    #[test]
    fn multiple_connections() {
        let mut connection_map : super::ConnectionMap<TestPeer>
            = super::ConnectionMap::new();
        let public_id = ::public_id::PublicId::new(&::id::Id::new());
        let identity = TestPeer{ name: public_id.name() };
        let connection1 = random_connection();
        let connection2 = random_connection();
        assert!(connection2 != connection1);

        assert!(connection_map.add_peer(connection1.clone(), identity.clone(), public_id.clone()));
        assert!(connection_map.lookup_identity(&identity).0.is_some());
        assert!(connection_map.lookup_connection(&connection1).is_some());

        assert!(connection_map.add_peer(connection2.clone(), identity.clone(), public_id.clone()));
        assert!(connection_map.lookup_identity(&identity).0.is_some());
        assert!(connection_map.lookup_connection(&connection2).is_some());

        let (opt_public_id, registered_connections) = connection_map.drop_identity(&identity);
        assert!(opt_public_id.is_some());
        assert_eq!(registered_connections.len(), 2usize);
        assert!(registered_connections.contains(&connection1));
        assert!(registered_connections.contains(&connection2));

        assert!(connection_map.lookup_identity(&identity).0.is_none());
        assert!(connection_map.lookup_connection(&connection1).is_none());
        assert!(connection_map.lookup_connection(&connection2).is_none());
    }

    #[test]
    fn multiple_connections_drop_connection() {
        let mut connection_map : super::ConnectionMap<TestPeer>
            = super::ConnectionMap::new();
        let public_id = ::public_id::PublicId::new(&::id::Id::new());
        let identity = TestPeer{ name: public_id.name() };
        let connection1 = random_connection();
        let connection2 = random_connection();
        assert!(connection2 != connection1);

        assert!(connection_map.add_peer(connection1.clone(), identity.clone(), public_id.clone()));
        assert!(connection_map.lookup_identity(&identity).0.is_some());
        assert!(connection_map.lookup_connection(&connection1).is_some());

        assert!(connection_map.add_peer(connection2.clone(), identity.clone(), public_id.clone()));
        assert!(connection_map.lookup_identity(&identity).0.is_some());
        assert!(connection_map.lookup_connection(&connection2).is_some());

        assert!(connection_map.drop_connection(&connection1).is_none());

        assert!(connection_map.lookup_identity(&identity).0.is_some());
        assert!(connection_map.lookup_connection(&connection1).is_none());
        assert!(connection_map.lookup_connection(&connection2).is_some());

        assert_eq!(connection_map.drop_connection(&connection2).unwrap(), public_id);

        assert!(connection_map.lookup_identity(&identity).0.is_none());
        assert!(connection_map.lookup_connection(&connection1).is_none());
        assert!(connection_map.lookup_connection(&connection2).is_none());
    }
}
