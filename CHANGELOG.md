# kademlia_routing_table - Change Log

## [0.1.0]
- Major changes to the routing logic, so that some useful properties can be
  guaranteed.
- Expand the documentation.

## [0.0.5]
- Change the close group definition to ensure quorum can always be reached.
- Relay messages to the nodes closest to the target instead of our close group.

## [0.0.4]
- Add bucket index to NodeInfo\<T,U\>
- hash_node -> get (return option & NodeInfo)
- reduced some if statements with if/else if blocks

## [0.0.3]
- Remove unneeded library (clippy)
- Fixed typo in parallelism methods

## [0.0.2]
- Added functions to return constant values as usize
- Moved constants to u8
- Added function to return dynamic quorum size
- unpublished in crates.io

## [0.0.1]
- Initial Implementation
