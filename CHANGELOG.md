# kademlia_routing_table - Change Log

## [0.4.0]
- Made `closest_nodes_to` public.
- Updated dependencies.

## [0.3.3]
- Don't relay messages to the node they were received from.

## [0.3.2]
- Allow get to return own node info.

## [0.3.1]
- Add a `find` method.

## [0.3.0]
- Make Routing generic again, without the previous restrictions, so it can
  store more peer information in addition to the `XorName` again.
- Add lots of integration tests.

## [0.2.0]
- Only manage `XorName`s, not connections or public IDs.
- Keep contacts sorted in buckets to speed up several methods.

## [0.1.1]
- Add the is_recipient method to move that logic out of the Routing crate.

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
