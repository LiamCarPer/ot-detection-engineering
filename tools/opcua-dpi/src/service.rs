//! Service NodeId decoding and the names of the standard services.
//!
//! A service message body begins with the ExtensionObject type id: a NodeId
//! identifying the service (for example `ReadRequest` 631, `WriteRequest` 673).
//! The identifiers used here are the `..._Encoding_DefaultBinary` values from
//! OPC UA Part 6, Annex A.

/// A numeric NodeId.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceNodeId {
    /// Namespace index.
    pub namespace: u16,
    /// Numeric identifier.
    pub identifier: u32,
}

/// Decode a numeric NodeId from the start of `bytes`.
pub fn parse_node_id(bytes: &[u8]) -> Option<ServiceNodeId> {
    match *bytes.first()? {
        0x00 => Some(ServiceNodeId {
            namespace: 0,
            identifier: u32::from(*bytes.get(1)?),
        }),
        0x01 => Some(ServiceNodeId {
            namespace: u16::from(*bytes.get(1)?),
            identifier: u32::from(u16::from_le_bytes(bytes.get(2..4)?.try_into().ok()?)),
        }),
        0x02 => Some(ServiceNodeId {
            namespace: u16::from_le_bytes(bytes.get(1..3)?.try_into().ok()?),
            identifier: u32::from_le_bytes(bytes.get(3..7)?.try_into().ok()?),
        }),
        _ => None,
    }
}

/// Name of a standard OPC UA service, or `None` for an unknown identifier.
pub fn service_name(identifier: u32) -> Option<&'static str> {
    Some(match identifier {
        422 => "FindServersRequest",
        425 => "FindServersResponse",
        428 => "GetEndpointsRequest",
        431 => "GetEndpointsResponse",
        461 => "CreateSessionRequest",
        464 => "CreateSessionResponse",
        467 => "ActivateSessionRequest",
        470 => "ActivateSessionResponse",
        473 => "CloseSessionRequest",
        476 => "CloseSessionResponse",
        488 => "AddNodesRequest",
        491 => "AddNodesResponse",
        494 => "AddReferencesRequest",
        497 => "AddReferencesResponse",
        500 => "DeleteNodesRequest",
        503 => "DeleteNodesResponse",
        506 => "DeleteReferencesRequest",
        509 => "DeleteReferencesResponse",
        527 => "BrowseRequest",
        530 => "BrowseResponse",
        533 => "BrowseNextRequest",
        536 => "BrowseNextResponse",
        554 => "TranslateBrowsePathsToNodeIdsRequest",
        557 => "TranslateBrowsePathsToNodeIdsResponse",
        560 => "RegisterNodesRequest",
        563 => "RegisterNodesResponse",
        566 => "UnregisterNodesRequest",
        569 => "UnregisterNodesResponse",
        631 => "ReadRequest",
        634 => "ReadResponse",
        664 => "HistoryReadRequest",
        667 => "HistoryReadResponse",
        673 => "WriteRequest",
        676 => "WriteResponse",
        712 => "CallRequest",
        715 => "CallResponse",
        787 => "CreateSubscriptionRequest",
        790 => "CreateSubscriptionResponse",
        826 => "PublishRequest",
        829 => "PublishResponse",
        _ => return None,
    })
}

/// Request or response direction, inferred from the service name suffix.
pub fn direction(name: &str) -> &'static str {
    if name.ends_with("Request") {
        "request"
    } else if name.ends_with("Response") {
        "response"
    } else {
        "unknown"
    }
}
