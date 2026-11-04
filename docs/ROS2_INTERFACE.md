# PRC ROS 2 byte interface

`prc_interfaces/srv/Exchange` at `/prc/controller/exchange` carries the
canonical byte protocol. Requests are limited to 65,664 bytes and responses
to 1,048,704 bytes, including the outer CBOR wrapper. The service supports
HELLO and EXECUTE; it has no report retrieval method.

ROS 2 Jazzy with `rmw_fastrtps_cpp` uses reliable, volatile service QoS. One
nonblocking server gate spans all callbacks. Overlapping calls may receive an
unsigned REJECTED/BUSY response; middleware can also queue them. Use one
coordinator and one outstanding call. Reliability does not guarantee exactly
once execution. A timeout or loss after possible dispatch means UNKNOWN; do
not retry or infer nonexecution.

HELLO is unsigned readiness, not attestation. Its deadline uses the controller's
monotonic clock; do not compare clocks across hosts. The client timeout is 180
seconds. The controller's report limit is 1,048,576 bytes; an integration may
apply a smaller explicit limit without truncating a report.

For identities, requests, responses and state handling see
[SCENE_INTERFACE.md](SCENE_INTERFACE.md). Signed schemas and limits are in
[PROTOCOL_CONTRACT.md](PROTOCOL_CONTRACT.md).
