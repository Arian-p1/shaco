/// Represents the strategy in which the port scanning will run.
///   - Serial will run from start to end, for example 1 to 1_000.
///   - Random will randomize the order in which ports will be scanned.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ScanOrder {
    Serial,
}
/// Represents the range of ports to be scanned.
#[derive(Debug, Clone, PartialEq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}