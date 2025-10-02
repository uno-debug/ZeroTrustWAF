// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

/**
 * @title WafLog
 * @dev Stores a log of security events from the WAF.
 */
contract WafLog {

    // A structure to hold details of each logged event
    struct LogEntry {
        uint256 timestamp;
        string sourceIP;
        string requestDetails;
        uint256 threatScore;
        string decision; // "BLOCKED" or "ALLOWED"
    }

    // An array to store all log entries
    LogEntry[] public allLogs;

    // An event that is emitted every time a new log is added
    event LogAdded(
        uint256 indexed timestamp,
        string sourceIP,
        uint256 threatScore,
        string decision
    );

    /**
     * @dev Adds a new security event to the blockchain.
     * This function will be called by your Python backend.
     */
    function addLog(
        string memory _sourceIP,
        string memory _requestDetails,
        uint256 _threatScore,
        string memory _decision
    ) public {
        // Create a new log entry in memory
        LogEntry memory newLog = LogEntry({
            timestamp: block.timestamp,
            sourceIP: _sourceIP,
            requestDetails: _requestDetails,
            threatScore: _threatScore,
            decision: _decision
        });

        // Add it to the storage array
        allLogs.push(newLog);

        // Emit an event to announce the new log
        emit LogAdded(block.timestamp, _sourceIP, _threatScore, _decision);
    }
    function getLogsCount() public view returns (uint256) {
        return allLogs.length;
    }
}