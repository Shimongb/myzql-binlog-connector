//! MySQL Binlog Reader
//!
//! This module implements the core binlog streaming functionality.
//! It uses manual packet construction for the Binlog Dump command.
//!
//! References:
//! - https://dev.mysql.com/doc/c-api/8.0/en/c-api-binary-log-interface.html
//! - https://dev.mysql.com/doc/internals/en/com-binlog-dump.html

const std = @import("std");
const connection = @import("connection.zig");
const event_parser = @import("event_parser.zig");
const output = @import("output.zig");
const config_mod = @import("config.zig");
const Config = config_mod.Config;
const TableFilter = config_mod.table_filter.TableFilter;

const log = std.log.scoped(.binlog_reader);

const COM_BINLOG_DUMP = 0x12;
const BINLOG_DUMP_NON_BLOCK = 0x01;

/// Binlog Dump Command Packet Structure
const BinlogDumpCommand = struct {
    binlog_flags: u16,
    server_id: u32,
    binlog_filename: []const u8,
    binlog_position: u32,

    pub fn write(self: BinlogDumpCommand, writer: anytype) !void {
        try writer.writeByte(COM_BINLOG_DUMP);
        try writer.writeInt(u32, self.binlog_position, .little);
        try writer.writeInt(u16, self.binlog_flags, .little);
        try writer.writeInt(u32, self.server_id, .little);
        try writer.writeAll(self.binlog_filename);
    }
};

/// Binlog Reader with state tracking
pub const BinlogReader = struct {
    allocator: std.mem.Allocator,
    conn: *connection.Connection,
    config: Config,
    events_read: u64,

    // State tracking for current position in binlog stream
    current_binlog_file: []u8, // Current binlog file being read (owned, allocated)
    current_position: u64, // Current position in bytes

    // Table metadata cache for parsing ROW events
    // Maps table_id -> TableMetadata
    table_cache: std.AutoHashMap(u64, event_parser.TableMetadata),

    // Format description info from FORMAT_DESCRIPTION_EVENT
    format_description: ?event_parser.FormatDescriptionInfo,

    // Table filter for include/exclude logic
    table_filter: ?TableFilter,
    tables_filtered: u64,

    /// Initialize binlog reader with a connection
    pub fn init(allocator: std.mem.Allocator, conn: *connection.Connection, config: Config) !BinlogReader {
        const binlog_file_copy = try allocator.dupe(u8, config.from_binlog_file);
        errdefer allocator.free(binlog_file_copy);

        // Build table filter if include/exclude patterns are configured
        var filter: ?TableFilter = null;
        if (config.include != null or config.exclude != null) {
            filter = try TableFilter.init(allocator, config.include, config.exclude);
        }

        return BinlogReader{
            .allocator = allocator,
            .conn = conn,
            .config = config,
            .events_read = 0,
            .current_binlog_file = binlog_file_copy,
            .current_position = config.from_binlog_position,
            .table_cache = std.AutoHashMap(u64, event_parser.TableMetadata).init(allocator),
            .format_description = null,
            .table_filter = filter,
            .tables_filtered = 0,
        };
    }

    /// Deinitialize and free resources
    pub fn deinit(self: *BinlogReader) void {
        self.allocator.free(self.current_binlog_file);
        var iter = self.table_cache.valueIterator();
        while (iter.next()) |metadata| {
            metadata.deinit(self.allocator);
        }
        self.table_cache.deinit();
        if (self.table_filter) |*f| {
            f.deinit();
        }
    }

    /// Open binlog stream at specified position
    pub fn open(self: *BinlogReader) !void {
        log.info("opening binlog stream: {s}:{d}", .{
            self.config.from_binlog_file,
            self.config.from_binlog_position,
        });

        // Enable checksum support
        log.debug("enabling binlog checksum support", .{});
        self.conn.executeQuery("SET @master_binlog_checksum='CRC32'") catch |err| {
            log.warn("failed to set binlog checksum: {}", .{err});
        };

        // Construct and send Binlog Dump command
        // We need to construct the packet payload manually
        var payload = std.ArrayListUnmanaged(u8){};
        defer payload.deinit(self.allocator);

        const cmd = BinlogDumpCommand{
            .binlog_flags = 0, // Block until event available
            .server_id = 1, // Client server_id (should be unique)
            .binlog_filename = self.config.from_binlog_file,
            .binlog_position = @intCast(self.config.from_binlog_position),
        };

        // Manually serialize command into payload (ArrayList.writer removed in 0.16)
        try payload.append(self.allocator, COM_BINLOG_DUMP);
        try payload.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, cmd.binlog_position)));
        try payload.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToLittle(u16, cmd.binlog_flags)));
        try payload.appendSlice(self.allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, cmd.server_id)));
        try payload.appendSlice(self.allocator, cmd.binlog_filename);

        // Manual packet framing
        const length = payload.items.len;
        var header: [4]u8 = undefined;
        header[0] = @intCast(length & 0xFF);
        header[1] = @intCast((length >> 8) & 0xFF);
        header[2] = @intCast((length >> 16) & 0xFF);
        // Reset sequence_id for new command
        self.conn.conn.sequence_id = 0;
        header[3] = self.conn.conn.sequence_id;
        self.conn.conn.sequence_id +%= 1;

        try self.conn.conn.stream.writeAll(&header);
        try self.conn.conn.stream.writeAll(payload.items);

        log.info("binlog stream opened successfully", .{});
    }

    /// Fetch and process next binlog event
    pub fn fetchAndProcessEvent(self: *BinlogReader) !bool {
        // Check stop condition
        if (self.shouldStopAtCurrentPosition()) {
            log.info("reached target position, stopping gracefully", .{});
            return false;
        }

        // Read next packet
        const packet = self.conn.conn.readPacket() catch |err| {
            log.err("error reading packet: {}", .{err});
            return err;
        };

        // Check for EOF or Error packets
        if (packet.payload.len > 0) {
            const status = packet.payload[0];
            if (status == 0xFE) { // EOF
                log.info("received EOF packet", .{});
                return false;
            }
            if (status == 0xFF) { // Error
                if (packet.payload.len >= 9) {
                    const err_code = std.mem.readInt(u16, packet.payload[1..3], .little);
                    var msg_start: usize = 3;
                    if (packet.payload.len > 9 and packet.payload[3] == '#') {
                        msg_start = 9;
                    }
                    const err_msg = packet.payload[msg_start..];
                    log.err("received error packet: code={d} message={s}", .{ err_code, err_msg });
                } else {
                    log.err("received error packet (no details available)", .{});
                }
                return error.BinlogError;
            }
        }

        // Skip OK byte (0x00) if present
        // Binlog events usually start with 0x00 (OK) followed by event header
        var event_data = packet.payload;
        if (event_data.len > 0 and event_data[0] == 0x00) {
            event_data = event_data[1..];
        }

        if (event_data.len < 19) {
            // Too small for header
            return true;
        }

        // Parse event header
        const event = try event_parser.parseEventHeader(event_data);

        // Update position tracking
        self.current_position = event.log_pos;
        self.events_read += 1;

        // Periodic progress for stdout mode
        if (self.events_read % 10_000 == 0) {
            log.info("processed {d} events, position={d}", .{ self.events_read, self.current_position });
        }

        // Filter
        if (!event_parser.shouldProcessEvent(event.event_type)) {
            return true;
        }

        // Handle event types
        switch (event.event_type) {
            .ROTATE_EVENT => {
                const rotate = try event_parser.parseRotateEvent(self.allocator, event.data);
                defer self.allocator.free(rotate.next_binlog_file);

                log.info("binlog rotation: next_file={s}", .{rotate.next_binlog_file});

                self.allocator.free(self.current_binlog_file);
                self.current_binlog_file = try self.allocator.dupe(u8, rotate.next_binlog_file);
                self.current_position = rotate.next_position;

                if (self.config.to_binlog_file) |end_file| {
                    if (std.mem.order(u8, rotate.next_binlog_file, end_file) == .gt) {
                        return false;
                    }
                }
            },
            .FORMAT_DESCRIPTION_EVENT => {
                const format_desc = try event_parser.parseFormatDescriptionEvent(event.data);
                self.format_description = format_desc;
                log.info("format description: binlog_version={d}", .{format_desc.binlog_version});
            },
            .TABLE_MAP_EVENT => {
                const table_metadata = try event_parser.parseTableMapEvent(self.allocator, event.data);
                errdefer table_metadata.deinit(self.allocator);

                if (self.table_cache.fetchRemove(table_metadata.table_id)) |old_entry| {
                    old_entry.value.deinit(self.allocator);
                }
                try self.table_cache.put(table_metadata.table_id, table_metadata);

                log.debug("table_map: {s}.{s} (id={d})", .{ table_metadata.database_name, table_metadata.table_name, table_metadata.table_id });
            },
            .WRITE_ROWS_EVENT_V0, .WRITE_ROWS_EVENT, .UPDATE_ROWS_EVENT_V0, .UPDATE_ROWS_EVENT, .PARTIAL_UPDATE_ROWS_EVENT, .DELETE_ROWS_EVENT_V0, .DELETE_ROWS_EVENT => {
                if (event.data.len < 6) return true;

                const table_id_bytes = event.data[0..6];
                var table_id_u64: u64 = 0;
                // Read 6 bytes little endian
                table_id_u64 |= @as(u64, table_id_bytes[0]);
                table_id_u64 |= @as(u64, table_id_bytes[1]) << 8;
                table_id_u64 |= @as(u64, table_id_bytes[2]) << 16;
                table_id_u64 |= @as(u64, table_id_bytes[3]) << 24;
                table_id_u64 |= @as(u64, table_id_bytes[4]) << 32;
                table_id_u64 |= @as(u64, table_id_bytes[5]) << 40;

                if (self.table_cache.get(table_id_u64)) |metadata| {
                    const row_events = try event_parser.parseRowEvent(self.allocator, event.event_type, event.data, &metadata, self.format_description);
                    defer {
                        for (row_events) |*re| {
                            re.deinit(self.allocator);
                        }
                        self.allocator.free(row_events);
                    }
                    for (row_events) |row_event| {
                        output.printRowEvent(event, row_event);
                    }
                } else {
                    output.printEvent(event);
                }
            },
            else => {
                output.printEvent(event);
            },
        }

        return true;
    }

    fn shouldStopAtCurrentPosition(self: *BinlogReader) bool {
        if (self.config.to_binlog_file) |end_file| {
            const file_comparison = std.mem.order(u8, self.current_binlog_file, end_file);

            if (file_comparison == .gt) return true;
            if (file_comparison == .eq) {
                if (self.config.to_binlog_position) |end_pos| {
                    if (self.current_position >= end_pos) {
                        return true;
                    }
                    return false;
                }
                return false;
            }
            return false;
        } else if (self.config.to_binlog_position) |end_pos| {
            if (self.current_position >= end_pos) {
                return true;
            }
        }
        return false;
    }

    pub fn readAll(self: *BinlogReader) !void {
        log.info("reading binlog events (Ctrl+C to stop)", .{});

        var continue_reading = true;
        while (continue_reading) {
            continue_reading = self.fetchAndProcessEvent() catch |err| {
                log.err("error reading event: {}", .{err});
                return err;
            };
        }
        log.info("finished reading binlog, total events: {d}", .{self.events_read});
    }

    pub fn close(self: *BinlogReader) void {
        // Shutdown the TCP socket to terminate the binlog dump session.
        // Without this, conn.deinit() sends COM_QUIT and waits for a response,
        // but the server is still in binlog dump mode and blocks indefinitely.
        // Using shutdown() instead of close() keeps the fd valid so conn.deinit()
        // can still call stream.close() without hitting EBADF.
        _ = std.c.shutdown(self.conn.conn.stream.handle, 2); // SHUT_RDWR
    }

    /// Pull-based event fetching for pipeline integration.
    /// Returns parsed event data without printing. Caller owns returned RowEvent data.
    pub const FetchedEvent = union(enum) {
        rows: struct {
            event: event_parser.Event,
            row_events: []event_parser.RowEvent,
            table_metadata: event_parser.TableMetadata,
        },
        rotate: struct {
            next_binlog_file: []const u8,
        },
        format_description: event_parser.FormatDescriptionInfo,
        eof: void,
        skip: void,
    };

    pub fn fetchEvent(self: *BinlogReader) !?FetchedEvent {
        if (self.shouldStopAtCurrentPosition()) {
            return .eof;
        }

        const packet = self.conn.conn.readPacket() catch |err| {
            return err;
        };

        if (packet.payload.len > 0) {
            const status = packet.payload[0];
            if (status == 0xFE) return .eof;
            if (status == 0xFF) return error.BinlogError;
        }

        var event_data = packet.payload;
        if (event_data.len > 0 and event_data[0] == 0x00) {
            event_data = event_data[1..];
        }

        if (event_data.len < 19) return .skip;

        const event = try event_parser.parseEventHeader(event_data);
        self.current_position = event.log_pos;
        self.events_read += 1;

        if (!event_parser.shouldProcessEvent(event.event_type)) {
            return .skip;
        }

        switch (event.event_type) {
            .ROTATE_EVENT => {
                const rotate = try event_parser.parseRotateEvent(self.allocator, event.data);

                self.allocator.free(self.current_binlog_file);
                self.current_binlog_file = try self.allocator.dupe(u8, rotate.next_binlog_file);
                self.current_position = rotate.next_position;

                log.info("binlog rotation: next_file={s}", .{rotate.next_binlog_file});

                if (self.config.to_binlog_file) |end_file| {
                    if (std.mem.order(u8, rotate.next_binlog_file, end_file) == .gt) {
                        self.allocator.free(rotate.next_binlog_file);
                        return .eof;
                    }
                }

                return .{ .rotate = .{ .next_binlog_file = rotate.next_binlog_file } };
            },
            .FORMAT_DESCRIPTION_EVENT => {
                const format_desc = try event_parser.parseFormatDescriptionEvent(event.data);
                self.format_description = format_desc;
                log.info("format description: binlog_version={d}", .{format_desc.binlog_version});
                return .{ .format_description = format_desc };
            },
            .TABLE_MAP_EVENT => {
                const table_metadata = try event_parser.parseTableMapEvent(self.allocator, event.data);
                errdefer table_metadata.deinit(self.allocator);

                // Apply table filter: skip caching excluded tables so their
                // subsequent row events are automatically skipped (no metadata = no parsing)
                if (self.table_filter) |*filter| {
                    if (!filter.shouldInclude(table_metadata.database_name, table_metadata.table_name)) {
                        log.debug("table_map: FILTERED {s}.{s} (id={d})", .{ table_metadata.database_name, table_metadata.table_name, table_metadata.table_id });
                        // Remove from cache if previously cached (table_id reuse)
                        if (self.table_cache.fetchRemove(table_metadata.table_id)) |old_entry| {
                            old_entry.value.deinit(self.allocator);
                        }
                        table_metadata.deinit(self.allocator);
                        self.tables_filtered += 1;
                        return .skip;
                    }
                }

                if (self.table_cache.fetchRemove(table_metadata.table_id)) |old_entry| {
                    old_entry.value.deinit(self.allocator);
                }
                try self.table_cache.put(table_metadata.table_id, table_metadata);

                log.debug("table_map: {s}.{s} (id={d})", .{ table_metadata.database_name, table_metadata.table_name, table_metadata.table_id });
                return .skip;
            },
            .WRITE_ROWS_EVENT_V0, .WRITE_ROWS_EVENT, .UPDATE_ROWS_EVENT_V0, .UPDATE_ROWS_EVENT, .PARTIAL_UPDATE_ROWS_EVENT, .DELETE_ROWS_EVENT_V0, .DELETE_ROWS_EVENT => {
                if (event.data.len < 6) return .skip;

                const table_id_bytes = event.data[0..6];
                var table_id_u64: u64 = 0;
                table_id_u64 |= @as(u64, table_id_bytes[0]);
                table_id_u64 |= @as(u64, table_id_bytes[1]) << 8;
                table_id_u64 |= @as(u64, table_id_bytes[2]) << 16;
                table_id_u64 |= @as(u64, table_id_bytes[3]) << 24;
                table_id_u64 |= @as(u64, table_id_bytes[4]) << 32;
                table_id_u64 |= @as(u64, table_id_bytes[5]) << 40;

                if (self.table_cache.get(table_id_u64)) |metadata| {
                    const row_events = try event_parser.parseRowEvent(self.allocator, event.event_type, event.data, &metadata, self.format_description);

                    // Check stop condition after parsing
                    if (self.config.to_binlog_position) |end_pos| {
                        if (self.config.to_binlog_file == null or
                            std.mem.eql(u8, self.current_binlog_file, self.config.to_binlog_file.?))
                        {
                            if (event.log_pos >= end_pos) {
                                for (row_events) |*re| {
                                    re.deinit(self.allocator);
                                }
                                self.allocator.free(row_events);
                                return .eof;
                            }
                        }
                    }

                    return .{ .rows = .{
                        .event = event,
                        .row_events = row_events,
                        .table_metadata = metadata,
                    } };
                }
                return .skip;
            },
            else => return .skip,
        }
    }
};
