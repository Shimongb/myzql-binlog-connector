//! Native Parquet File Writer
//!
//! Writes Parquet files with a fixed 9-column schema for CDC events.
//! Uses Thrift compact protocol for metadata, PLAIN encoding for data,
//! and GZIP compression for data pages.
//!
//! Schema:
//!   required INT64      timestamp
//!   required INT32      server_id
//!   required INT64      log_pos
//!   required INT64      event_row_index (1-based index of row within the binlog event)
//!   optional BYTE_ARRAY database       (UTF8)
//!   optional BYTE_ARRAY table_name     (UTF8)
//!   required BYTE_ARRAY dml_type       (UTF8)
//!   optional BYTE_ARRAY before_values  (UTF8)
//!   optional BYTE_ARRAY after_values   (UTF8)

const std = @import("std");
const thrift = @import("thrift_compact.zig");
const object_store = @import("object_store.zig");

const PARQUET_MAGIC = "PAR1";

/// Column index constants
const COL_TIMESTAMP = 0;
const COL_SERVER_ID = 1;
const COL_LOG_POS = 2;
const COL_EVENT_ROW_INDEX = 3;
const COL_DATABASE = 4;
const COL_TABLE_NAME = 5;
const COL_DML_TYPE = 6;
const COL_BEFORE_VALUES = 7;
const COL_AFTER_VALUES = 8;
const NUM_COLUMNS = 9;

/// Parquet physical types
const ParquetType = enum(i32) {
    BOOLEAN = 0,
    INT32 = 1,
    INT64 = 2,
    INT96 = 3,
    FLOAT = 4,
    DOUBLE = 5,
    BYTE_ARRAY = 6,
    FIXED_LEN_BYTE_ARRAY = 7,
};

/// Repetition types
const Repetition = enum(i32) {
    REQUIRED = 0,
    OPTIONAL = 1,
    REPEATED = 2,
};

/// Converted types
const ConvertedType = enum(i32) {
    UTF8 = 0,
};

/// Encoding types
const Encoding = enum(i32) {
    PLAIN = 0,
    RLE = 3,
};

/// Compression codec
const CompressionCodec = enum(i32) {
    UNCOMPRESSED = 0,
    GZIP = 2,
};

/// Page type
const PageType = enum(i32) {
    DATA_PAGE = 0,
};

/// Column schema definition
const ColumnDef = struct {
    name: []const u8,
    physical_type: ParquetType,
    repetition: Repetition,
    converted_type: ?ConvertedType,
};

const SCHEMA: [NUM_COLUMNS]ColumnDef = .{
    .{ .name = "timestamp", .physical_type = .INT64, .repetition = .REQUIRED, .converted_type = null },
    .{ .name = "server_id", .physical_type = .INT32, .repetition = .REQUIRED, .converted_type = null },
    .{ .name = "log_pos", .physical_type = .INT64, .repetition = .REQUIRED, .converted_type = null },
    .{ .name = "event_row_index", .physical_type = .INT64, .repetition = .REQUIRED, .converted_type = null },
    .{ .name = "database", .physical_type = .BYTE_ARRAY, .repetition = .OPTIONAL, .converted_type = .UTF8 },
    .{ .name = "table_name", .physical_type = .BYTE_ARRAY, .repetition = .OPTIONAL, .converted_type = .UTF8 },
    .{ .name = "dml_type", .physical_type = .BYTE_ARRAY, .repetition = .REQUIRED, .converted_type = .UTF8 },
    .{ .name = "before_values", .physical_type = .BYTE_ARRAY, .repetition = .OPTIONAL, .converted_type = .UTF8 },
    .{ .name = "after_values", .physical_type = .BYTE_ARRAY, .repetition = .OPTIONAL, .converted_type = .UTF8 },
};

fn isOptional(col_idx: usize) bool {
    return SCHEMA[col_idx].repetition == .OPTIONAL;
}

/// Metadata about a written column chunk (collected during write for footer)
const ColumnChunkInfo = struct {
    file_offset: i64,
    total_compressed_size: i64,
    total_uncompressed_size: i64,
    data_page_offset: i64,
    num_values: i64,
    codec: CompressionCodec,
};

/// Metadata about a written row group
const RowGroupInfo = struct {
    columns: [NUM_COLUMNS]ColumnChunkInfo,
    num_rows: i64,
    total_byte_size: i64,
};

/// Batch data passed to writeRowGroup
pub const RowBatch = struct {
    count: usize,
    timestamps: []const i64,
    server_ids: []const i32,
    log_positions: []const i64,
    event_row_indices: []const i64,
    databases: []const ?[]const u8,
    table_names: []const ?[]const u8,
    dml_types: []const []const u8,
    before_values_json: []const ?[]const u8,
    after_values_json: []const ?[]const u8,
};

pub const ParquetWriter = struct {
    // File creation is deferred until the first row group is written. This
    // avoids emitting zero-row parquet files on binlog rotations that carry
    // no DML (e.g. idle segments). An empty-but-valid parquet is still
    // readable individually, but mixing them into a directory glob makes
    // downstream readers iterate extra files for no benefit — and a broken
    // empty file (pre-0.16 gzip bug) would poison the whole glob.
    //
    // Writes go through ObjectStore.WriteHandle: a sidecar temp file is
    // opened lazily, written chunk by chunk, and renamed into place on
    // `finish()` (commit). `deinit()` on an unfinished writer aborts the
    // sidecar so partial data never becomes visible.
    write_handle: ?object_store.WriteHandle,
    store: *object_store.ObjectStore,
    key: []const u8,
    allocator: std.mem.Allocator,
    row_groups: std.ArrayList(RowGroupInfo),
    total_rows: i64,
    bytes_written: u64,

    pub fn init(
        allocator: std.mem.Allocator,
        store: *object_store.ObjectStore,
        key: []const u8,
    ) !ParquetWriter {
        return ParquetWriter{
            .write_handle = null,
            .store = store,
            .key = try allocator.dupe(u8, key),
            .allocator = allocator,
            .row_groups = .empty,
            .total_rows = 0,
            .bytes_written = 0,
        };
    }

    pub fn deinit(self: *ParquetWriter) void {
        self.row_groups.deinit(self.allocator);
        // If finish() wasn't called (or failed before commit), discard the
        // sidecar so no partial file is left visible.
        if (self.write_handle) |*h| h.abort();
        self.allocator.free(self.key);
    }

    /// Lazily open the write handle and emit the leading PAR1 magic on
    /// first use.
    fn ensureOpen(self: *ParquetWriter) !*object_store.WriteHandle {
        if (self.write_handle == null) {
            var h = try self.store.create(self.key);
            errdefer h.abort();
            try h.write(PARQUET_MAGIC);
            self.write_handle = h;
            self.bytes_written = 4;
        }
        return &self.write_handle.?;
    }

    pub fn writeRowGroup(self: *ParquetWriter, batch: *const RowBatch) !void {
        if (batch.count == 0) return;
        _ = try self.ensureOpen();

        var rg_info: RowGroupInfo = undefined;
        rg_info.num_rows = @intCast(batch.count);
        var total_byte_size: i64 = 0;

        // Write each column chunk
        inline for (0..NUM_COLUMNS) |col_idx| {
            const chunk_info = try self.writeColumnChunk(batch, col_idx);
            rg_info.columns[col_idx] = chunk_info;
            total_byte_size += chunk_info.total_compressed_size;
        }

        rg_info.total_byte_size = total_byte_size;
        self.total_rows += rg_info.num_rows;
        try self.row_groups.append(self.allocator, rg_info);
    }

    fn writeColumnChunk(self: *ParquetWriter, batch: *const RowBatch, comptime col_idx: usize) !ColumnChunkInfo {
        const num_values = batch.count;
        const optional = comptime isOptional(col_idx);

        // Encode column data (PLAIN encoding)
        var data_buf: std.ArrayList(u8) = .empty;
        defer data_buf.deinit(self.allocator);

        // For optional columns, write definition levels first
        if (optional) {
            try writeDefinitionLevels(self.allocator, &data_buf, batch, col_idx);
        }

        // Write values
        try encodeColumnValues(self.allocator, &data_buf, batch, col_idx);

        const uncompressed_size: i64 = @intCast(data_buf.items.len);

        // Compress with gzip
        const codec = CompressionCodec.GZIP;

        var output_alloc = try std.Io.Writer.Allocating.initCapacity(self.allocator, 4096);
        defer output_alloc.deinit();

        // Compress buffer must be >= flate.max_window_len (65536)
        var compress_window: [65536]u8 = undefined;

        var compressor = try std.compress.flate.Compress.init(
            &output_alloc.writer,
            &compress_window,
            .gzip,
            .default,
        );

        // Write uncompressed data through compressor.
        // NOTE: Zig 0.16.0's std.compress.flate splits stream termination into
        // two steps — `flush` only sync-aligns buffered bytes, while `finish`
        // emits the final deflate block *and* the gzip trailer (CRC32+ISIZE).
        // Using `flush` here produced truncated gzip streams that downstream
        // readers (DuckDB, Python gzip) rejected with "data error" / "ended
        // before end-of-stream marker". `finish` is the correct terminator.
        compressor.writer.writeAll(data_buf.items) catch return error.CompressionFailed;
        compressor.finish() catch return error.CompressionFailed;

        const compressed_data = output_alloc.written();

        const compressed_size: i64 = @intCast(compressed_data.len);

        // Build page header
        var page_header_buf: std.ArrayList(u8) = .empty;
        defer page_header_buf.deinit(self.allocator);

        {
            var tw = thrift.ThriftCompactWriter.init(self.allocator);
            defer tw.deinit();

            tw.beginRootStruct();
            // PageHeader.type = DATA_PAGE (field 1)
            try tw.writeI32(1, @intFromEnum(PageType.DATA_PAGE));
            // PageHeader.uncompressed_page_size (field 2)
            try tw.writeI32(2, @intCast(uncompressed_size));
            // PageHeader.compressed_page_size (field 3)
            try tw.writeI32(3, @intCast(compressed_size));
            // PageHeader.data_page_header (field 5, struct)
            try tw.beginStruct(5);
            // DataPageHeader.num_values (field 1)
            try tw.writeI32(1, @intCast(num_values));
            // DataPageHeader.encoding (field 2) = PLAIN
            try tw.writeI32(2, @intFromEnum(Encoding.PLAIN));
            // DataPageHeader.definition_level_encoding (field 3) = RLE
            try tw.writeI32(3, @intFromEnum(Encoding.RLE));
            // DataPageHeader.repetition_level_encoding (field 4) = RLE
            try tw.writeI32(4, @intFromEnum(Encoding.RLE));
            try tw.endStruct();
            try tw.endRootStruct();

            try page_header_buf.appendSlice(self.allocator, tw.getWritten());
        }

        // Record file offset for this column chunk
        const file_offset: i64 = @intCast(self.bytes_written);
        const data_page_offset = file_offset;

        // Write page header + compressed data.
        // `writeRowGroup` has already ensured the handle is open, so unwrap directly.
        const handle = &self.write_handle.?;
        try handle.write(page_header_buf.items);
        try handle.write(compressed_data);

        const total_written = page_header_buf.items.len + compressed_data.len;
        self.bytes_written += total_written;

        return ColumnChunkInfo{
            .file_offset = file_offset,
            .total_compressed_size = @intCast(total_written),
            .total_uncompressed_size = @intCast(page_header_buf.items.len + @as(usize, @intCast(uncompressed_size))),
            .data_page_offset = data_page_offset,
            .num_values = @intCast(num_values),
            .codec = codec,
        };
    }

    fn writeDefinitionLevels(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), batch: *const RowBatch, comptime col_idx: usize) !void {
        // RLE/bit-packed encoding for definition levels
        // max_def_level = 1, so 1 bit per value
        // Format: [4-byte encoded length][RLE data]
        var rle_buf: std.ArrayList(u8) = .empty;
        defer rle_buf.deinit(allocator);

        // Gather def levels
        const count = batch.count;
        var levels = try allocator.alloc(u8, count);
        defer allocator.free(levels);

        for (0..count) |i| {
            levels[i] = if (getOptionalValue(batch, col_idx, i) != null) 1 else 0;
        }

        // Encode as bit-packed groups of 8
        var pos: usize = 0;
        while (pos < count) {
            const remaining = count - pos;
            const group_size = @min(remaining, 8);
            const num_groups: usize = 1;

            // Header: (num_groups << 1) | 1
            try rle_buf.append(allocator, @intCast((num_groups << 1) | 1));

            // Pack bits into a byte
            var pack_val: u8 = 0;
            for (0..group_size) |j| {
                if (levels[pos + j] == 1) {
                    pack_val |= @as(u8, 1) << @intCast(j);
                }
            }
            try rle_buf.append(allocator, pack_val);
            pos += group_size;
        }

        // Write 4-byte length prefix + RLE data
        const rle_len: u32 = @intCast(rle_buf.items.len);
        try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, rle_len)));
        try buf.appendSlice(allocator, rle_buf.items);
    }

    fn getOptionalValue(batch: *const RowBatch, comptime col_idx: usize, i: usize) ?[]const u8 {
        return switch (col_idx) {
            COL_DATABASE => batch.databases[i],
            COL_TABLE_NAME => batch.table_names[i],
            COL_BEFORE_VALUES => batch.before_values_json[i],
            COL_AFTER_VALUES => batch.after_values_json[i],
            else => unreachable,
        };
    }

    fn encodeColumnValues(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), batch: *const RowBatch, comptime col_idx: usize) !void {
        switch (col_idx) {
            COL_TIMESTAMP => {
                for (batch.timestamps[0..batch.count]) |v| {
                    try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(i64, v)));
                }
            },
            COL_SERVER_ID => {
                for (batch.server_ids[0..batch.count]) |v| {
                    try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(i32, v)));
                }
            },
            COL_LOG_POS => {
                for (batch.log_positions[0..batch.count]) |v| {
                    try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(i64, v)));
                }
            },
            COL_EVENT_ROW_INDEX => {
                for (batch.event_row_indices[0..batch.count]) |v| {
                    try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(i64, v)));
                }
            },
            COL_DATABASE => {
                for (batch.databases[0..batch.count]) |opt_v| {
                    if (opt_v) |v| {
                        try writeByteArray(allocator, buf, v);
                    }
                }
            },
            COL_TABLE_NAME => {
                for (batch.table_names[0..batch.count]) |opt_v| {
                    if (opt_v) |v| {
                        try writeByteArray(allocator, buf, v);
                    }
                }
            },
            COL_DML_TYPE => {
                for (batch.dml_types[0..batch.count]) |v| {
                    try writeByteArray(allocator, buf, v);
                }
            },
            COL_BEFORE_VALUES => {
                for (batch.before_values_json[0..batch.count]) |opt_v| {
                    if (opt_v) |v| {
                        try writeByteArray(allocator, buf, v);
                    }
                }
            },
            COL_AFTER_VALUES => {
                for (batch.after_values_json[0..batch.count]) |opt_v| {
                    if (opt_v) |v| {
                        try writeByteArray(allocator, buf, v);
                    }
                }
            },
            else => unreachable,
        }
    }

    fn writeByteArray(allocator: std.mem.Allocator, buf: *std.ArrayList(u8), data: []const u8) !void {
        const len: u32 = @intCast(data.len);
        try buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToLittle(u32, len)));
        try buf.appendSlice(allocator, data);
    }

    pub fn finish(self: *ParquetWriter) !void {
        // If no row groups were written, discard any in-flight sidecar and
        // skip the footer — the output directory stays free of zero-row
        // parquets. Downstream readers using `dir/*.parquet` globs would
        // otherwise have to open (and tolerate) empty files on every rotate.
        if (self.write_handle == null or self.row_groups.items.len == 0) {
            if (self.write_handle) |*h| {
                h.abort();
                self.write_handle = null;
            }
            return;
        }

        // Encode FileMetaData using Thrift compact protocol
        var tw = thrift.ThriftCompactWriter.init(self.allocator);
        defer tw.deinit();

        tw.beginRootStruct();

        // FileMetaData.version (field 1) = 2
        try tw.writeI32(1, 2);

        // FileMetaData.schema (field 2) = list of SchemaElement
        try tw.beginList(2, .struct_, NUM_COLUMNS + 1);

        // Root schema element
        try tw.beginListStructElement();
        try tw.writeString(4, "schema"); // name (field 4)
        try tw.writeI32(5, NUM_COLUMNS); // num_children (field 5)
        try tw.endListStructElement();

        // Column schema elements
        inline for (0..NUM_COLUMNS) |col_idx| {
            const col = SCHEMA[col_idx];
            try tw.beginListStructElement();
            try tw.writeI32(1, @intFromEnum(col.physical_type));
            try tw.writeI32(3, @intFromEnum(col.repetition));
            try tw.writeString(4, col.name);
            if (col.converted_type) |ct| {
                try tw.writeI32(6, @intFromEnum(ct));
            }
            try tw.endListStructElement();
        }

        // FileMetaData.num_rows (field 3)
        try tw.writeI64(3, self.total_rows);

        // FileMetaData.row_groups (field 4) = list of RowGroup
        try tw.beginList(4, .struct_, self.row_groups.items.len);

        for (self.row_groups.items) |rg| {
            try tw.beginListStructElement();

            // RowGroup.columns (field 1) = list of ColumnChunk
            try tw.beginList(1, .struct_, NUM_COLUMNS);

            inline for (0..NUM_COLUMNS) |col_idx| {
                const chunk = rg.columns[col_idx];
                try tw.beginListStructElement();

                // ColumnChunk.file_offset (field 2)
                try tw.writeI64(2, chunk.file_offset);

                // ColumnChunk.meta_data (field 3) = ColumnMetaData struct
                try tw.beginStruct(3);

                // ColumnMetaData.type (field 1)
                try tw.writeI32(1, @intFromEnum(SCHEMA[col_idx].physical_type));

                // ColumnMetaData.encodings (field 2) = list of Encoding
                if (comptime isOptional(col_idx)) {
                    try tw.writeI32List(2, &.{ @intFromEnum(Encoding.PLAIN), @intFromEnum(Encoding.RLE) });
                } else {
                    try tw.writeI32List(2, &.{@intFromEnum(Encoding.PLAIN)});
                }

                // ColumnMetaData.path_in_schema (field 3) = list of string
                try tw.beginList(3, .binary, 1);
                try tw.writeVarint(SCHEMA[col_idx].name.len);
                try tw.appendRawSlice(SCHEMA[col_idx].name);

                // ColumnMetaData.codec (field 4)
                try tw.writeI32(4, @intFromEnum(chunk.codec));

                // ColumnMetaData.num_values (field 5)
                try tw.writeI64(5, chunk.num_values);

                // ColumnMetaData.total_uncompressed_size (field 6)
                try tw.writeI64(6, chunk.total_uncompressed_size);

                // ColumnMetaData.total_compressed_size (field 7)
                try tw.writeI64(7, chunk.total_compressed_size);

                // ColumnMetaData.data_page_offset (field 9)
                try tw.writeI64(9, chunk.data_page_offset);

                try tw.endStruct(); // end ColumnMetaData
                try tw.endListStructElement(); // end ColumnChunk
            }

            // RowGroup.total_byte_size (field 2)
            try tw.writeI64(2, rg.total_byte_size);

            // RowGroup.num_rows (field 3)
            try tw.writeI64(3, rg.num_rows);

            try tw.endListStructElement(); // end RowGroup
        }

        // FileMetaData.created_by (field 5)
        try tw.writeString(5, "myzql-binlog-connector");

        try tw.endRootStruct();

        // Write footer. The early-return above guarantees `self.write_handle`
        // is non-null here.
        const handle = &self.write_handle.?;
        const footer_data = tw.getWritten();
        try handle.write(footer_data);

        // Write footer length (4 bytes LE)
        const footer_len: u32 = @intCast(footer_data.len);
        try handle.write(&std.mem.toBytes(std.mem.nativeToLittle(u32, footer_len)));

        // Write trailing magic
        try handle.write(PARQUET_MAGIC);

        self.bytes_written += footer_data.len + 4 + 4;

        // Commit: close + atomic rename. After this, the write handle is
        // finalized — null it out so deinit() doesn't double-cleanup.
        // On commit failure the abstraction already cleans up the sidecar;
        // we still null the handle so the caller's defer deinit() is safe.
        defer self.write_handle = null;
        try handle.commit();
    }

    pub fn getBytesWritten(self: *const ParquetWriter) u64 {
        return self.bytes_written;
    }
};

