const std = @import("std");
const testing = std.testing;

const HandshakeType = enum(u8) {
    client_hello = 1,
};

const ClientHelloHandshake = struct {
    handshake_type: HandshakeType,
    length: u24,
    protocol_version: u16,
    random: u32,
    session_id_length: u8,
    session_id: u32,
};

const ClientHello = struct {
    const Self = @This();

    pub fn decode(raw: []const u8) ClientHelloHandshake {
        const handshake_type = @intToEnum(HandshakeType, raw[0]);
        const length = std.mem.readIntSliceBig(u24, raw[1..4]);
        const protocol_version = std.mem.readIntSliceBig(u16, raw[4..6]);
        const random = std.mem.readIntSliceBig(u32, raw[6..10]);
        const session_id_length = raw[10];
        const session_id = std.mem.readIntSliceBig(u32, raw[11 .. 11 + session_id_length / 8]);

        return .{
            .handshake_type = handshake_type,
            .length = length,
            .protocol_version = protocol_version,
            .random = random,
            .session_id_length = session_id_length,
            .session_id = session_id,
        };
    }

    pub const Encoder = struct {
        buf: std.ArrayList(u8),
        handshake: ClientHelloHandshake,

        pub fn init(alloc: std.mem.Allocator, handshake: ClientHelloHandshake) Encoder {
            return .{
                .buf = std.ArrayList(u8).init(alloc),
                .handshake = handshake,
            };
        }

        pub fn deinit(self: *Encoder) void {
            self.buf.deinit();
        }

        pub fn encode(self: *Encoder) ![]const u8 {
            try self.buf.append(@enumToInt(self.handshake.handshake_type));

            var length_buf: [3]u8 = undefined;
            std.mem.writeIntSlice(u24, &length_buf, self.handshake.length, .Big);
            try self.buf.appendSlice(length_buf[0..]);

            var protocol_version_buf: [2]u8 = undefined;
            std.mem.writeIntSlice(u16, &protocol_version_buf, self.handshake.protocol_version, .Big);
            try self.buf.appendSlice(protocol_version_buf[0..]);

            var random_buf: [4]u8 = undefined;
            std.mem.writeIntSlice(u32, &random_buf, self.handshake.random, .Big);
            try self.buf.appendSlice(random_buf[0..]);

            try self.buf.append(self.handshake.session_id_length);

            var session_id_buf: [4]u8 = undefined;
            std.mem.writeIntSlice(u32, &session_id_buf, self.handshake.session_id, .Big);
            try self.buf.appendSlice(session_id_buf[0 .. self.handshake.session_id_length / 8]);

            return self.buf.items;
        }
    };
};

test "ClientHello" {
    const raw = &[_]u8{
        @enumToInt(HandshakeType.client_hello),
        // length
        0x10,
        0x00,
        0x00,
        // protocol version
        0x03,
        0x03,
        // random
        0x00,
        0x00,
        0x00,
        0x00,
        // session_id_length
        0x20,
        // session_id
        0x00,
        0x00,
        0x00,
        0x00,
    };

    const handshake = ClientHello.decode(raw);

    try testing.expectEqual(handshake.handshake_type, .client_hello);
    try testing.expectEqual(handshake.length, 1048576);
    try testing.expectEqual(handshake.protocol_version, 0x0303);
    try testing.expectEqual(handshake.random, 0x00);
    try testing.expectEqual(handshake.session_id_length, 32);
    try testing.expectEqual(handshake.session_id, 0x00);

    var encoder = ClientHello.Encoder.init(testing.allocator, handshake);
    defer encoder.deinit();
    const encoded = try encoder.encode();

    try testing.expectEqualSlices(u8, encoded, raw);
}
