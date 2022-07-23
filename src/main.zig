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
    session_id: []const u8,
};

const ClientHello = struct {
    const Self = @This();

    pub const Decoder = struct {
        cur: usize,
        raw: []const u8,

        pub fn init(raw: []const u8) Decoder {
            return .{
                .cur = 0,
                .raw = raw,
            };
        }

        pub fn decode(self: *Decoder) ClientHelloHandshake {
            const handshake_type = @intToEnum(HandshakeType, self.readIntBig(u8, 1));
            const length = self.readIntBig(u24, 3);
            const protocol_version = self.readIntBig(u16, 2);
            const random = self.readIntBig(u32, 4);
            const session_id_length = self.readIntBig(u8, 1);
            const session_id = self.readSlice(session_id_length);

            return .{
                .handshake_type = handshake_type,
                .length = length,
                .protocol_version = protocol_version,
                .random = random,
                .session_id_length = session_id_length,
                .session_id = session_id,
            };
        }

        fn readIntBig(self: *Decoder, comptime T: type, len: usize) T {
            const v = std.mem.readIntSliceBig(T, self.raw[self.cur .. self.cur + len]);

            self.cur += len;

            return v;
        }

        fn readSlice(self: *Decoder, len: usize) []const u8 {
            const v = self.raw[self.cur .. self.cur + len];

            self.cur += len;

            return v;
        }
    };

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

            try self.buf.appendSlice(self.handshake.session_id[0..self.handshake.session_id_length]);

            return self.buf.items;
        }
    };
};

test "ClientHello" {
    const handshake_type = &[_]u8{
        @enumToInt(HandshakeType.client_hello),
    };
    const length = &[_]u8{
        0x10,
        0x00,
        0x00,
    };
    const protocol_version = &[_]u8{
        0x03,
        0x03,
    };
    const random = &[_]u8{
        0x00,
        0x00,
        0x00,
        0x00,
    };
    const session_id_length = &[_]u8{
        0x20,
    };
    const sesion_id = &[_]u8{0x00} ** 0x20;
    const raw =
        handshake_type ++
        length ++
        protocol_version ++
        random ++
        session_id_length ++
        sesion_id;

    var decoder = ClientHello.Decoder.init(raw);
    const handshake = decoder.decode();

    try testing.expectEqual(handshake.handshake_type, .client_hello);
    try testing.expectEqual(handshake.length, 1048576);
    try testing.expectEqual(handshake.protocol_version, 0x0303);
    try testing.expectEqual(handshake.random, 0x00);
    try testing.expectEqual(handshake.session_id_length, 32);
    try testing.expectEqualSlices(u8, handshake.session_id, &[_]u8{0x00} ** 32);

    var encoder = ClientHello.Encoder.init(testing.allocator, handshake);
    defer encoder.deinit();
    const encoded = try encoder.encode();

    try testing.expectEqualSlices(u8, encoded, raw);
}
