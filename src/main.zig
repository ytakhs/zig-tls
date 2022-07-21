const std = @import("std");
const testing = std.testing;

const HandshakeType = enum(u8) {
    client_hello = 1,
};

const ClientHelloHandshake = struct {
    handshake_type: HandshakeType,
    length: u24,
    protocol_version: u16,
};

const ClientHello = struct {
    const Self = @This();

    pub fn decode(raw: []const u8) ClientHelloHandshake {
        const handshake_type = @intToEnum(HandshakeType, raw[0]);
        const length = std.mem.readIntSliceBig(u24, raw[1..4]);
        const protocol_version = std.mem.readIntSliceBig(u16, raw[4..6]);

        return .{ .handshake_type = handshake_type, .length = length, .protocol_version = protocol_version };
    }

    pub const Encoder = struct {
        buf: std.ArrayList(u8),
        handshake: ClientHelloHandshake,

        pub fn init(alloc: std.mem.Allocator, handshake: ClientHelloHandshake) Encoder {
            return .{ .buf = std.ArrayList(u8).init(alloc), .handshake = handshake };
        }

        pub fn deinit(self: *Encoder) void {
            self.buf.deinit();
        }

        pub fn encode(self: *Encoder) ![]const u8 {
            try self.buf.append(@enumToInt(self.handshake.handshake_type));

            var lengthBuf: [3]u8 = undefined;
            std.mem.writeIntSlice(u24, &lengthBuf, self.handshake.length, .Big);
            try self.buf.appendSlice(lengthBuf[0..]);

            var protocolVersionBuf: [2]u8 = undefined;
            std.mem.writeIntSlice(u16, &protocolVersionBuf, self.handshake.protocol_version, .Big);
            try self.buf.appendSlice(protocolVersionBuf[0..]);

            return self.buf.items;
        }
    };
};

test "ClientHello" {
    const handshake_type = &[_]u8{@enumToInt(HandshakeType.client_hello)};
    const length = &[_]u8{ 0x10, 0x00, 0x00 };
    const protocol_version = &[_]u8{ 0x03, 0x03 };
    const data: []const u8 = handshake_type ++ length ++ protocol_version;

    const handshake = ClientHello.decode(data);

    try testing.expectEqual(handshake.handshake_type, .client_hello);
    try testing.expectEqual(handshake.length, 1048576);
    try testing.expectEqual(handshake.protocol_version, 0x0303);

    var encoder = ClientHello.Encoder.init(testing.allocator, handshake);
    defer encoder.deinit();
    const encoded = try encoder.encode();

    try testing.expectEqualSlices(u8, encoded, data);
}
