const std = @import("std");
const testing = std.testing;

const HandshakeType = enum(u8) {
    client_hello = 1,
};

const ClientHelloHandshake = struct { handshakeType: HandshakeType, length: u24 };

const ClientHello = struct {
    const Self = @This();

    pub fn decode(raw: []const u8) ClientHelloHandshake {
        const handshakeType = @intToEnum(HandshakeType, raw[0]);
        const length = std.mem.readIntSliceBig(u24, raw[1..4]);

        return .{ .handshakeType = handshakeType, .length = length };
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
            try self.buf.append(@enumToInt(self.handshake.handshakeType));

            var lengthBuf: [3]u8 = undefined;
            std.mem.writeIntSlice(u24, &lengthBuf, self.handshake.length, .Big);
            try self.buf.appendSlice(lengthBuf[0..]);

            return self.buf.items;
        }
    };
};

test "ClientHello" {
    const data: []const u8 = &[_]u8{ @enumToInt(HandshakeType.client_hello), 0x10, 0x00, 0x00 };
    const handshake = ClientHello.decode(data);

    try testing.expectEqual(handshake.handshakeType, .client_hello);
    try testing.expectEqual(handshake.length, 1048576);

    var encoder = ClientHello.Encoder.init(testing.allocator, handshake);
    defer encoder.deinit();
    const encoded = try encoder.encode();

    try testing.expectEqualSlices(u8, encoded, data);
}
