const std = @import("std");
const testing = std.testing;

const HandshakeType = enum(u8) {
    ClientHello = 1,
};

const Handshake = struct { handshakeType: HandshakeType, length: u24 };

const ClientHello = struct {
    const Self = @This();

    pub fn decode(raw: []const u8) Handshake {
        const handshakeType = @intToEnum(HandshakeType, raw[0]);
        const length = std.mem.readIntSliceBig(u24, raw[1..4]);

        return .{ .handshakeType = handshakeType, .length = length };
    }

    const Encoder = struct {
        handshake: Handshake,
        alloc: std.mem.Allocator,

        pub fn init(alloc: std.mem.Allocator, handshake: Handshake) Encoder {
            return .{ .alloc = alloc, .handshake = handshake };
        }

        pub fn encode(self: *Self) []const u8 {
            var buf = std.ArrayList(u8).init(self.alloc);

            buf.append(@enumToInt(self.handshake.handshakeType));
            buf.appendSlice(std.mem.readIntBig([]const u8, self.handshake.length));

            return buf.items;
        }
    };
};

test "decode" {
    const data: []const u8 = &[_]u8{ @enumToInt(HandshakeType.ClientHello), 0x00, 0x00, 0x00 };
    const handshake = ClientHello.decode(data);

    try testing.expectEqual(handshake.handshakeType, .ClientHello);
    try testing.expectEqual(handshake.length, 0);
}
