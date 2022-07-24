const std = @import("std");
const handshake = @import("./handshake.zig");
const ClientHelloHandshake = handshake.ClientHelloHandshake;

pub const HandshakeRecord = struct {
    const Self = @This();

    handshake: ClientHelloHandshake,

    pub fn length(self: *Self) u16 {
        const len = 4 + self.handshake.length();

        std.debug.print("{}\n", .{@intCast(u16, len)});

        return @intCast(u16, len);
    }

    pub fn encode(self: *Self, alloc: std.mem.Allocator) ![]const u8 {
        var buf = std.ArrayList(u8).init(alloc);

        // Handshake(22)
        try buf.append(0x16);
        // TLS 1.0
        try buf.appendSlice(&[_]u8{ 0x03, 0x01 });
        // Length
        var length_buf: [2]u8 = undefined;
        std.mem.writeIntSlice(u16, &length_buf, self.length(), .Big);
        try buf.appendSlice(length_buf[0..]);
        // payload
        const payload = try self.handshake.encode(alloc);
        try buf.appendSlice(payload);

        return buf.items;
    }
};

test {
    _ = HandshakeRecord;
}
