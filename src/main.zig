const std = @import("std");
const net = std.net;
const client_hello = @import("./client_hello.zig");
const record = @import("./record.zig");
const ClientHelloHandshake = client_hello.ClientHelloHandshake;

pub fn main() anyerror!void {
    const targetAddr = try std.net.Address.parseIp4("127.0.0.1", 4433);
    const conn = try net.tcpConnectToAddress(targetAddr);

    var r = initRecord();
    const data = try r.encode(std.heap.page_allocator);
    defer std.heap.page_allocator.free(data);

    std.debug.print("{any}", .{data});

    _ = try conn.write(data);
}

fn initRecord() record.HandshakeRecord {
    const handshake = ClientHelloHandshake{
        .handshake_type = .client_hello,
        .protocol_version = 0x0303,
        .random = &[_]u8{0x00} ** 32,
        .session_id_length = 32,
        .session_id = &[_]u8{0x00} ** 32,
        .cipher_suites_length = 2,
        .cipher_suites = &[_]u8{ 0x00, 0x9c },
        .compression_methods_length = 1,
        .compression_methods = &[_]u8{0x00},
    };

    return .{ .handshake = handshake };
}

test "" {
    _ = client_hello;
    _ = record;
}
