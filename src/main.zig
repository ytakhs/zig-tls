const std = @import("std");
const net = std.net;
const client_hello = @import("./client_hello.zig");
const ClientHelloHandshake = client_hello.ClientHelloHandshake;

pub fn main() anyerror!void {
    const targetAddr = try std.net.Address.parseIp4("127.0.0.1", 4433);
    const conn = try net.tcpConnectToAddress(targetAddr);

    var handshake = initHandshake();
    const data = try handshake.encode(std.heap.page_allocator);
    defer std.heap.page_allocator.free(data);

    std.debug.print("{any}", .{data});

    _ = try conn.write(data);
}

fn initHandshake() ClientHelloHandshake {
    return .{
        .handshake_type = .client_hello,
        .protocol_version = 0x0303,
        .random = 0x00,
        .session_id_length = 32,
        .session_id = &[_]u8{0x00} ** 32,
        .cipher_suites_length = 2,
        .cipher_suites = &[_]u8{ 0x00, 0x9c },
        .compression_methods_length = 1,
        .compression_methods = &[_]u8{0x00},
    };
}

test "" {
    _ = client_hello;
}
