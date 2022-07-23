const std = @import("std");
const client_hello = @import("./client_hello.zig");

pub fn main() anyerror!void {
    // Note that info level log messages are by default printed only in Debug
    // and ReleaseSafe build modes.
    std.log.info("All your codebase are belong to us.", .{});
}

test "" {
    _ = client_hello;
}
