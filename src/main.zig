pub const Module = @import("module.zig").Module;
pub const Instance = @import("instance.zig").Instance;
pub const VirtualMachine = @import("vm.zig").VirtualMachine;
pub const Store = @import("store.zig").ArrayListStore;
pub const Function = @import("function.zig").Function;
pub const Global = @import("global.zig").Global;
pub const Memory = @import("memory.zig").Memory;
pub const ValueType = @import("value_type.zig").ValueType;
pub const WasmError = @import("function.zig").WasmError;

test {
    _ = @import("validator.zig");
    _ = @import("vm.zig");
    _ = @import("module.zig");
}
