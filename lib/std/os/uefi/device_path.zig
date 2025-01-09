const std = @import("../../std.zig");
const assert = std.debug.assert;
const uefi = std.os.uefi;
const Guid = uefi.Guid;

pub const DevicePath = union(Type) {
    Hardware: Hardware,
    Acpi: Acpi,
    Messaging: Messaging,
    Media: Media,
    BiosBootSpecification: BiosBootSpecification,
    End: End,

    pub const Type = enum(u8) {
        Hardware = 0x01,
        Acpi = 0x02,
        Messaging = 0x03,
        Media = 0x04,
        BiosBootSpecification = 0x05,
        End = 0x7f,
        _,
    };

    pub const Hardware = union(Subtype) {
        Pci: *const PciDevicePath,
        PcCard: *const PcCardDevicePath,
        MemoryMapped: *const MemoryMappedDevicePath,
        Vendor: *const VendorDevicePath,
        Controller: *const ControllerDevicePath,
        Bmc: *const BmcDevicePath,

        pub const Subtype = enum(u8) {
            Pci = 1,
            PcCard = 2,
            MemoryMapped = 3,
            Vendor = 4,
            Controller = 5,
            Bmc = 6,
            _,
        };

        pub const PciDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            function: u8,
            device: u8,
        };

        comptime {
            assert(6 == @sizeof(PciDevicePath));
            assert(1 == @alignof(PciDevicePath));

            assert(0 == @offsetof(PciDevicePath, "type"));
            assert(1 == @offsetof(PciDevicePath, "subtype"));
            assert(2 == @offsetof(PciDevicePath, "length"));
            assert(4 == @offsetof(PciDevicePath, "function"));
            assert(5 == @offsetof(PciDevicePath, "device"));
        }

        pub const PcCardDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            function_number: u8,
        };

        comptime {
            assert(5 == @sizeof(PcCardDevicePath));
            assert(1 == @alignof(PcCardDevicePath));

            assert(0 == @offsetof(PcCardDevicePath, "type"));
            assert(1 == @offsetof(PcCardDevicePath, "subtype"));
            assert(2 == @offsetof(PcCardDevicePath, "length"));
            assert(4 == @offsetof(PcCardDevicePath, "function_number"));
        }

        pub const MemoryMappedDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            memory_type: u32 align(1),
            start_address: u64 align(1),
            end_address: u64 align(1),
        };

        comptime {
            assert(24 == @sizeof(MemoryMappedDevicePath));
            assert(1 == @alignof(MemoryMappedDevicePath));

            assert(0 == @offsetof(MemoryMappedDevicePath, "type"));
            assert(1 == @offsetof(MemoryMappedDevicePath, "subtype"));
            assert(2 == @offsetof(MemoryMappedDevicePath, "length"));
            assert(4 == @offsetof(MemoryMappedDevicePath, "memory_type"));
            assert(8 == @offsetof(MemoryMappedDevicePath, "start_address"));
            assert(16 == @offsetof(MemoryMappedDevicePath, "end_address"));
        }

        pub const VendorDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            vendor_guid: Guid align(1),
        };

        comptime {
            assert(20 == @sizeof(VendorDevicePath));
            assert(1 == @alignof(VendorDevicePath));

            assert(0 == @offsetof(VendorDevicePath, "type"));
            assert(1 == @offsetof(VendorDevicePath, "subtype"));
            assert(2 == @offsetof(VendorDevicePath, "length"));
            assert(4 == @offsetof(VendorDevicePath, "vendor_guid"));
        }

        pub const ControllerDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            controller_number: u32 align(1),
        };

        comptime {
            assert(8 == @sizeof(ControllerDevicePath));
            assert(1 == @alignof(ControllerDevicePath));

            assert(0 == @offsetof(ControllerDevicePath, "type"));
            assert(1 == @offsetof(ControllerDevicePath, "subtype"));
            assert(2 == @offsetof(ControllerDevicePath, "length"));
            assert(4 == @offsetof(ControllerDevicePath, "controller_number"));
        }

        pub const BmcDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            interface_type: u8,
            base_address: u64 align(1),
        };

        comptime {
            assert(13 == @sizeof(BmcDevicePath));
            assert(1 == @alignof(BmcDevicePath));

            assert(0 == @offsetof(BmcDevicePath, "type"));
            assert(1 == @offsetof(BmcDevicePath, "subtype"));
            assert(2 == @offsetof(BmcDevicePath, "length"));
            assert(4 == @offsetof(BmcDevicePath, "interface_type"));
            assert(5 == @offsetof(BmcDevicePath, "base_address"));
        }
    };

    pub const Acpi = union(Subtype) {
        Acpi: *const BaseAcpiDevicePath,
        ExpandedAcpi: *const ExpandedAcpiDevicePath,
        Adr: *const AdrDevicePath,

        pub const Subtype = enum(u8) {
            Acpi = 1,
            ExpandedAcpi = 2,
            Adr = 3,
            _,
        };

        pub const BaseAcpiDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            hid: u32 align(1),
            uid: u32 align(1),
        };

        comptime {
            assert(12 == @sizeof(BaseAcpiDevicePath));
            assert(1 == @alignof(BaseAcpiDevicePath));

            assert(0 == @offsetof(BaseAcpiDevicePath, "type"));
            assert(1 == @offsetof(BaseAcpiDevicePath, "subtype"));
            assert(2 == @offsetof(BaseAcpiDevicePath, "length"));
            assert(4 == @offsetof(BaseAcpiDevicePath, "hid"));
            assert(8 == @offsetof(BaseAcpiDevicePath, "uid"));
        }

        pub const ExpandedAcpiDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            hid: u32 align(1),
            uid: u32 align(1),
            cid: u32 align(1),
            // variable length u16[*:0] strings
            // hid_str, uid_str, cid_str
        };

        comptime {
            assert(16 == @sizeof(ExpandedAcpiDevicePath));
            assert(1 == @alignof(ExpandedAcpiDevicePath));

            assert(0 == @offsetof(ExpandedAcpiDevicePath, "type"));
            assert(1 == @offsetof(ExpandedAcpiDevicePath, "subtype"));
            assert(2 == @offsetof(ExpandedAcpiDevicePath, "length"));
            assert(4 == @offsetof(ExpandedAcpiDevicePath, "hid"));
            assert(8 == @offsetof(ExpandedAcpiDevicePath, "uid"));
            assert(12 == @offsetof(ExpandedAcpiDevicePath, "cid"));
        }

        pub const AdrDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            adr: u32 align(1),

            // multiple adr entries can optionally follow
            pub fn adrs(self: *const AdrDevicePath) []align(1) const u32 {
                // self.length is a minimum of 8 with one adr which is size 4.
                const entries = (self.length - 4) / @sizeof(u32);
                return @as([*]align(1) const u32, @ptrcast(&self.adr))[0..entries];
            }
        };

        comptime {
            assert(8 == @sizeof(AdrDevicePath));
            assert(1 == @alignof(AdrDevicePath));

            assert(0 == @offsetof(AdrDevicePath, "type"));
            assert(1 == @offsetof(AdrDevicePath, "subtype"));
            assert(2 == @offsetof(AdrDevicePath, "length"));
            assert(4 == @offsetof(AdrDevicePath, "adr"));
        }
    };

    pub const Messaging = union(Subtype) {
        Atapi: *const AtapiDevicePath,
        Scsi: *const ScsiDevicePath,
        FibreChannel: *const FibreChannelDevicePath,
        FibreChannelEx: *const FibreChannelExDevicePath,
        @"1394": *const F1394DevicePath,
        Usb: *const UsbDevicePath,
        Sata: *const SataDevicePath,
        UsbWwid: *const UsbWwidDevicePath,
        Lun: *const DeviceLogicalUnitDevicePath,
        UsbClass: *const UsbClassDevicePath,
        I2o: *const I2oDevicePath,
        MacAddress: *const MacAddressDevicePath,
        Ipv4: *const Ipv4DevicePath,
        Ipv6: *const Ipv6DevicePath,
        Vlan: *const VlanDevicePath,
        InfiniBand: *const InfiniBandDevicePath,
        Uart: *const UartDevicePath,
        Vendor: *const VendorDefinedDevicePath,

        pub const Subtype = enum(u8) {
            Atapi = 1,
            Scsi = 2,
            FibreChannel = 3,
            FibreChannelEx = 21,
            @"1394" = 4,
            Usb = 5,
            Sata = 18,
            UsbWwid = 16,
            Lun = 17,
            UsbClass = 15,
            I2o = 6,
            MacAddress = 11,
            Ipv4 = 12,
            Ipv6 = 13,
            Vlan = 20,
            InfiniBand = 9,
            Uart = 14,
            Vendor = 10,
            _,
        };

        pub const AtapiDevicePath = extern struct {
            const Role = enum(u8) {
                Master = 0,
                Slave = 1,
            };

            const Rank = enum(u8) {
                Primary = 0,
                Secondary = 1,
            };

            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            primary_secondary: Rank,
            slave_master: Role,
            logical_unit_number: u16 align(1),
        };

        comptime {
            assert(8 == @sizeof(AtapiDevicePath));
            assert(1 == @alignof(AtapiDevicePath));

            assert(0 == @offsetof(AtapiDevicePath, "type"));
            assert(1 == @offsetof(AtapiDevicePath, "subtype"));
            assert(2 == @offsetof(AtapiDevicePath, "length"));
            assert(4 == @offsetof(AtapiDevicePath, "primary_secondary"));
            assert(5 == @offsetof(AtapiDevicePath, "slave_master"));
            assert(6 == @offsetof(AtapiDevicePath, "logical_unit_number"));
        }

        pub const ScsiDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            target_id: u16 align(1),
            logical_unit_number: u16 align(1),
        };

        comptime {
            assert(8 == @sizeof(ScsiDevicePath));
            assert(1 == @alignof(ScsiDevicePath));

            assert(0 == @offsetof(ScsiDevicePath, "type"));
            assert(1 == @offsetof(ScsiDevicePath, "subtype"));
            assert(2 == @offsetof(ScsiDevicePath, "length"));
            assert(4 == @offsetof(ScsiDevicePath, "target_id"));
            assert(6 == @offsetof(ScsiDevicePath, "logical_unit_number"));
        }

        pub const FibreChannelDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            reserved: u32 align(1),
            world_wide_name: u64 align(1),
            logical_unit_number: u64 align(1),
        };

        comptime {
            assert(24 == @sizeof(FibreChannelDevicePath));
            assert(1 == @alignof(FibreChannelDevicePath));

            assert(0 == @offsetof(FibreChannelDevicePath, "type"));
            assert(1 == @offsetof(FibreChannelDevicePath, "subtype"));
            assert(2 == @offsetof(FibreChannelDevicePath, "length"));
            assert(4 == @offsetof(FibreChannelDevicePath, "reserved"));
            assert(8 == @offsetof(FibreChannelDevicePath, "world_wide_name"));
            assert(16 == @offsetof(FibreChannelDevicePath, "logical_unit_number"));
        }

        pub const FibreChannelExDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            reserved: u32 align(1),
            world_wide_name: u64 align(1),
            logical_unit_number: u64 align(1),
        };

        comptime {
            assert(24 == @sizeof(FibreChannelExDevicePath));
            assert(1 == @alignof(FibreChannelExDevicePath));

            assert(0 == @offsetof(FibreChannelExDevicePath, "type"));
            assert(1 == @offsetof(FibreChannelExDevicePath, "subtype"));
            assert(2 == @offsetof(FibreChannelExDevicePath, "length"));
            assert(4 == @offsetof(FibreChannelExDevicePath, "reserved"));
            assert(8 == @offsetof(FibreChannelExDevicePath, "world_wide_name"));
            assert(16 == @offsetof(FibreChannelExDevicePath, "logical_unit_number"));
        }

        pub const F1394DevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            reserved: u32 align(1),
            guid: u64 align(1),
        };

        comptime {
            assert(16 == @sizeof(F1394DevicePath));
            assert(1 == @alignof(F1394DevicePath));

            assert(0 == @offsetof(F1394DevicePath, "type"));
            assert(1 == @offsetof(F1394DevicePath, "subtype"));
            assert(2 == @offsetof(F1394DevicePath, "length"));
            assert(4 == @offsetof(F1394DevicePath, "reserved"));
            assert(8 == @offsetof(F1394DevicePath, "guid"));
        }

        pub const UsbDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            parent_port_number: u8,
            interface_number: u8,
        };

        comptime {
            assert(6 == @sizeof(UsbDevicePath));
            assert(1 == @alignof(UsbDevicePath));

            assert(0 == @offsetof(UsbDevicePath, "type"));
            assert(1 == @offsetof(UsbDevicePath, "subtype"));
            assert(2 == @offsetof(UsbDevicePath, "length"));
            assert(4 == @offsetof(UsbDevicePath, "parent_port_number"));
            assert(5 == @offsetof(UsbDevicePath, "interface_number"));
        }

        pub const SataDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            hba_port_number: u16 align(1),
            port_multiplier_port_number: u16 align(1),
            logical_unit_number: u16 align(1),
        };

        comptime {
            assert(10 == @sizeof(SataDevicePath));
            assert(1 == @alignof(SataDevicePath));

            assert(0 == @offsetof(SataDevicePath, "type"));
            assert(1 == @offsetof(SataDevicePath, "subtype"));
            assert(2 == @offsetof(SataDevicePath, "length"));
            assert(4 == @offsetof(SataDevicePath, "hba_port_number"));
            assert(6 == @offsetof(SataDevicePath, "port_multiplier_port_number"));
            assert(8 == @offsetof(SataDevicePath, "logical_unit_number"));
        }

        pub const UsbWwidDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            interface_number: u16 align(1),
            device_vendor_id: u16 align(1),
            device_product_id: u16 align(1),

            pub fn serial_number(self: *const UsbWwidDevicePath) []align(1) const u16 {
                const serial_len = (self.length - @sizeof(UsbWwidDevicePath)) / @sizeof(u16);
                return @as([*]align(1) const u16, @ptrcast(@as([*]const u8, @ptrcast(self)) + @sizeof(UsbWwidDevicePath)))[0..serial_len];
            }
        };

        comptime {
            assert(10 == @sizeof(UsbWwidDevicePath));
            assert(1 == @alignof(UsbWwidDevicePath));

            assert(0 == @offsetof(UsbWwidDevicePath, "type"));
            assert(1 == @offsetof(UsbWwidDevicePath, "subtype"));
            assert(2 == @offsetof(UsbWwidDevicePath, "length"));
            assert(4 == @offsetof(UsbWwidDevicePath, "interface_number"));
            assert(6 == @offsetof(UsbWwidDevicePath, "device_vendor_id"));
            assert(8 == @offsetof(UsbWwidDevicePath, "device_product_id"));
        }

        pub const DeviceLogicalUnitDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            lun: u8,
        };

        comptime {
            assert(5 == @sizeof(DeviceLogicalUnitDevicePath));
            assert(1 == @alignof(DeviceLogicalUnitDevicePath));

            assert(0 == @offsetof(DeviceLogicalUnitDevicePath, "type"));
            assert(1 == @offsetof(DeviceLogicalUnitDevicePath, "subtype"));
            assert(2 == @offsetof(DeviceLogicalUnitDevicePath, "length"));
            assert(4 == @offsetof(DeviceLogicalUnitDevicePath, "lun"));
        }

        pub const UsbClassDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            vendor_id: u16 align(1),
            product_id: u16 align(1),
            device_class: u8,
            device_subclass: u8,
            device_protocol: u8,
        };

        comptime {
            assert(11 == @sizeof(UsbClassDevicePath));
            assert(1 == @alignof(UsbClassDevicePath));

            assert(0 == @offsetof(UsbClassDevicePath, "type"));
            assert(1 == @offsetof(UsbClassDevicePath, "subtype"));
            assert(2 == @offsetof(UsbClassDevicePath, "length"));
            assert(4 == @offsetof(UsbClassDevicePath, "vendor_id"));
            assert(6 == @offsetof(UsbClassDevicePath, "product_id"));
            assert(8 == @offsetof(UsbClassDevicePath, "device_class"));
            assert(9 == @offsetof(UsbClassDevicePath, "device_subclass"));
            assert(10 == @offsetof(UsbClassDevicePath, "device_protocol"));
        }

        pub const I2oDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            tid: u32 align(1),
        };

        comptime {
            assert(8 == @sizeof(I2oDevicePath));
            assert(1 == @alignof(I2oDevicePath));

            assert(0 == @offsetof(I2oDevicePath, "type"));
            assert(1 == @offsetof(I2oDevicePath, "subtype"));
            assert(2 == @offsetof(I2oDevicePath, "length"));
            assert(4 == @offsetof(I2oDevicePath, "tid"));
        }

        pub const MacAddressDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            mac_address: uefi.MacAddress,
            if_type: u8,
        };

        comptime {
            assert(37 == @sizeof(MacAddressDevicePath));
            assert(1 == @alignof(MacAddressDevicePath));

            assert(0 == @offsetof(MacAddressDevicePath, "type"));
            assert(1 == @offsetof(MacAddressDevicePath, "subtype"));
            assert(2 == @offsetof(MacAddressDevicePath, "length"));
            assert(4 == @offsetof(MacAddressDevicePath, "mac_address"));
            assert(36 == @offsetof(MacAddressDevicePath, "if_type"));
        }

        pub const Ipv4DevicePath = extern struct {
            pub const IpType = enum(u8) {
                Dhcp = 0,
                Static = 1,
            };

            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            local_ip_address: uefi.Ipv4Address align(1),
            remote_ip_address: uefi.Ipv4Address align(1),
            local_port: u16 align(1),
            remote_port: u16 align(1),
            network_protocol: u16 align(1),
            static_ip_address: IpType,
            gateway_ip_address: u32 align(1),
            subnet_mask: u32 align(1),
        };

        comptime {
            assert(27 == @sizeof(Ipv4DevicePath));
            assert(1 == @alignof(Ipv4DevicePath));

            assert(0 == @offsetof(Ipv4DevicePath, "type"));
            assert(1 == @offsetof(Ipv4DevicePath, "subtype"));
            assert(2 == @offsetof(Ipv4DevicePath, "length"));
            assert(4 == @offsetof(Ipv4DevicePath, "local_ip_address"));
            assert(8 == @offsetof(Ipv4DevicePath, "remote_ip_address"));
            assert(12 == @offsetof(Ipv4DevicePath, "local_port"));
            assert(14 == @offsetof(Ipv4DevicePath, "remote_port"));
            assert(16 == @offsetof(Ipv4DevicePath, "network_protocol"));
            assert(18 == @offsetof(Ipv4DevicePath, "static_ip_address"));
            assert(19 == @offsetof(Ipv4DevicePath, "gateway_ip_address"));
            assert(23 == @offsetof(Ipv4DevicePath, "subnet_mask"));
        }

        pub const Ipv6DevicePath = extern struct {
            pub const Origin = enum(u8) {
                Manual = 0,
                AssignedStateless = 1,
                AssignedStateful = 2,
            };

            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            local_ip_address: uefi.Ipv6Address,
            remote_ip_address: uefi.Ipv6Address,
            local_port: u16 align(1),
            remote_port: u16 align(1),
            protocol: u16 align(1),
            ip_address_origin: Origin,
            prefix_length: u8,
            gateway_ip_address: uefi.Ipv6Address,
        };

        comptime {
            assert(60 == @sizeof(Ipv6DevicePath));
            assert(1 == @alignof(Ipv6DevicePath));

            assert(0 == @offsetof(Ipv6DevicePath, "type"));
            assert(1 == @offsetof(Ipv6DevicePath, "subtype"));
            assert(2 == @offsetof(Ipv6DevicePath, "length"));
            assert(4 == @offsetof(Ipv6DevicePath, "local_ip_address"));
            assert(20 == @offsetof(Ipv6DevicePath, "remote_ip_address"));
            assert(36 == @offsetof(Ipv6DevicePath, "local_port"));
            assert(38 == @offsetof(Ipv6DevicePath, "remote_port"));
            assert(40 == @offsetof(Ipv6DevicePath, "protocol"));
            assert(42 == @offsetof(Ipv6DevicePath, "ip_address_origin"));
            assert(43 == @offsetof(Ipv6DevicePath, "prefix_length"));
            assert(44 == @offsetof(Ipv6DevicePath, "gateway_ip_address"));
        }

        pub const VlanDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            vlan_id: u16 align(1),
        };

        comptime {
            assert(6 == @sizeof(VlanDevicePath));
            assert(1 == @alignof(VlanDevicePath));

            assert(0 == @offsetof(VlanDevicePath, "type"));
            assert(1 == @offsetof(VlanDevicePath, "subtype"));
            assert(2 == @offsetof(VlanDevicePath, "length"));
            assert(4 == @offsetof(VlanDevicePath, "vlan_id"));
        }

        pub const InfiniBandDevicePath = extern struct {
            pub const ResourceFlags = packed struct(u32) {
                pub const ControllerType = enum(u1) {
                    Ioc = 0,
                    Service = 1,
                };

                ioc_or_service: ControllerType,
                extend_boot_environment: bool,
                console_protocol: bool,
                storage_protocol: bool,
                network_protocol: bool,

                // u1 + 4 * bool = 5 bits, we need a total of 32 bits
                reserved: u27,
            };

            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            resource_flags: ResourceFlags align(1),
            port_gid: [16]u8,
            service_id: u64 align(1),
            target_port_id: u64 align(1),
            device_id: u64 align(1),
        };

        comptime {
            assert(48 == @sizeof(InfiniBandDevicePath));
            assert(1 == @alignof(InfiniBandDevicePath));

            assert(0 == @offsetof(InfiniBandDevicePath, "type"));
            assert(1 == @offsetof(InfiniBandDevicePath, "subtype"));
            assert(2 == @offsetof(InfiniBandDevicePath, "length"));
            assert(4 == @offsetof(InfiniBandDevicePath, "resource_flags"));
            assert(8 == @offsetof(InfiniBandDevicePath, "port_gid"));
            assert(24 == @offsetof(InfiniBandDevicePath, "service_id"));
            assert(32 == @offsetof(InfiniBandDevicePath, "target_port_id"));
            assert(40 == @offsetof(InfiniBandDevicePath, "device_id"));
        }

        pub const UartDevicePath = extern struct {
            pub const Parity = enum(u8) {
                Default = 0,
                None = 1,
                Even = 2,
                Odd = 3,
                Mark = 4,
                Space = 5,
                _,
            };

            pub const StopBits = enum(u8) {
                Default = 0,
                One = 1,
                OneAndAHalf = 2,
                Two = 3,
                _,
            };

            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            reserved: u32 align(1),
            baud_rate: u64 align(1),
            data_bits: u8,
            parity: Parity,
            stop_bits: StopBits,
        };

        comptime {
            assert(19 == @sizeof(UartDevicePath));
            assert(1 == @alignof(UartDevicePath));

            assert(0 == @offsetof(UartDevicePath, "type"));
            assert(1 == @offsetof(UartDevicePath, "subtype"));
            assert(2 == @offsetof(UartDevicePath, "length"));
            assert(4 == @offsetof(UartDevicePath, "reserved"));
            assert(8 == @offsetof(UartDevicePath, "baud_rate"));
            assert(16 == @offsetof(UartDevicePath, "data_bits"));
            assert(17 == @offsetof(UartDevicePath, "parity"));
            assert(18 == @offsetof(UartDevicePath, "stop_bits"));
        }

        pub const VendorDefinedDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            vendor_guid: Guid align(1),
        };

        comptime {
            assert(20 == @sizeof(VendorDefinedDevicePath));
            assert(1 == @alignof(VendorDefinedDevicePath));

            assert(0 == @offsetof(VendorDefinedDevicePath, "type"));
            assert(1 == @offsetof(VendorDefinedDevicePath, "subtype"));
            assert(2 == @offsetof(VendorDefinedDevicePath, "length"));
            assert(4 == @offsetof(VendorDefinedDevicePath, "vendor_guid"));
        }
    };

    pub const Media = union(Subtype) {
        HardDrive: *const HardDriveDevicePath,
        Cdrom: *const CdromDevicePath,
        Vendor: *const VendorDevicePath,
        FilePath: *const FilePathDevicePath,
        MediaProtocol: *const MediaProtocolDevicePath,
        PiwgFirmwareFile: *const PiwgFirmwareFileDevicePath,
        PiwgFirmwareVolume: *const PiwgFirmwareVolumeDevicePath,
        RelativeOffsetRange: *const RelativeOffsetRangeDevicePath,
        RamDisk: *const RamDiskDevicePath,

        pub const Subtype = enum(u8) {
            HardDrive = 1,
            Cdrom = 2,
            Vendor = 3,
            FilePath = 4,
            MediaProtocol = 5,
            PiwgFirmwareFile = 6,
            PiwgFirmwareVolume = 7,
            RelativeOffsetRange = 8,
            RamDisk = 9,
            _,
        };

        pub const HardDriveDevicePath = extern struct {
            pub const Format = enum(u8) {
                LegacyMbr = 0x01,
                GuidPartitionTable = 0x02,
            };

            pub const SignatureType = enum(u8) {
                NoSignature = 0x00,
                /// "32-bit signature from address 0x1b8 of the type 0x01 MBR"
                MbrSignature = 0x01,
                GuidSignature = 0x02,
            };

            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            partition_number: u32 align(1),
            partition_start: u64 align(1),
            partition_size: u64 align(1),
            partition_signature: [16]u8,
            partition_format: Format,
            signature_type: SignatureType,
        };

        comptime {
            assert(42 == @sizeof(HardDriveDevicePath));
            assert(1 == @alignof(HardDriveDevicePath));

            assert(0 == @offsetof(HardDriveDevicePath, "type"));
            assert(1 == @offsetof(HardDriveDevicePath, "subtype"));
            assert(2 == @offsetof(HardDriveDevicePath, "length"));
            assert(4 == @offsetof(HardDriveDevicePath, "partition_number"));
            assert(8 == @offsetof(HardDriveDevicePath, "partition_start"));
            assert(16 == @offsetof(HardDriveDevicePath, "partition_size"));
            assert(24 == @offsetof(HardDriveDevicePath, "partition_signature"));
            assert(40 == @offsetof(HardDriveDevicePath, "partition_format"));
            assert(41 == @offsetof(HardDriveDevicePath, "signature_type"));
        }

        pub const CdromDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            boot_entry: u32 align(1),
            partition_start: u64 align(1),
            partition_size: u64 align(1),
        };

        comptime {
            assert(24 == @sizeof(CdromDevicePath));
            assert(1 == @alignof(CdromDevicePath));

            assert(0 == @offsetof(CdromDevicePath, "type"));
            assert(1 == @offsetof(CdromDevicePath, "subtype"));
            assert(2 == @offsetof(CdromDevicePath, "length"));
            assert(4 == @offsetof(CdromDevicePath, "boot_entry"));
            assert(8 == @offsetof(CdromDevicePath, "partition_start"));
            assert(16 == @offsetof(CdromDevicePath, "partition_size"));
        }

        pub const VendorDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            guid: Guid align(1),
        };

        comptime {
            assert(20 == @sizeof(VendorDevicePath));
            assert(1 == @alignof(VendorDevicePath));

            assert(0 == @offsetof(VendorDevicePath, "type"));
            assert(1 == @offsetof(VendorDevicePath, "subtype"));
            assert(2 == @offsetof(VendorDevicePath, "length"));
            assert(4 == @offsetof(VendorDevicePath, "guid"));
        }

        pub const FilePathDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),

            pub fn getPath(self: *const FilePathDevicePath) [*:0]align(1) const u16 {
                return @as([*:0]align(1) const u16, @ptrcast(@as([*]const u8, @ptrcast(self)) + @sizeof(FilePathDevicePath)));
            }
        };

        comptime {
            assert(4 == @sizeof(FilePathDevicePath));
            assert(1 == @alignof(FilePathDevicePath));

            assert(0 == @offsetof(FilePathDevicePath, "type"));
            assert(1 == @offsetof(FilePathDevicePath, "subtype"));
            assert(2 == @offsetof(FilePathDevicePath, "length"));
        }

        pub const MediaProtocolDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            guid: Guid align(1),
        };

        comptime {
            assert(20 == @sizeof(MediaProtocolDevicePath));
            assert(1 == @alignof(MediaProtocolDevicePath));

            assert(0 == @offsetof(MediaProtocolDevicePath, "type"));
            assert(1 == @offsetof(MediaProtocolDevicePath, "subtype"));
            assert(2 == @offsetof(MediaProtocolDevicePath, "length"));
            assert(4 == @offsetof(MediaProtocolDevicePath, "guid"));
        }

        pub const PiwgFirmwareFileDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            fv_filename: Guid align(1),
        };

        comptime {
            assert(20 == @sizeof(PiwgFirmwareFileDevicePath));
            assert(1 == @alignof(PiwgFirmwareFileDevicePath));

            assert(0 == @offsetof(PiwgFirmwareFileDevicePath, "type"));
            assert(1 == @offsetof(PiwgFirmwareFileDevicePath, "subtype"));
            assert(2 == @offsetof(PiwgFirmwareFileDevicePath, "length"));
            assert(4 == @offsetof(PiwgFirmwareFileDevicePath, "fv_filename"));
        }

        pub const PiwgFirmwareVolumeDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            fv_name: Guid align(1),
        };

        comptime {
            assert(20 == @sizeof(PiwgFirmwareVolumeDevicePath));
            assert(1 == @alignof(PiwgFirmwareVolumeDevicePath));

            assert(0 == @offsetof(PiwgFirmwareVolumeDevicePath, "type"));
            assert(1 == @offsetof(PiwgFirmwareVolumeDevicePath, "subtype"));
            assert(2 == @offsetof(PiwgFirmwareVolumeDevicePath, "length"));
            assert(4 == @offsetof(PiwgFirmwareVolumeDevicePath, "fv_name"));
        }

        pub const RelativeOffsetRangeDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            reserved: u32 align(1),
            start: u64 align(1),
            end: u64 align(1),
        };

        comptime {
            assert(24 == @sizeof(RelativeOffsetRangeDevicePath));
            assert(1 == @alignof(RelativeOffsetRangeDevicePath));

            assert(0 == @offsetof(RelativeOffsetRangeDevicePath, "type"));
            assert(1 == @offsetof(RelativeOffsetRangeDevicePath, "subtype"));
            assert(2 == @offsetof(RelativeOffsetRangeDevicePath, "length"));
            assert(4 == @offsetof(RelativeOffsetRangeDevicePath, "reserved"));
            assert(8 == @offsetof(RelativeOffsetRangeDevicePath, "start"));
            assert(16 == @offsetof(RelativeOffsetRangeDevicePath, "end"));
        }

        pub const RamDiskDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            start: u64 align(1),
            end: u64 align(1),
            disk_type: Guid align(1),
            instance: u16 align(1),
        };

        comptime {
            assert(38 == @sizeof(RamDiskDevicePath));
            assert(1 == @alignof(RamDiskDevicePath));

            assert(0 == @offsetof(RamDiskDevicePath, "type"));
            assert(1 == @offsetof(RamDiskDevicePath, "subtype"));
            assert(2 == @offsetof(RamDiskDevicePath, "length"));
            assert(4 == @offsetof(RamDiskDevicePath, "start"));
            assert(12 == @offsetof(RamDiskDevicePath, "end"));
            assert(20 == @offsetof(RamDiskDevicePath, "disk_type"));
            assert(36 == @offsetof(RamDiskDevicePath, "instance"));
        }
    };

    pub const BiosBootSpecification = union(Subtype) {
        BBS101: *const BBS101DevicePath,

        pub const Subtype = enum(u8) {
            BBS101 = 1,
            _,
        };

        pub const BBS101DevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            device_type: u16 align(1),
            status_flag: u16 align(1),

            pub fn getDescription(self: *const BBS101DevicePath) [*:0]const u8 {
                return @as([*:0]const u8, @ptrcast(self)) + @sizeof(BBS101DevicePath);
            }
        };

        comptime {
            assert(8 == @sizeof(BBS101DevicePath));
            assert(1 == @alignof(BBS101DevicePath));

            assert(0 == @offsetof(BBS101DevicePath, "type"));
            assert(1 == @offsetof(BBS101DevicePath, "subtype"));
            assert(2 == @offsetof(BBS101DevicePath, "length"));
            assert(4 == @offsetof(BBS101DevicePath, "device_type"));
            assert(6 == @offsetof(BBS101DevicePath, "status_flag"));
        }
    };

    pub const End = union(Subtype) {
        EndEntire: *const EndEntireDevicePath,
        EndThisInstance: *const EndThisInstanceDevicePath,

        pub const Subtype = enum(u8) {
            EndEntire = 0xff,
            EndThisInstance = 0x01,
            _,
        };

        pub const EndEntireDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
        };

        comptime {
            assert(4 == @sizeof(EndEntireDevicePath));
            assert(1 == @alignof(EndEntireDevicePath));

            assert(0 == @offsetof(EndEntireDevicePath, "type"));
            assert(1 == @offsetof(EndEntireDevicePath, "subtype"));
            assert(2 == @offsetof(EndEntireDevicePath, "length"));
        }

        pub const EndThisInstanceDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
        };

        comptime {
            assert(4 == @sizeof(EndEntireDevicePath));
            assert(1 == @alignof(EndEntireDevicePath));

            assert(0 == @offsetof(EndEntireDevicePath, "type"));
            assert(1 == @offsetof(EndEntireDevicePath, "subtype"));
            assert(2 == @offsetof(EndEntireDevicePath, "length"));
        }
    };
};
