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
            assert(6 == @size_of(PciDevicePath));
            assert(1 == @alignOf(PciDevicePath));

            assert(0 == @offset_of(PciDevicePath, "type"));
            assert(1 == @offset_of(PciDevicePath, "subtype"));
            assert(2 == @offset_of(PciDevicePath, "length"));
            assert(4 == @offset_of(PciDevicePath, "function"));
            assert(5 == @offset_of(PciDevicePath, "device"));
        }

        pub const PcCardDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            function_number: u8,
        };

        comptime {
            assert(5 == @size_of(PcCardDevicePath));
            assert(1 == @alignOf(PcCardDevicePath));

            assert(0 == @offset_of(PcCardDevicePath, "type"));
            assert(1 == @offset_of(PcCardDevicePath, "subtype"));
            assert(2 == @offset_of(PcCardDevicePath, "length"));
            assert(4 == @offset_of(PcCardDevicePath, "function_number"));
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
            assert(24 == @size_of(MemoryMappedDevicePath));
            assert(1 == @alignOf(MemoryMappedDevicePath));

            assert(0 == @offset_of(MemoryMappedDevicePath, "type"));
            assert(1 == @offset_of(MemoryMappedDevicePath, "subtype"));
            assert(2 == @offset_of(MemoryMappedDevicePath, "length"));
            assert(4 == @offset_of(MemoryMappedDevicePath, "memory_type"));
            assert(8 == @offset_of(MemoryMappedDevicePath, "start_address"));
            assert(16 == @offset_of(MemoryMappedDevicePath, "end_address"));
        }

        pub const VendorDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            vendor_guid: Guid align(1),
        };

        comptime {
            assert(20 == @size_of(VendorDevicePath));
            assert(1 == @alignOf(VendorDevicePath));

            assert(0 == @offset_of(VendorDevicePath, "type"));
            assert(1 == @offset_of(VendorDevicePath, "subtype"));
            assert(2 == @offset_of(VendorDevicePath, "length"));
            assert(4 == @offset_of(VendorDevicePath, "vendor_guid"));
        }

        pub const ControllerDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            controller_number: u32 align(1),
        };

        comptime {
            assert(8 == @size_of(ControllerDevicePath));
            assert(1 == @alignOf(ControllerDevicePath));

            assert(0 == @offset_of(ControllerDevicePath, "type"));
            assert(1 == @offset_of(ControllerDevicePath, "subtype"));
            assert(2 == @offset_of(ControllerDevicePath, "length"));
            assert(4 == @offset_of(ControllerDevicePath, "controller_number"));
        }

        pub const BmcDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            interface_type: u8,
            base_address: u64 align(1),
        };

        comptime {
            assert(13 == @size_of(BmcDevicePath));
            assert(1 == @alignOf(BmcDevicePath));

            assert(0 == @offset_of(BmcDevicePath, "type"));
            assert(1 == @offset_of(BmcDevicePath, "subtype"));
            assert(2 == @offset_of(BmcDevicePath, "length"));
            assert(4 == @offset_of(BmcDevicePath, "interface_type"));
            assert(5 == @offset_of(BmcDevicePath, "base_address"));
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
            assert(12 == @size_of(BaseAcpiDevicePath));
            assert(1 == @alignOf(BaseAcpiDevicePath));

            assert(0 == @offset_of(BaseAcpiDevicePath, "type"));
            assert(1 == @offset_of(BaseAcpiDevicePath, "subtype"));
            assert(2 == @offset_of(BaseAcpiDevicePath, "length"));
            assert(4 == @offset_of(BaseAcpiDevicePath, "hid"));
            assert(8 == @offset_of(BaseAcpiDevicePath, "uid"));
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
            assert(16 == @size_of(ExpandedAcpiDevicePath));
            assert(1 == @alignOf(ExpandedAcpiDevicePath));

            assert(0 == @offset_of(ExpandedAcpiDevicePath, "type"));
            assert(1 == @offset_of(ExpandedAcpiDevicePath, "subtype"));
            assert(2 == @offset_of(ExpandedAcpiDevicePath, "length"));
            assert(4 == @offset_of(ExpandedAcpiDevicePath, "hid"));
            assert(8 == @offset_of(ExpandedAcpiDevicePath, "uid"));
            assert(12 == @offset_of(ExpandedAcpiDevicePath, "cid"));
        }

        pub const AdrDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            adr: u32 align(1),

            // multiple adr entries can optionally follow
            pub fn adrs(self: *const AdrDevicePath) []align(1) const u32 {
                // self.length is a minimum of 8 with one adr which is size 4.
                const entries = (self.length - 4) / @size_of(u32);
                return @as([*]align(1) const u32, @ptr_cast(&self.adr))[0..entries];
            }
        };

        comptime {
            assert(8 == @size_of(AdrDevicePath));
            assert(1 == @alignOf(AdrDevicePath));

            assert(0 == @offset_of(AdrDevicePath, "type"));
            assert(1 == @offset_of(AdrDevicePath, "subtype"));
            assert(2 == @offset_of(AdrDevicePath, "length"));
            assert(4 == @offset_of(AdrDevicePath, "adr"));
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
            assert(8 == @size_of(AtapiDevicePath));
            assert(1 == @alignOf(AtapiDevicePath));

            assert(0 == @offset_of(AtapiDevicePath, "type"));
            assert(1 == @offset_of(AtapiDevicePath, "subtype"));
            assert(2 == @offset_of(AtapiDevicePath, "length"));
            assert(4 == @offset_of(AtapiDevicePath, "primary_secondary"));
            assert(5 == @offset_of(AtapiDevicePath, "slave_master"));
            assert(6 == @offset_of(AtapiDevicePath, "logical_unit_number"));
        }

        pub const ScsiDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            target_id: u16 align(1),
            logical_unit_number: u16 align(1),
        };

        comptime {
            assert(8 == @size_of(ScsiDevicePath));
            assert(1 == @alignOf(ScsiDevicePath));

            assert(0 == @offset_of(ScsiDevicePath, "type"));
            assert(1 == @offset_of(ScsiDevicePath, "subtype"));
            assert(2 == @offset_of(ScsiDevicePath, "length"));
            assert(4 == @offset_of(ScsiDevicePath, "target_id"));
            assert(6 == @offset_of(ScsiDevicePath, "logical_unit_number"));
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
            assert(24 == @size_of(FibreChannelDevicePath));
            assert(1 == @alignOf(FibreChannelDevicePath));

            assert(0 == @offset_of(FibreChannelDevicePath, "type"));
            assert(1 == @offset_of(FibreChannelDevicePath, "subtype"));
            assert(2 == @offset_of(FibreChannelDevicePath, "length"));
            assert(4 == @offset_of(FibreChannelDevicePath, "reserved"));
            assert(8 == @offset_of(FibreChannelDevicePath, "world_wide_name"));
            assert(16 == @offset_of(FibreChannelDevicePath, "logical_unit_number"));
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
            assert(24 == @size_of(FibreChannelExDevicePath));
            assert(1 == @alignOf(FibreChannelExDevicePath));

            assert(0 == @offset_of(FibreChannelExDevicePath, "type"));
            assert(1 == @offset_of(FibreChannelExDevicePath, "subtype"));
            assert(2 == @offset_of(FibreChannelExDevicePath, "length"));
            assert(4 == @offset_of(FibreChannelExDevicePath, "reserved"));
            assert(8 == @offset_of(FibreChannelExDevicePath, "world_wide_name"));
            assert(16 == @offset_of(FibreChannelExDevicePath, "logical_unit_number"));
        }

        pub const F1394DevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            reserved: u32 align(1),
            guid: u64 align(1),
        };

        comptime {
            assert(16 == @size_of(F1394DevicePath));
            assert(1 == @alignOf(F1394DevicePath));

            assert(0 == @offset_of(F1394DevicePath, "type"));
            assert(1 == @offset_of(F1394DevicePath, "subtype"));
            assert(2 == @offset_of(F1394DevicePath, "length"));
            assert(4 == @offset_of(F1394DevicePath, "reserved"));
            assert(8 == @offset_of(F1394DevicePath, "guid"));
        }

        pub const UsbDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            parent_port_number: u8,
            interface_number: u8,
        };

        comptime {
            assert(6 == @size_of(UsbDevicePath));
            assert(1 == @alignOf(UsbDevicePath));

            assert(0 == @offset_of(UsbDevicePath, "type"));
            assert(1 == @offset_of(UsbDevicePath, "subtype"));
            assert(2 == @offset_of(UsbDevicePath, "length"));
            assert(4 == @offset_of(UsbDevicePath, "parent_port_number"));
            assert(5 == @offset_of(UsbDevicePath, "interface_number"));
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
            assert(10 == @size_of(SataDevicePath));
            assert(1 == @alignOf(SataDevicePath));

            assert(0 == @offset_of(SataDevicePath, "type"));
            assert(1 == @offset_of(SataDevicePath, "subtype"));
            assert(2 == @offset_of(SataDevicePath, "length"));
            assert(4 == @offset_of(SataDevicePath, "hba_port_number"));
            assert(6 == @offset_of(SataDevicePath, "port_multiplier_port_number"));
            assert(8 == @offset_of(SataDevicePath, "logical_unit_number"));
        }

        pub const UsbWwidDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            interface_number: u16 align(1),
            device_vendor_id: u16 align(1),
            device_product_id: u16 align(1),

            pub fn serial_number(self: *const UsbWwidDevicePath) []align(1) const u16 {
                const serial_len = (self.length - @size_of(UsbWwidDevicePath)) / @size_of(u16);
                return @as([*]align(1) const u16, @ptr_cast(@as([*]const u8, @ptr_cast(self)) + @size_of(UsbWwidDevicePath)))[0..serial_len];
            }
        };

        comptime {
            assert(10 == @size_of(UsbWwidDevicePath));
            assert(1 == @alignOf(UsbWwidDevicePath));

            assert(0 == @offset_of(UsbWwidDevicePath, "type"));
            assert(1 == @offset_of(UsbWwidDevicePath, "subtype"));
            assert(2 == @offset_of(UsbWwidDevicePath, "length"));
            assert(4 == @offset_of(UsbWwidDevicePath, "interface_number"));
            assert(6 == @offset_of(UsbWwidDevicePath, "device_vendor_id"));
            assert(8 == @offset_of(UsbWwidDevicePath, "device_product_id"));
        }

        pub const DeviceLogicalUnitDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            lun: u8,
        };

        comptime {
            assert(5 == @size_of(DeviceLogicalUnitDevicePath));
            assert(1 == @alignOf(DeviceLogicalUnitDevicePath));

            assert(0 == @offset_of(DeviceLogicalUnitDevicePath, "type"));
            assert(1 == @offset_of(DeviceLogicalUnitDevicePath, "subtype"));
            assert(2 == @offset_of(DeviceLogicalUnitDevicePath, "length"));
            assert(4 == @offset_of(DeviceLogicalUnitDevicePath, "lun"));
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
            assert(11 == @size_of(UsbClassDevicePath));
            assert(1 == @alignOf(UsbClassDevicePath));

            assert(0 == @offset_of(UsbClassDevicePath, "type"));
            assert(1 == @offset_of(UsbClassDevicePath, "subtype"));
            assert(2 == @offset_of(UsbClassDevicePath, "length"));
            assert(4 == @offset_of(UsbClassDevicePath, "vendor_id"));
            assert(6 == @offset_of(UsbClassDevicePath, "product_id"));
            assert(8 == @offset_of(UsbClassDevicePath, "device_class"));
            assert(9 == @offset_of(UsbClassDevicePath, "device_subclass"));
            assert(10 == @offset_of(UsbClassDevicePath, "device_protocol"));
        }

        pub const I2oDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            tid: u32 align(1),
        };

        comptime {
            assert(8 == @size_of(I2oDevicePath));
            assert(1 == @alignOf(I2oDevicePath));

            assert(0 == @offset_of(I2oDevicePath, "type"));
            assert(1 == @offset_of(I2oDevicePath, "subtype"));
            assert(2 == @offset_of(I2oDevicePath, "length"));
            assert(4 == @offset_of(I2oDevicePath, "tid"));
        }

        pub const MacAddressDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            mac_address: uefi.MacAddress,
            if_type: u8,
        };

        comptime {
            assert(37 == @size_of(MacAddressDevicePath));
            assert(1 == @alignOf(MacAddressDevicePath));

            assert(0 == @offset_of(MacAddressDevicePath, "type"));
            assert(1 == @offset_of(MacAddressDevicePath, "subtype"));
            assert(2 == @offset_of(MacAddressDevicePath, "length"));
            assert(4 == @offset_of(MacAddressDevicePath, "mac_address"));
            assert(36 == @offset_of(MacAddressDevicePath, "if_type"));
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
            assert(27 == @size_of(Ipv4DevicePath));
            assert(1 == @alignOf(Ipv4DevicePath));

            assert(0 == @offset_of(Ipv4DevicePath, "type"));
            assert(1 == @offset_of(Ipv4DevicePath, "subtype"));
            assert(2 == @offset_of(Ipv4DevicePath, "length"));
            assert(4 == @offset_of(Ipv4DevicePath, "local_ip_address"));
            assert(8 == @offset_of(Ipv4DevicePath, "remote_ip_address"));
            assert(12 == @offset_of(Ipv4DevicePath, "local_port"));
            assert(14 == @offset_of(Ipv4DevicePath, "remote_port"));
            assert(16 == @offset_of(Ipv4DevicePath, "network_protocol"));
            assert(18 == @offset_of(Ipv4DevicePath, "static_ip_address"));
            assert(19 == @offset_of(Ipv4DevicePath, "gateway_ip_address"));
            assert(23 == @offset_of(Ipv4DevicePath, "subnet_mask"));
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
            assert(60 == @size_of(Ipv6DevicePath));
            assert(1 == @alignOf(Ipv6DevicePath));

            assert(0 == @offset_of(Ipv6DevicePath, "type"));
            assert(1 == @offset_of(Ipv6DevicePath, "subtype"));
            assert(2 == @offset_of(Ipv6DevicePath, "length"));
            assert(4 == @offset_of(Ipv6DevicePath, "local_ip_address"));
            assert(20 == @offset_of(Ipv6DevicePath, "remote_ip_address"));
            assert(36 == @offset_of(Ipv6DevicePath, "local_port"));
            assert(38 == @offset_of(Ipv6DevicePath, "remote_port"));
            assert(40 == @offset_of(Ipv6DevicePath, "protocol"));
            assert(42 == @offset_of(Ipv6DevicePath, "ip_address_origin"));
            assert(43 == @offset_of(Ipv6DevicePath, "prefix_length"));
            assert(44 == @offset_of(Ipv6DevicePath, "gateway_ip_address"));
        }

        pub const VlanDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            vlan_id: u16 align(1),
        };

        comptime {
            assert(6 == @size_of(VlanDevicePath));
            assert(1 == @alignOf(VlanDevicePath));

            assert(0 == @offset_of(VlanDevicePath, "type"));
            assert(1 == @offset_of(VlanDevicePath, "subtype"));
            assert(2 == @offset_of(VlanDevicePath, "length"));
            assert(4 == @offset_of(VlanDevicePath, "vlan_id"));
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
            assert(48 == @size_of(InfiniBandDevicePath));
            assert(1 == @alignOf(InfiniBandDevicePath));

            assert(0 == @offset_of(InfiniBandDevicePath, "type"));
            assert(1 == @offset_of(InfiniBandDevicePath, "subtype"));
            assert(2 == @offset_of(InfiniBandDevicePath, "length"));
            assert(4 == @offset_of(InfiniBandDevicePath, "resource_flags"));
            assert(8 == @offset_of(InfiniBandDevicePath, "port_gid"));
            assert(24 == @offset_of(InfiniBandDevicePath, "service_id"));
            assert(32 == @offset_of(InfiniBandDevicePath, "target_port_id"));
            assert(40 == @offset_of(InfiniBandDevicePath, "device_id"));
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
            assert(19 == @size_of(UartDevicePath));
            assert(1 == @alignOf(UartDevicePath));

            assert(0 == @offset_of(UartDevicePath, "type"));
            assert(1 == @offset_of(UartDevicePath, "subtype"));
            assert(2 == @offset_of(UartDevicePath, "length"));
            assert(4 == @offset_of(UartDevicePath, "reserved"));
            assert(8 == @offset_of(UartDevicePath, "baud_rate"));
            assert(16 == @offset_of(UartDevicePath, "data_bits"));
            assert(17 == @offset_of(UartDevicePath, "parity"));
            assert(18 == @offset_of(UartDevicePath, "stop_bits"));
        }

        pub const VendorDefinedDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            vendor_guid: Guid align(1),
        };

        comptime {
            assert(20 == @size_of(VendorDefinedDevicePath));
            assert(1 == @alignOf(VendorDefinedDevicePath));

            assert(0 == @offset_of(VendorDefinedDevicePath, "type"));
            assert(1 == @offset_of(VendorDefinedDevicePath, "subtype"));
            assert(2 == @offset_of(VendorDefinedDevicePath, "length"));
            assert(4 == @offset_of(VendorDefinedDevicePath, "vendor_guid"));
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
            assert(42 == @size_of(HardDriveDevicePath));
            assert(1 == @alignOf(HardDriveDevicePath));

            assert(0 == @offset_of(HardDriveDevicePath, "type"));
            assert(1 == @offset_of(HardDriveDevicePath, "subtype"));
            assert(2 == @offset_of(HardDriveDevicePath, "length"));
            assert(4 == @offset_of(HardDriveDevicePath, "partition_number"));
            assert(8 == @offset_of(HardDriveDevicePath, "partition_start"));
            assert(16 == @offset_of(HardDriveDevicePath, "partition_size"));
            assert(24 == @offset_of(HardDriveDevicePath, "partition_signature"));
            assert(40 == @offset_of(HardDriveDevicePath, "partition_format"));
            assert(41 == @offset_of(HardDriveDevicePath, "signature_type"));
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
            assert(24 == @size_of(CdromDevicePath));
            assert(1 == @alignOf(CdromDevicePath));

            assert(0 == @offset_of(CdromDevicePath, "type"));
            assert(1 == @offset_of(CdromDevicePath, "subtype"));
            assert(2 == @offset_of(CdromDevicePath, "length"));
            assert(4 == @offset_of(CdromDevicePath, "boot_entry"));
            assert(8 == @offset_of(CdromDevicePath, "partition_start"));
            assert(16 == @offset_of(CdromDevicePath, "partition_size"));
        }

        pub const VendorDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            guid: Guid align(1),
        };

        comptime {
            assert(20 == @size_of(VendorDevicePath));
            assert(1 == @alignOf(VendorDevicePath));

            assert(0 == @offset_of(VendorDevicePath, "type"));
            assert(1 == @offset_of(VendorDevicePath, "subtype"));
            assert(2 == @offset_of(VendorDevicePath, "length"));
            assert(4 == @offset_of(VendorDevicePath, "guid"));
        }

        pub const FilePathDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),

            pub fn get_path(self: *const FilePathDevicePath) [*:0]align(1) const u16 {
                return @as([*:0]align(1) const u16, @ptr_cast(@as([*]const u8, @ptr_cast(self)) + @size_of(FilePathDevicePath)));
            }
        };

        comptime {
            assert(4 == @size_of(FilePathDevicePath));
            assert(1 == @alignOf(FilePathDevicePath));

            assert(0 == @offset_of(FilePathDevicePath, "type"));
            assert(1 == @offset_of(FilePathDevicePath, "subtype"));
            assert(2 == @offset_of(FilePathDevicePath, "length"));
        }

        pub const MediaProtocolDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            guid: Guid align(1),
        };

        comptime {
            assert(20 == @size_of(MediaProtocolDevicePath));
            assert(1 == @alignOf(MediaProtocolDevicePath));

            assert(0 == @offset_of(MediaProtocolDevicePath, "type"));
            assert(1 == @offset_of(MediaProtocolDevicePath, "subtype"));
            assert(2 == @offset_of(MediaProtocolDevicePath, "length"));
            assert(4 == @offset_of(MediaProtocolDevicePath, "guid"));
        }

        pub const PiwgFirmwareFileDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            fv_filename: Guid align(1),
        };

        comptime {
            assert(20 == @size_of(PiwgFirmwareFileDevicePath));
            assert(1 == @alignOf(PiwgFirmwareFileDevicePath));

            assert(0 == @offset_of(PiwgFirmwareFileDevicePath, "type"));
            assert(1 == @offset_of(PiwgFirmwareFileDevicePath, "subtype"));
            assert(2 == @offset_of(PiwgFirmwareFileDevicePath, "length"));
            assert(4 == @offset_of(PiwgFirmwareFileDevicePath, "fv_filename"));
        }

        pub const PiwgFirmwareVolumeDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
            fv_name: Guid align(1),
        };

        comptime {
            assert(20 == @size_of(PiwgFirmwareVolumeDevicePath));
            assert(1 == @alignOf(PiwgFirmwareVolumeDevicePath));

            assert(0 == @offset_of(PiwgFirmwareVolumeDevicePath, "type"));
            assert(1 == @offset_of(PiwgFirmwareVolumeDevicePath, "subtype"));
            assert(2 == @offset_of(PiwgFirmwareVolumeDevicePath, "length"));
            assert(4 == @offset_of(PiwgFirmwareVolumeDevicePath, "fv_name"));
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
            assert(24 == @size_of(RelativeOffsetRangeDevicePath));
            assert(1 == @alignOf(RelativeOffsetRangeDevicePath));

            assert(0 == @offset_of(RelativeOffsetRangeDevicePath, "type"));
            assert(1 == @offset_of(RelativeOffsetRangeDevicePath, "subtype"));
            assert(2 == @offset_of(RelativeOffsetRangeDevicePath, "length"));
            assert(4 == @offset_of(RelativeOffsetRangeDevicePath, "reserved"));
            assert(8 == @offset_of(RelativeOffsetRangeDevicePath, "start"));
            assert(16 == @offset_of(RelativeOffsetRangeDevicePath, "end"));
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
            assert(38 == @size_of(RamDiskDevicePath));
            assert(1 == @alignOf(RamDiskDevicePath));

            assert(0 == @offset_of(RamDiskDevicePath, "type"));
            assert(1 == @offset_of(RamDiskDevicePath, "subtype"));
            assert(2 == @offset_of(RamDiskDevicePath, "length"));
            assert(4 == @offset_of(RamDiskDevicePath, "start"));
            assert(12 == @offset_of(RamDiskDevicePath, "end"));
            assert(20 == @offset_of(RamDiskDevicePath, "disk_type"));
            assert(36 == @offset_of(RamDiskDevicePath, "instance"));
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

            pub fn get_description(self: *const BBS101DevicePath) [*:0]const u8 {
                return @as([*:0]const u8, @ptr_cast(self)) + @size_of(BBS101DevicePath);
            }
        };

        comptime {
            assert(8 == @size_of(BBS101DevicePath));
            assert(1 == @alignOf(BBS101DevicePath));

            assert(0 == @offset_of(BBS101DevicePath, "type"));
            assert(1 == @offset_of(BBS101DevicePath, "subtype"));
            assert(2 == @offset_of(BBS101DevicePath, "length"));
            assert(4 == @offset_of(BBS101DevicePath, "device_type"));
            assert(6 == @offset_of(BBS101DevicePath, "status_flag"));
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
            assert(4 == @size_of(EndEntireDevicePath));
            assert(1 == @alignOf(EndEntireDevicePath));

            assert(0 == @offset_of(EndEntireDevicePath, "type"));
            assert(1 == @offset_of(EndEntireDevicePath, "subtype"));
            assert(2 == @offset_of(EndEntireDevicePath, "length"));
        }

        pub const EndThisInstanceDevicePath = extern struct {
            type: DevicePath.Type,
            subtype: Subtype,
            length: u16 align(1),
        };

        comptime {
            assert(4 == @size_of(EndEntireDevicePath));
            assert(1 == @alignOf(EndEntireDevicePath));

            assert(0 == @offset_of(EndEntireDevicePath, "type"));
            assert(1 == @offset_of(EndEntireDevicePath, "subtype"));
            assert(2 == @offset_of(EndEntireDevicePath, "length"));
        }
    };
};
