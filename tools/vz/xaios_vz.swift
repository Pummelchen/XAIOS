// Boot XAIOS on Apple's Virtualization.framework.
//
// QEMU's HVF backend cannot run XAIOS: it aborts emulating MMIO whose trap
// carries no instruction syndrome, which happens in both the xHCI and GIC
// paths (QEMU issue 2312, reproducible from other guests since 8.2). That
// leaves TCG, which tells us nothing about cache behaviour or timing.
//
// Virtualization.framework takes a different route. The guest runs on the
// host's own cores, and the interrupt controller and timer are the real
// hardware rather than a userspace model, so the class of failure that blocks
// HVF does not arise. The trade is a fixed device set: virtio over PCI, no
// PL011, and no control over core affinity.
//
// This is deliberately a spike. It answers one question — does Apple's EFI
// firmware load and run the XAIOS loader — and prints whatever the firmware
// and loader write to the virtio console.

import AppKit
import Foundation
import Virtualization

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("xaios-vz: \(message)\n".utf8))
    exit(1)
}

// The variable store is firmware state, not ours; keep it beside the images.
func efiVariableStore(at url: URL) -> VZEFIVariableStore {
    if FileManager.default.fileExists(atPath: url.path) {
        return VZEFIVariableStore(url: url)
    }
    do {
        return try VZEFIVariableStore(creatingVariableStoreAt: url, options: [])
    } catch {
        fail("could not create EFI variable store: \(error)")
    }
}

func blockDevice(_ url: URL, readOnly: Bool) -> VZVirtioBlockDeviceConfiguration {
    guard FileManager.default.fileExists(atPath: url.path) else {
        fail("disk image not found: \(url.path)")
    }
    do {
        let attachment = try VZDiskImageStorageDeviceAttachment(url: url,
                                                               readOnly: readOnly)
        return VZVirtioBlockDeviceConfiguration(attachment: attachment)
    } catch {
        fail("could not attach \(url.lastPathComponent): \(error)")
    }
}

let arguments = CommandLine.arguments
guard arguments.count >= 2 else {
    fail("usage: xaios-vz <boot-image> [more-images...] [--vmnet socket] [--cpus N] [--memory-mib N]")
}

var positional: [String] = []
var cpuCount = 1
var vmnetSocket: String? = nil
var memoryMiB: UInt64 = 2048
// Without a display there is nothing to watch: XAIOS draws its boot progress
// through the UEFI framebuffer, and Apple's firmware does not appear to route
// EFI console output to the virtio console.
var showWindow = false
var usbBoot = false
var index = 1
while index < arguments.count {
    switch arguments[index] {
    case "--vmnet":
        index += 1
        vmnetSocket = arguments[safe: index]
    case "--cpus":
        index += 1
        cpuCount = Int(arguments[safe: index] ?? "") ?? cpuCount
    case "--memory-mib":
        index += 1
        memoryMiB = UInt64(arguments[safe: index] ?? "") ?? memoryMiB
    case "--gui":
        showWindow = true
    case "--usb-boot":
        // Firmware tries the removable-media path, \EFI\BOOT\BOOTAA64.EFI,
        // for removable devices. A virtio disk is fixed storage, for which it
        // may instead expect a boot entry naming the loader explicitly.
        usbBoot = true
    default:
        positional.append(arguments[index])
    }
    index += 1
}

extension Array where Element == String {
    subscript(safe i: Int) -> String? { indices.contains(i) ? self[i] : nil }
}

let bootImage = URL(fileURLWithPath: positional[0])
let stateDirectory = bootImage.deletingLastPathComponent()
    .appendingPathComponent("vz", isDirectory: true)
try? FileManager.default.createDirectory(at: stateDirectory,
                                         withIntermediateDirectories: true)

let configuration = VZVirtualMachineConfiguration()
configuration.cpuCount = cpuCount
configuration.memorySize = memoryMiB * 1024 * 1024
configuration.platform = VZGenericPlatformConfiguration()

let bootLoader = VZEFIBootLoader()
bootLoader.variableStore = efiVariableStore(
    at: stateDirectory.appendingPathComponent("efi-vars"))
configuration.bootLoader = bootLoader

// The boot image is read-only: it is the same artifact the QEMU and Fusion
// paths consume, and nothing here should be able to modify it.
var storage: [VZStorageDeviceConfiguration] = []
if usbBoot {
    if #available(macOS 15.0, *) {
        let controller = VZXHCIControllerConfiguration()
        configuration.usbControllers = [controller]
        do {
            let attachment = try VZDiskImageStorageDeviceAttachment(
                url: bootImage, readOnly: true)
            let usb = VZUSBMassStorageDeviceConfiguration(attachment: attachment)
            storage.append(usb)
        } catch {
            fail("could not attach boot disk over USB: \(error)")
        }
    } else {
        fail("--usb-boot needs macOS 15 or newer")
    }
} else {
    storage.append(blockDevice(bootImage, readOnly: true))
}
// Every disk after the boot image is attached in the order given, because
// the kernel identifies its volumes by position on the bus: the deterministic
// test volume, the persistent MutableFS volume, the model volume, the storage
// administration scratch volume and the A/B system volume, in that order.
// This mirrors the order run-qemu-x86_64.sh uses, which is the layout the
// slot-to-ordinal mapping in the PCI transport expects.
for path in positional.dropFirst() {
    storage.append(blockDevice(URL(fileURLWithPath: path), readOnly: false))
}
configuration.storageDevices = storage

// Apple's NAT attachment carries guest-initiated traffic only, so the Mac
// cannot reach a guest behind it and a listening sshd is unreachable. Given a
// --vmnet path, attach instead to the datagram socket that vmnet-helper relays
// vmnet frames over: the guest then sits on a real vmnet network the host can
// reach. Only the helper needs root; this process does not.
func vmnetAttachment(_ path: String) -> VZFileHandleNetworkDeviceAttachment {
    let descriptor = socket(AF_UNIX, SOCK_DGRAM, 0)
    if descriptor < 0 { fail("could not create the vmnet socket") }

    // Each side binds a known path and sends to the other's, so neither has to
    // start first.
    func address(_ value: String) -> sockaddr_un {
        var storage = sockaddr_un()
        storage.sun_family = sa_family_t(AF_UNIX)
        storage.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let capacity = MemoryLayout.size(ofValue: storage.sun_path)
        let offset = MemoryLayout<sockaddr_un>.offset(of: \.sun_path)!
        withUnsafeMutablePointer(to: &storage) { pointer in
            let bytes = UnsafeMutableRawPointer(pointer)
                .advanced(by: offset)
                .assumingMemoryBound(to: CChar.self)
            _ = strncpy(bytes, value, capacity - 1)
        }
        return storage
    }

    let localPath = path + ".vm"
    unlink(localPath)
    var local = address(localPath)
    let bound = withUnsafePointer(to: &local) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { generic in
            bind(descriptor, generic, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    if bound < 0 { fail("could not bind \(localPath): \(String(cString: strerror(errno)))") }

    var peer = address(path)
    let connected = withUnsafePointer(to: &peer) { pointer in
        pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { generic in
            connect(descriptor, generic, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
    if connected < 0 {
        fail("could not reach \(path): \(String(cString: strerror(errno))). Start vmnet-helper first.")
    }

    // Virtualization.framework expects the receive buffer to be at least double
    // the send buffer, and recommends four times. Sizing them equally leaves it
    // reading nothing: frames written to this socket never reach the guest,
    // while the guest's own traffic still flows out, which looks like a one-way
    // network rather than a misconfigured socket.
    var sendBuffer: Int32 = 1 << 18
    var receiveBuffer: Int32 = sendBuffer * 4
    setsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &sendBuffer, socklen_t(MemoryLayout<Int32>.size))
    setsockopt(descriptor, SOL_SOCKET, SO_RCVBUF, &receiveBuffer, socklen_t(MemoryLayout<Int32>.size))

    return VZFileHandleNetworkDeviceAttachment(
        fileHandle: FileHandle(fileDescriptor: descriptor, closeOnDealloc: false))
}

let network = VZVirtioNetworkDeviceConfiguration()
if let vmnetSocket {
    network.attachment = vmnetAttachment(vmnetSocket)
} else {
    network.attachment = VZNATNetworkDeviceAttachment()
}
configuration.networkDevices = [network]

configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]

if showWindow {
    let graphics = VZVirtioGraphicsDeviceConfiguration()
    graphics.scanouts = [
        VZVirtioGraphicsScanoutConfiguration(widthInPixels: 1280,
                                             heightInPixels: 800)
    ]
    configuration.graphicsDevices = [graphics]
}

// XAIOS logs to PL011, which this platform does not have, so nothing from the
// kernel proper will appear here yet. The firmware and the UEFI loader write
// through EFI console services, which do land on this port, and that is
// exactly what the spike needs to observe.
let console = VZVirtioConsoleDeviceSerialPortConfiguration()
console.attachment = VZFileHandleSerialPortAttachment(
    fileHandleForReading: FileHandle.standardInput,
    fileHandleForWriting: FileHandle.standardOutput)
configuration.serialPorts = [console]

do {
    try configuration.validate()
} catch {
    fail("configuration rejected: \(error)")
}

final class Observer: NSObject, VZVirtualMachineDelegate {
    func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        FileHandle.standardError.write(Data("xaios-vz: guest stopped\n".utf8))
        exit(0)
    }
    func virtualMachine(_ virtualMachine: VZVirtualMachine,
                        didStopWithError error: Error) {
        fail("guest stopped with error: \(error)")
    }
}

// VZVirtualMachineView requires the machine to live on the main queue, so
// both modes use it rather than keeping two lifetimes to reason about.
let observer = Observer()
let machine = VZVirtualMachine(configuration: configuration)
machine.delegate = observer

func startMachine() {
    machine.start { result in
        if case .failure(let error) = result {
            fail("start failed: \(error)")
        }
        FileHandle.standardError.write(Data(
            "xaios-vz: started cpus=\(cpuCount) memory=\(memoryMiB)MiB\n".utf8))
    }
}

if showWindow {
    let application = NSApplication.shared
    application.setActivationPolicy(.regular)
    let view = VZVirtualMachineView(frame: NSRect(x: 0, y: 0, width: 1280, height: 800))
    view.virtualMachine = machine
    let window = NSWindow(
        contentRect: view.frame,
        styleMask: [.titled, .closable, .resizable],
        backing: .buffered, defer: false)
    window.title = "XAIOS"
    window.contentView = view
    window.makeKeyAndOrderFront(nil)
    application.activate(ignoringOtherApps: true)
    DispatchQueue.main.async { startMachine() }
    application.run()
} else {
    DispatchQueue.main.async { startMachine() }
    RunLoop.main.run()
}
