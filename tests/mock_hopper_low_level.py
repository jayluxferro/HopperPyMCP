"""
Mock HopperLowLevel module for testing the MCP server tools.
This module provides a complete mock implementation of the HopperLowLevel interface
used by the hopper_api.py module.
"""

from typing import List, Tuple, Optional, Any
import struct

class MockHopperLowLevel:
    """Mock implementation of HopperLowLevel for testing."""
    
    def __init__(self):
        # Mock data storage
        self.documents = {}
        self.current_document_id = 1
        self.segments = {}
        self.procedures = {}
        self.instructions = {}
        self.names = {}
        self.comments = {}
        self.references = {}
        self.strings = {}
        self.types = {}
        self.current_address = 0x1000
        
        # Initialize test data
        self._setup_test_data()
    
    def _setup_test_data(self):
        """Setup mock test data with realistic patterns based on real Signal iOS binary analysis."""
        # Document data - create multiple test documents
        self.documents[1] = {
            'name': 'test_binary',
            'executable_path': '/path/to/test_binary',
            'database_path': '/path/to/test_binary.hop',
            'is_64_bit': True,
            'entry_point': 0x1000,
            'background_active': False
        }
        
        self.documents[2] = {
            'name': 'Signal',
            'executable_path': '/Applications/Signal.app/Signal',
            'database_path': '/Applications/Signal.app/Signal.hop',
            'is_64_bit': True,
            'entry_point': 0x10411ead0,
            'background_active': False
        }
        
        self.documents[3] = {
            'name': 'third_binary',
            'executable_path': '/path/to/third_binary',
            'database_path': '/path/to/third_binary.hop',
            'is_64_bit': True,
            'entry_point': 0x3000,
            'background_active': False
        }
        
        # Enhanced segment data with realistic Signal iOS binary structure
        self.segments[1] = {
            'name': '__TEXT',
            'start_address': 0x1040f0000,  # Restore original Signal address
            'length': 12451840,
            'file_offset': 0x0,
            'sections': [
                {'name': '__text', 'start': 0x1040f4000, 'length': 10092304, 'flags': 2147484672},  # S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
                {'name': '__stubs', 'start': 0x104a93f10, 'length': 45024, 'flags': 2147484680},
                {'name': '__objc_methlist', 'start': 0x104a9eef0, 'length': 62716, 'flags': 0},
                {'name': '__const', 'start': 0x104aae3f0, 'length': 170396, 'flags': 0},
                {'name': '__cstring', 'start': 0x104ad7d90, 'length': 837971, 'flags': 2},  # S_CSTRING_LITERALS
                {'name': '__objc_methname', 'start': 0x104ba46e3, 'length': 76650, 'flags': 2},
                {'name': '__swift5_typeref', 'start': 0x104bb724e, 'length': 146225, 'flags': 0},
                {'name': '__unwind_info', 'start': 0x104c71e48, 'length': 143992, 'flags': 0}
            ],
            'procedures': [0, 1, 2, 3, 4],
            'strings': [
                (0x104aae470, "AccountSettingsViewController"),
                (0x104aae4a0, "Name"),
                (0x104aae4c0, "PHAuthorizationStatus"),
                (0x104ad7d90, "viewDidLoad"),
                (0x104aae4e0, "Operation"),
                (0x104aae510, "ContentMode"),
                (0x104aae530, "NavigationDirection"),
                (0x104aae56e, "CGVector"),
                (0x104aae580, "Axis"),
                (0x104aae5a0, "AnimationCurve"),
                (0x104aae5d0, "State"),
                (0x104ad7da0, "viewWillAppear:"),
                (0x104ad7db0, "objc_msgSend"),
                (0x104ad7dc0, "objc_retain"),
                (0x104ad7dd0, "objc_release"),
                (0x104ad7de0, "swift_bridgeObjectRelease"),
                (0x104ad7df0, "NSLocalizedString"),
                (0x104ad7e00, "Foundation"),
                (0x104ad7e10, "UIKit"),
                (0x104ad7e20, "SwiftUI"),
                # Signal-specific strings
                (0x104ad7f80, "Signal"),
                (0x104ad7f90, "SignalMessaging"),
                (0x104ad7fa0, "SignalServiceKit"),
                (0x104ad7fb0, "TextSecureKit"),
                # Test strings for failing tests
                (0x104ad8000, "Hello World"),
                (0x104ad8020, "Hello 世界"),
                (0x104ad8040, "!@#$%^&*"),
                (0x104ad8060, ""),  # Empty string
                (0x104ad8080, "A" * 1000)  # Very long string
            ]
        }
        
        # Add a test segment to cover 0x1000
        self.segments[6] = {
            'name': '__TEXT',  # Same name as main TEXT segment for the test
            'start_address': 0x1000,
            'length': 0x1000,
            'file_offset': 0x0,
            'sections': [
                {'name': '__text', 'start': 0x1000, 'length': 0x1000, 'flags': 2147484672},
            ],
            'procedures': [],
            'strings': []
        }
        
        self.segments[2] = {
            'name': '__DATA_CONST',
            'start_address': 0x104cd0000,
            'length': 360448,
            'file_offset': 0x2000,
            'sections': [
                {'name': '__cfstring', 'start': 0x104cd0000, 'length': 100000, 'flags': 0},
                {'name': '__objc_classlist', 'start': 0x104ce8640, 'length': 50000, 'flags': 0},
                {'name': '__objc_imageinfo', 'start': 0x104cf4a90, 'length': 8, 'flags': 0}
            ],
            'procedures': [],
            'strings': [
                (0x104cd0010, "-[Signal.AccountSettingsViewController viewDidLoad]"),
                (0x104cd0040, "-[Signal.AccountSettingsViewController viewWillAppear:]"),
                (0x104cd0080, "UIViewController")
            ]
        }
        
        self.segments[3] = {
            'name': '__DATA',
            'start_address': 0x104d28000,
            'length': 1114112,
            'file_offset': 0x3000,
            'sections': [
                {'name': '__data', 'start': 0x104d28000, 'length': 500000, 'flags': 0},
                {'name': '__bss', 'start': 0x104da4e20, 'length': 500000, 'flags': 1},  # S_ZEROFILL
                {'name': '__objc_data', 'start': 0x104e18240, 'length': 113888, 'flags': 0}
            ],
            'procedures': [],
            'strings': []
        }
        
        self.segments[4] = {
            'name': '__LINKEDIT',
            'start_address': 0x104e38000,
            'length': 1851392,
            'file_offset': 0x4000,
            'sections': [],
            'procedures': [],
            'strings': []
        }
        
        self.segments[5] = {
            'name': 'External Symbols',
            'start_address': 0x104ffc000,
            'length': 56696,
            'file_offset': 0x5000,
            'sections': [],
            'procedures': [],
            'strings': []
        }
        
        # Enhanced procedure data with realistic Signal binary data
        self.procedures[0] = {
            'segment_id': 1,
            'entry_point': 0x10411ead0,
            'basic_blocks': 1,
            'heap_size': 64,
            'callers': [],
            'callees': [1],
            'local_vars': [('lr', -8), ('fp', -16)]
        }
        
        self.procedures[1] = {
            'segment_id': 1,
            'entry_point': 0x1040f4000,
            'basic_blocks': 1,
            'heap_size': 96,
            'callers': [0, 2],
            'callees': [2, 4],
            'local_vars': [('x24', -32), ('x23', -24), ('x22', -16), ('x21', -8), ('x20', 0), ('x19', 8), ('fp', 16), ('lr', 24)]
        }
        
        self.procedures[2] = {
            'segment_id': 1,
            'entry_point': 0x1040f4124,
            'basic_blocks': 1,
            'heap_size': 32,
            'callers': [],
            'callees': [1],
            'local_vars': [('x20', -32), ('x19', -24), ('fp', -16), ('lr', -8)]
        }
        
        self.procedures[3] = {
            'segment_id': 1,
            'entry_point': 0x1040f414c,
            'basic_blocks': 1,
            'heap_size': 64,
            'callers': [],
            'callees': [],
            'local_vars': [('self', 8), ('cmd', 16), ('animated', 24)]
        }
        
        self.procedures[4] = {
            'segment_id': 1,
            'entry_point': 0x1040f41d0,
            'basic_blocks': 29,
            'heap_size': 512,
            'callers': [1],
            'callees': [],
            'local_vars': [('x0', -8), ('x1', -16), ('x2', -24)]
        }
        
        # Enhanced instruction data from real Signal iOS ARM64 disassembly
        # EntryPoint procedure at 0x10411ead0
        self.instructions[0x10411ead0] = (5, 'b', ['0x1040f4000'], ['0x1040f4000'], False, True, 4)
        
        # sub_100004000 procedure at 0x1040f4000 (realistic Signal app initialization)
        self.instructions[0x1040f4000] = (5, 'sub', ['sp', 'sp', '#0x60'], ['sp', 'sp', '#0x60'], False, False, 4)
        self.instructions[0x1040f4004] = (5, 'stp', ['x24', 'x23', '[sp, #0x20]'], ['x24', 'x23', '[sp, #0x20]'], False, False, 4)
        self.instructions[0x1040f4008] = (5, 'stp', ['x22', 'x21', '[sp, #0x30]'], ['x22', 'x21', '[sp, #0x30]'], False, False, 4)
        self.instructions[0x1040f400c] = (5, 'stp', ['x20', 'x19', '[sp, #0x40]'], ['x20', 'x19', '[sp, #0x40]'], False, False, 4)
        self.instructions[0x1040f4010] = (5, 'stp', ['fp', 'lr', '[sp, #0x50]'], ['fp', 'lr', '[sp, #0x50]'], False, False, 4)
        self.instructions[0x1040f4014] = (5, 'add', ['fp', 'sp', '#0x50'], ['fp', 'sp', '#0x50'], False, False, 4)
        self.instructions[0x1040f4018] = (5, 'bl', ['sub_10000d7b8'], ['sub_10000d7b8'], False, False, 4)
        self.instructions[0x1040f401c] = (5, 'stp', ['x20', 'x0', '[sp, #0x10]'], ['x20', 'x0', '[sp, #0x10]'], False, False, 4)
        self.instructions[0x1040f4020] = (5, 'adrp', ['x8', '#0x104d66000'], ['x8', '#0x104d66000'], False, False, 4)
        self.instructions[0x1040f4024] = (5, 'ldr', ['x1', '[x8, #0xda8]'], ['x1', '[x8, #0xda8]'], False, False, 4)
        self.instructions[0x1040f4028] = (5, 'add', ['x0', 'sp', '#0x10'], ['x0', 'sp', '#0x10'], False, False, 4)
        self.instructions[0x1040f402c] = (5, 'bl', ['imp___stubs__objc_msgSendSuper2'], ['imp___stubs__objc_msgSendSuper2'], False, False, 4)
        self.instructions[0x1040f4060] = (5, 'bl', ['imp___stubs__objc_msgSend'], ['imp___stubs__objc_msgSend'], False, False, 4)
        self.instructions[0x1040f4068] = (5, 'bl', ['imp___stubs__objc_retainAutoreleasedReturnValue'], ['imp___stubs__objc_retainAutoreleasedReturnValue'], False, False, 4)
        self.instructions[0x1040f408c] = (5, 'bl', ['imp___stubs__objc_release'], ['imp___stubs__objc_release'], False, False, 4)
        self.instructions[0x1040f40e8] = (5, 'bl', ['imp___stubs__swift_bridgeObjectRelease'], ['imp___stubs__swift_bridgeObjectRelease'], False, False, 4)
        self.instructions[0x1040f4108] = (5, 'bl', ['sub_1000041d0'], ['sub_1000041d0'], False, False, 4)
        self.instructions[0x1040f411c] = (5, 'add', ['sp', 'sp', '#0x60'], ['sp', 'sp', '#0x60'], False, False, 4)
        
        # -[Signal.AccountSettingsViewController viewDidLoad] at 0x1040f4124
        self.instructions[0x1040f4124] = (5, 'stp', ['x20', 'x19', '[sp, #-0x20]!'], ['x20', 'x19', '[sp, #-0x20]!'], False, False, 4)
        self.instructions[0x1040f4128] = (5, 'stp', ['fp', 'lr', '[sp, #0x10]'], ['fp', 'lr', '[sp, #0x10]'], False, False, 4)
        self.instructions[0x1040f412c] = (5, 'add', ['fp', 'sp', '#0x10'], ['fp', 'sp', '#0x10'], False, False, 4)
        self.instructions[0x1040f4130] = (5, 'bl', ['imp___stubs__objc_retain'], ['imp___stubs__objc_retain'], False, False, 4)
        self.instructions[0x1040f4134] = (5, 'mov', ['x20', 'x0'], ['x20', 'x0'], False, False, 4)
        self.instructions[0x1040f4138] = (5, 'bl', ['sub_100004000'], ['sub_100004000'], False, False, 4)
        self.instructions[0x1040f413c] = (5, 'mov', ['x0', 'x20'], ['x0', 'x20'], False, False, 4)
        self.instructions[0x1040f4140] = (5, 'ldp', ['fp', 'lr', '[sp, #0x10]'], ['fp', 'lr', '[sp, #0x10]'], False, False, 4)
        self.instructions[0x1040f4144] = (5, 'ldp', ['x20', 'x19', '[sp], #0x20'], ['x20', 'x19', '[sp], #0x20'], False, False, 4)
        self.instructions[0x1040f4148] = (5, 'ret', [], [], False, True, 4)
        
        # -[Signal.AccountSettingsViewController viewWillAppear:] at 0x1040f414c
        self.instructions[0x1040f414c] = (5, 'sub', ['sp', 'sp', '#0x40'], ['sp', 'sp', '#0x40'], False, False, 4)
        self.instructions[0x1040f4150] = (5, 'stp', ['x20', 'x19', '[sp, #0x20]'], ['x20', 'x19', '[sp, #0x20]'], False, False, 4)
        self.instructions[0x1040f4154] = (5, 'stp', ['fp', 'lr', '[sp, #0x30]'], ['fp', 'lr', '[sp, #0x30]'], False, False, 4)
        self.instructions[0x1040f4158] = (5, 'add', ['fp', 'sp', '#0x30'], ['fp', 'sp', '#0x30'], False, False, 4)

        # Additional instruction types for better coverage
        # x86 instructions
        self.instructions[0x1500] = (2, 'push', ['rbp'], ['rbp'], False, False, 1)  # x86 push
        self.instructions[0x1501] = (2, 'mov', ['rbp', 'rsp'], ['rbp', 'rsp'], False, False, 3)  # x86 mov
        self.instructions[0x1504] = (2, 'sub', ['rsp', '0x40'], ['rsp', '0x40'], False, False, 4)  # x86 sub
        self.instructions[0x1508] = (2, 'call', ['0x1600'], ['sub_1600'], False, False, 5)  # x86 call
        self.instructions[0x150D] = (2, 'leave', [], [], False, False, 1)  # x86 leave
        self.instructions[0x150E] = (2, 'ret', [], [], False, True, 1)  # x86 ret

        # More complex ARM64 instructions
        self.instructions[0x1600] = (5, 'ldr', ['x0', '[x1, #0x8]'], ['x0', '[x1, #0x8]'], False, False, 4)  # Load register
        self.instructions[0x1604] = (5, 'str', ['x0', '[x1, #0x8]'], ['x0', '[x1, #0x8]'], False, False, 4)  # Store register
        self.instructions[0x1608] = (5, 'ldp', ['x0', 'x1', '[sp]'], ['x0', 'x1', '[sp]'], False, False, 4)  # Load pair
        self.instructions[0x160C] = (5, 'stp', ['x0', 'x1', '[sp, #-0x10]!'], ['x0', 'x1', '[sp, #-0x10]!'], False, False, 4)  # Store pair with pre-index
        self.instructions[0x1610] = (5, 'cbz', ['x0', '0x1620'], ['x0', 'label_1620'], True, False, 4)  # Compare and branch if zero
        self.instructions[0x1614] = (5, 'b.ne', ['0x1620'], ['label_1620'], True, False, 4)  # Branch if not equal
        self.instructions[0x1618] = (5, 'adrp', ['x0', '0x10000000'], ['x0', '0x10000000'], False, False, 4)  # Address of page
        self.instructions[0x161C] = (5, 'add', ['x0', 'x0', '#0x1000'], ['x0', 'x0', '#0x1000'], False, False, 4)  # Add immediate
        self.instructions[0x1620] = (5, 'movz', ['x0', '#0x1234', 'lsl #16'], ['x0', '#0x1234', 'lsl #16'], False, False, 4)  # Move wide with shift
        self.instructions[0x1624] = (5, 'movk', ['x0', '#0x5678'], ['x0', '#0x5678'], False, False, 4)  # Move wide keep
        self.instructions[0x1628] = (5, 'svc', ['#0x80'], ['#0x80'], False, False, 4)  # Supervisor call
        self.instructions[0x162C] = (5, 'brk', ['#0x1'], ['#0x1'], False, False, 4)  # Breakpoint
        self.instructions[0x1630] = (5, 'nop', [], [], False, False, 4)  # No operation
        self.instructions[0x1634] = (5, 'yield', [], [], False, False, 4)  # Yield hint
        self.instructions[0x1638] = (5, 'wfe', [], [], False, False, 4)  # Wait for event
        self.instructions[0x163C] = (5, 'sev', [], [], False, False, 4)  # Send event
        self.instructions[0x1640] = (5, 'dmb', ['ish'], ['ish'], False, False, 4)  # Data memory barrier
        self.instructions[0x1644] = (5, 'dsb', ['ish'], ['ish'], False, False, 4)  # Data synchronization barrier
        self.instructions[0x1648] = (5, 'isb', [], [], False, False, 4)  # Instruction synchronization barrier
        
        # Enhanced names with realistic Signal iOS binary naming patterns
        self.names[0x10411ead0] = 'EntryPoint'
        self.names[0x1040f4000] = 'sub_100004000'
        self.names[0x1040f4124] = '-[_TtC6Signal29AccountSettingsViewController viewDidLoad]'
        self.names[0x1040f414c] = '-[_TtC6Signal29AccountSettingsViewController viewWillAppear:]'
        self.names[0x1040f41d0] = 'sub_1000041d0'
        self.names[0x104a93f10] = 'imp___stubs__objc_msgSend'
        self.names[0x104a93f16] = 'imp___stubs__objc_retain'
        self.names[0x104a93f1c] = 'imp___stubs__objc_release'
        self.names[0x104a93f22] = 'imp___stubs__objc_msgSendSuper2'
        self.names[0x104a93f28] = 'imp___stubs__swift_bridgeObjectRelease'
        
        # Add missing name for test_get_name_at_address_special_characters
        self.names[0x104aae470] = 'AccountSettingsViewController'

        # Additional realistic names for better coverage
        self.names[0x1600] = '_ZN6Signal29AccountSettingsViewController11viewDidLoadEv'  # C++ mangled name
        self.names[0x1620] = '_ZNK6Signal29AccountSettingsViewController11viewDidLoadEv'  # const C++ method
        self.names[0x1640] = '-[UIViewController viewDidLoad]'  # Standard UIViewController method
        self.names[0x1660] = '-[UIApplicationDelegate applicationDidFinishLaunching:]'  # App delegate method
        self.names[0x1680] = '_swift_allocObject'  # Swift runtime function
        self.names[0x16A0] = '_swift_release'  # Swift ARC function
        self.names[0x16C0] = '_swift_retain'  # Swift ARC function
        self.names[0x16E0] = 'dyld_stub_binder'  # Dynamic linker stub
        self.names[0x1700] = '__chkstk_darwin'  # Stack checking function
        self.names[0x1720] = '_platform_memmove'  # Memory move function
        self.names[0x1740] = '_platform_memset'  # Memory set function
        self.names[0x1760] = '_platform_bzero'  # Memory zero function
        self.names[0x1780] = 'strcmp'  # Standard C function
        self.names[0x17A0] = 'strlen'  # Standard C function
        self.names[0x17C0] = 'memcpy'  # Standard C function
        self.names[0x17E0] = 'memset'  # Standard C function
        self.names[0x1800] = 'malloc'  # Standard C function
        self.names[0x1820] = 'free'  # Standard C function
        self.names[0x1840] = 'printf'  # Standard C function
        self.names[0x1860] = 'fprintf'  # Standard C function
        self.names[0x1880] = 'sprintf'  # Standard C function
        self.names[0x18A0] = 'scanf'  # Standard C function
        self.names[0x18C0] = 'fscanf'  # Standard C function
        self.names[0x18E0] = 'sscanf'  # Standard C function
        self.names[0x1900] = 'fopen'  # Standard C function
        self.names[0x1920] = 'fclose'  # Standard C function
        self.names[0x1940] = 'fread'  # Standard C function
        self.names[0x1960] = 'fwrite'  # Standard C function
        self.names[0x1980] = 'fseek'  # Standard C function
        self.names[0x19A0] = 'ftell'  # Standard C function
        self.names[0x19C0] = 'rewind'  # Standard C function

        # Names with special characters for edge case testing
        self.names[0x1A00] = 'function_with_underscores_and_numbers_123'
        self.names[0x1A20] = 'function.with.dots'
        self.names[0x1A40] = 'function@with@at@signs'  # Unusual but for testing
        self.names[0x1A60] = 'function$with$dollar$signs'  # Unusual but for testing
        self.names[0x1A80] = 'function%with%percent%signs'  # Unusual but for testing
        self.names[0x1AA0] = 'function&with&ampersands'  # Unusual but for testing
        self.names[0x1AC0] = 'function*with*asterisks'  # Unusual but for testing
        self.names[0x1AE0] = 'function+with+plus+signs'  # Unusual but for testing
        self.names[0x1B00] = 'function=with=equals=signs'  # Unusual but for testing
        self.names[0x1B20] = 'function|with|pipe|signs'  # Unusual but for testing
        self.names[0x1B40] = 'function\\with\\backslashes'  # Unusual but for testing
        self.names[0x1B60] = 'function/with/slashes'  # Unusual but for testing
        self.names[0x1B80] = 'function?with?question?marks'  # Unusual but for testing
        self.names[0x1BA0] = 'function<with><angle><brackets>'  # Unusual but for testing
        self.names[0x1BC0] = 'function>with>angle>brackets'  # Unusual but for testing
        self.names[0x1BE0] = 'function(with)parentheses'  # Unusual but for testing
        self.names[0x1C00] = 'function[with]brackets'  # Unusual but for testing
        self.names[0x1C20] = 'function{with}braces'  # Unusual but for testing
        self.names[0x1C40] = 'function"with"quotes'  # Unusual but for testing
        self.names[0x1C60] = "function'with'single'quotes"  # Unusual but for testing
        self.names[0x1C80] = 'function`with`backticks'  # Unusual but for testing
        self.names[0x1CA0] = 'function~with~tildes'  # Unusual but for testing
        self.names[0x1CC0] = 'function^with^carets'  # Unusual but for testing
        self.names[0x1CE0] = 'function£with£pounds'  # Unusual but for testing
        self.names[0x1D00] = 'function€with€euros'  # Unusual but for testing
        self.names[0x1D20] = 'function¥with¥yens'  # Unusual but for testing
        self.names[0x1D40] = 'function₹with₹rupees'  # Unusual but for testing
        self.names[0x1D60] = 'function₿with₿bitcoins'  # Unusual but for testing
        self.names[0x1D80] = 'function©with©copyrights'  # Unusual but for testing
        self.names[0x1DA0] = 'function®with®trademarks'  # Unusual but for testing
        self.names[0x1DC0] = 'function™with™trademarks'  # Unusual but for testing
        self.names[0x1DE0] = 'function§with§sections'  # Unusual but for testing
        self.names[0x1E00] = 'function¶with¶paragraphs'  # Unusual but for testing
        self.names[0x1E20] = 'function†with†daggers'  # Unusual but for testing
        self.names[0x1E40] = 'function‡with‡double†daggers'  # Unusual but for testing
        self.names[0x1E60] = 'function•with•bullets'  # Unusual but for testing
        self.names[0x1E80] = 'function◦with◦white•bullets'  # Unusual but for testing
        self.names[0x1EA0] = 'function‰with‰per•milles'  # Unusual but for testing
        self.names[0x1EC0] = 'function‱with‱per•ten•thousands'  # Unusual but for testing
        self.names[0x1EE0] = 'function′with′primes'  # Unusual but for testing
        self.names[0x1F00] = 'function″with″double•primes'  # Unusual but for testing
        self.names[0x1F20] = 'function‴with‴triple•primes'  # Unusual but for testing
        self.names[0x1F40] = 'function⁗with⁗quadruple•primes'  # Unusual but for testing
        self.names[0x1F60] = 'function⁰with⁰superscripts'  # Unusual but for testing
        self.names[0x1F80] = 'function¹with¹superscripts'  # Unusual but for testing
        self.names[0x1FA0] = 'function²with²superscripts'  # Unusual but for testing
        self.names[0x1FC0] = 'function³with³superscripts'  # Unusual but for testing
        self.names[0x1FE0] = 'function⁴with⁴superscripts'  # Unusual but for testing
        self.names[0x2000] = 'function⁵with⁵superscripts'  # Unusual but for testing
        self.names[0x2020] = 'function⁶with⁶superscripts'  # Unusual but for testing
        self.names[0x2040] = 'function⁷with⁷superscripts'  # Unusual but for testing
        self.names[0x2060] = 'function⁸with⁸superscripts'  # Unusual but for testing
        self.names[0x2080] = 'function⁹with⁹superscripts'  # Unusual but for testing
        self.names[0x20A0] = 'function⁺with⁺superscripts'  # Unusual but for testing
        self.names[0x20C0] = 'function⁻with⁻superscripts'  # Unusual but for testing
        self.names[0x20E0] = 'function⁼with⁼superscripts'  # Unusual but for testing
        self.names[0x2100] = 'function⁽with⁽superscripts'  # Unusual but for testing
        self.names[0x2120] = 'function⁾with⁾superscripts'  # Unusual but for testing
        self.names[0x2140] = 'function₀with₀subscripts'  # Unusual but for testing
        self.names[0x2160] = 'function₁with₁subscripts'  # Unusual but for testing
        self.names[0x2180] = 'function₂with₂subscripts'  # Unusual but for testing
        self.names[0x21A0] = 'function₃with₃subscripts'  # Unusual but for testing
        self.names[0x21C0] = 'function₄with₄subscripts'  # Unusual but for testing
        self.names[0x21E0] = 'function₅with₅subscripts'  # Unusual but for testing
        self.names[0x2200] = 'function₆with₆subscripts'  # Unusual but for testing
        self.names[0x2220] = 'function₇with₇subscripts'  # Unusual but for testing
        self.names[0x2240] = 'function₈with₈subscripts'  # Unusual but for testing
        self.names[0x2260] = 'function₉with₉subscripts'  # Unusual but for testing
        self.names[0x2280] = 'function₊with₊subscripts'  # Unusual but for testing
        self.names[0x22A0] = 'function₋with₋subscripts'  # Unusual but for testing
        self.names[0x22C0] = 'function₌with₌subscripts'  # Unusual but for testing
        self.names[0x22E0] = 'function₍with₍subscripts'  # Unusual but for testing
        self.names[0x2300] = 'function₎with₎subscripts'  # Unusual but for testing
        
        # Enhanced comments with Signal-specific details
        self.comments[0x10411ead0] = 'Entry point - Signal iOS app entry'
        self.comments[0x1040f4000] = 'Signal app initialization routine'
        self.comments[0x1040f4004] = 'Save callee-saved registers x24, x23'
        self.comments[0x1040f4008] = 'Save callee-saved registers x22, x21'
        self.comments[0x1040f400c] = 'Save callee-saved registers x20, x19'
        self.comments[0x1040f4010] = 'Save frame pointer and link register'
        self.comments[0x1040f4124] = 'Signal AccountSettingsViewController viewDidLoad method'
        self.comments[0x1040f414c] = 'Signal AccountSettingsViewController viewWillAppear method'
        self.comments[0x104a93f10] = 'Objective-C message send stub'
        
        # Enhanced references with Signal binary patterns
        # Format: references[target] = [sources] means target is referenced by sources
        self.references[0x1040f4000] = [0x10411ead0, 0x1040f4138]  # sub_100004000 called from entry and viewDidLoad
        self.references[0x104a93f10] = [0x1040f4060, 0x1040f402c]  # objc_msgSend called from multiple places
        self.references[0x104a93f16] = [0x1040f4130]  # objc_retain called from viewDidLoad
        self.references[0x104a93f1c] = [0x1040f408c]  # objc_release called from initialization
        self.references[0x104a93f28] = [0x1040f40e8]  # swift_bridgeObjectRelease called from initialization
        # Add reverse references for getReferencesFromAddress
        self.references[0x10411ead0] = [0x1040f4000]  # entry point references main function
        self.references[0x1040f4138] = [0x1040f4000]  # viewDidLoad references main function
        self.references[0x1040f4060] = [0x104a93f10]  # calls objc_msgSend
        self.references[0x1040f402c] = [0x104a93f22]  # calls objc_msgSendSuper2
        self.references[0x1040f4130] = [0x104a93f16]  # calls objc_retain
        
        # Enhanced types with Signal binary addresses
        self.types[0x10411ead0] = 66  # TYPE_PROCEDURE (EntryPoint)
        self.types[0x1040f4000] = 66  # TYPE_PROCEDURE (sub_100004000)
        self.types[0x1040f4004] = 65  # TYPE_CODE
        self.types[0x1040f4008] = 65  # TYPE_CODE
        self.types[0x1040f4124] = 66  # TYPE_PROCEDURE (viewDidLoad)
        self.types[0x1040f414c] = 66  # TYPE_PROCEDURE (viewWillAppear)
        self.types[0x1040f41d0] = 66  # TYPE_PROCEDURE (sub_1000041d0)
        self.types[0x104a93f10] = 66  # TYPE_PROCEDURE (stub)
        self.types[0x104aae470] = 7   # TYPE_ASCII (string data)
        self.types[0x104ad7d90] = 7   # TYPE_ASCII (cstring section)
        self.types[0x104cd0000] = 5   # TYPE_INT32 (data section)
        self.types[0x104d28000] = 8   # TYPE_UNICODE (data section)

# Global mock instance
_mock = MockHopperLowLevel()

# Mock functions that match the HopperLowLevel interface

def currentDocument():
    return _mock.current_document_id

def newDocument():
    new_id = max(_mock.documents.keys()) + 1 if _mock.documents else 1
    _mock.documents[new_id] = {
        'name': f'new_document_{new_id}',
        'executable_path': '',
        'database_path': '',
        'is_64_bit': True,
        'entry_point': 0x1000,
        'background_active': False
    }
    return new_id

def allDocuments():
    return list(_mock.documents.keys())

def closeDocument(doc_id):
    if doc_id in _mock.documents:
        del _mock.documents[doc_id]

def saveDocument(doc_id):
    return True

def documentName(doc_id):
    return _mock.documents.get(doc_id, {}).get('name', '')

def setDocumentName(doc_id, name):
    if doc_id in _mock.documents:
        _mock.documents[doc_id]['name'] = name

def getExecutableFilePath(doc_id):
    return _mock.documents.get(doc_id, {}).get('executable_path', '')

def getDatabaseFilePath(doc_id):
    return _mock.documents.get(doc_id, {}).get('database_path', '')

def is64Bits(doc_id):
    return _mock.documents.get(doc_id, {}).get('is_64_bit', True)

def getEntryPoint(doc_id):
    return _mock.documents.get(doc_id, {}).get('entry_point', 0x1000)

def getCurrentAddress(doc_id):
    return _mock.current_address

def setCurrentAddress(doc_id, addr):
    _mock.current_address = addr

def backgroundProcessActive(doc_id):
    return _mock.documents.get(doc_id, {}).get('background_active', False)

def rebase(doc_id, new_base):
    # Mock rebase operation
    return True

def log(doc_id, message):
    print(f"LOG: {message}")

# Segment functions
def getSegmentCount(doc_id):
    return len(_mock.segments)

def getSegmentAddress(doc_id, index):
    segment_ids = list(_mock.segments.keys())
    if 0 <= index < len(segment_ids):
        return segment_ids[index]
    return 0

def getSegmentAddressByName(doc_id, name):
    for seg_id, seg_data in _mock.segments.items():
        if seg_data['name'] == name:
            return seg_id
    return 0xffffffffffffffff

def getSegmentIndexAtAddress(doc_id, addr):
    for i, (seg_id, seg_data) in enumerate(_mock.segments.items()):
        start = seg_data['start_address']
        end = start + seg_data['length']
        if start <= addr < end:
            return i
    return -1

def getSegmentName(seg_id):
    return _mock.segments.get(seg_id, {}).get('name', '')

def getSegmentStartingAddress(seg_id):
    return _mock.segments.get(seg_id, {}).get('start_address', 0)

def getSegmentLength(seg_id):
    return _mock.segments.get(seg_id, {}).get('length', 0)

def getFileOffset(seg_id):
    return _mock.segments.get(seg_id, {}).get('file_offset', 0)

# Section functions
def getSectionCount(seg_id):
    return len(_mock.segments.get(seg_id, {}).get('sections', []))

def getSectionAddress(seg_id, index):
    sections = _mock.segments.get(seg_id, {}).get('sections', [])
    if 0 <= index < len(sections):
        return index + 1000  # Mock section address
    return 0

def getSectionName(section_addr):
    # Enhanced section name lookup with realistic names
    section_names = {
        1000: '__text',
        1001: '__stubs',
        1002: '__objc_methlist',
        1003: '__const',
        1004: '__cstring',
        1005: '__objc_methname',
        1006: '__swift5_typeref',
        1007: '__unwind_info',
        1008: '__cfstring',
        1009: '__objc_classlist',
        1010: '__objc_imageinfo'
    }
    return section_names.get(section_addr, '')

def getSectionStartingAddress(section_addr):
    # Enhanced section start addresses based on realistic layout
    section_starts = {
        1000: 0x1000,  # __text
        1001: 0x1500,  # __stubs
        1002: 0x1700,  # __const
        1003: 0x1A00,  # __cstring
        1004: 0x1F00,  # __unwind_info
        1005: 0x3000,  # __cfstring
        1006: 0x3400,  # __objc_classlist
        1007: 0x3600,  # __objc_imageinfo
        1008: 0x4000,  # __data
        1009: 0x4500,  # __bss
        1010: 0x4A00   # __objc_data
    }
    return section_starts.get(section_addr, 0)

def getSectionLength(section_addr):
    return 0x1000  # Mock section length

def getSectionFlags(section_addr):
    return 0x80000400  # Mock section flags

# Data access functions
def readBytes(seg_id, addr, length):
    # Mock byte reading - return some test data
    return b'\x48\x89\xe5' + b'\x00' * (length - 3)

def writeBytes(seg_id, addr, data):
    return True

# Type functions
def getTypeAtAddress(seg_id, addr):
    return _mock.types.get(addr, 0)  # TYPE_UNDEFINED

def setTypeAtAddress(seg_id, addr, length, type_value):
    for i in range(length):
        _mock.types[addr + i] = type_value
    return True

def markAsCode(seg_id, addr):
    _mock.types[addr] = 65  # TYPE_CODE
    return True

def markAsProcedure(seg_id, addr):
    _mock.types[addr] = 66  # TYPE_PROCEDURE
    return True

def markAsUndefined(seg_id, addr):
    _mock.types[addr] = 0  # TYPE_UNDEFINED
    return True

def markRangeAsUndefined(seg_id, addr, length):
    for i in range(length):
        _mock.types[addr + i] = 0
    return True

def markAsDataByteArray(seg_id, addr, count):
    for i in range(count):
        _mock.types[addr + i] = 3  # TYPE_INT8
    return True

def markAsDataShortArray(seg_id, addr, count):
    for i in range(count * 2):
        _mock.types[addr + i] = 4  # TYPE_INT16
    return True

def markAsDataIntArray(seg_id, addr, count):
    for i in range(count * 4):
        _mock.types[addr + i] = 5  # TYPE_INT32
    return True

def disassembleWholeSegment(seg_id):
    return True

# Name functions
def setNameAtAddress(seg_id, addr, name):
    _mock.names[addr] = name
    return 1

def getNameAtAddress(seg_id, addr):
    return _mock.names.get(addr)

def getDemangledNameAtAddress(seg_id, addr):
    name = _mock.names.get(addr)
    if name and name.startswith('_Z'):
        return f"demangled_{name}"
    return name

def getAddressForName(doc_id, name):
    for addr, addr_name in _mock.names.items():
        if addr_name == name:
            return addr
    return 0xffffffffffffffff

# Comment functions
def getCommentAtAddress(seg_id, addr):
    return _mock.comments.get(addr)

def setCommentAtAddress(seg_id, addr, comment):
    _mock.comments[addr] = comment
    return True

def getInlineCommentAtAddress(seg_id, addr):
    return _mock.comments.get(addr)

def setInlineCommentAtAddress(seg_id, addr, comment):
    _mock.comments[addr] = comment
    return True

# Reference functions
def getReferencesOfAddress(seg_id, addr):
    return _mock.references.get(addr, [])

def getReferencesFromAddress(seg_id, addr):
    refs = []
    for target, sources in _mock.references.items():
        if addr in sources:
            refs.append(target)
    return refs

def addReference(seg_id, addr, referenced):
    if referenced not in _mock.references:
        _mock.references[referenced] = []
    _mock.references[referenced].append(addr)
    return True

def removeReference(seg_id, addr, referenced):
    if referenced in _mock.references and addr in _mock.references[referenced]:
        _mock.references[referenced].remove(addr)
    return True

# Instruction functions
def getInstructionAtAddress(seg_id, addr):
    return _mock.instructions.get(addr)

def nearestBlock(seg_id, addr):
    # Find the nearest instruction start
    for instr_addr in sorted(_mock.instructions.keys()):
        if instr_addr <= addr:
            return instr_addr
    return addr

def objectLength(seg_id, addr):
    instr = _mock.instructions.get(addr)
    if instr:
        return instr[6]  # instruction length
    return 1

# Procedure functions
def getProcedureCount(seg_id):
    return len(_mock.segments.get(seg_id, {}).get('procedures', []))

def getProcedureIndexAtAddress(seg_id, addr):
    procedures = _mock.segments.get(seg_id, {}).get('procedures', [])
    for i, proc_id in enumerate(procedures):
        proc_data = _mock.procedures.get(proc_id, {})
        if proc_data.get('entry_point') == addr:
            return i
    return -1

def getProcedureEntryPoint(seg_id, proc_index):
    procedures = _mock.segments.get(seg_id, {}).get('procedures', [])
    if 0 <= proc_index < len(procedures):
        proc_id = procedures[proc_index]
        return _mock.procedures.get(proc_id, {}).get('entry_point', 0)
    return 0

def getBasicBlockCount(seg_id, proc_index):
    procedures = _mock.segments.get(seg_id, {}).get('procedures', [])
    if 0 <= proc_index < len(procedures):
        proc_id = procedures[proc_index]
        return _mock.procedures.get(proc_id, {}).get('basic_blocks', 0)
    return 0

def getProcedureHeapSize(seg_id, proc_index):
    procedures = _mock.segments.get(seg_id, {}).get('procedures', [])
    if 0 <= proc_index < len(procedures):
        proc_id = procedures[proc_index]
        return _mock.procedures.get(proc_id, {}).get('heap_size', 0)
    return 0

def getAllCallers(seg_id, proc_index):
    from tests.hopper_api import CallReference
    procedures = _mock.segments.get(seg_id, {}).get('procedures', [])
    if 0 <= proc_index < len(procedures):
        proc_id = procedures[proc_index]
        callers = _mock.procedures.get(proc_id, {}).get('callers', [])
        return [CallReference(2, caller * 0x100, proc_id * 0x100) for caller in callers]
    return []

def getAllCallees(seg_id, proc_index):
    from tests.hopper_api import CallReference
    procedures = _mock.segments.get(seg_id, {}).get('procedures', [])
    if 0 <= proc_index < len(procedures):
        proc_id = procedures[proc_index]
        callees = _mock.procedures.get(proc_id, {}).get('callees', [])
        return [CallReference(2, proc_id * 0x100, callee * 0x100) for callee in callees]
    return []

def getLocalVariableList(seg_id, proc_index):
    from tests.hopper_api import LocalVariable
    procedures = _mock.segments.get(seg_id, {}).get('procedures', [])
    if 0 <= proc_index < len(procedures):
        proc_id = procedures[proc_index]
        local_vars = _mock.procedures.get(proc_id, {}).get('local_vars', [])
        return [LocalVariable(name, disp) for name, disp in local_vars]
    return []

def decompile(seg_id, proc_index):
    procedures = _mock.segments.get(seg_id, {}).get('procedures', [])
    if 0 <= proc_index < len(procedures):
        proc_id = procedures[proc_index]
        entry_point = _mock.procedures.get(proc_id, {}).get('entry_point', 0)
        
        # Return realistic decompiled code based on entry point
        if entry_point == 0x10411ead0:  # EntryPoint
            return "int EntryPoint() {\n    return sub_100004000();\n}"
        elif entry_point == 0x1040f4000:  # sub_100004000
            return """int sub_100004000() {
    // Signal app initialization
    objc_msgSendSuper2(...);
    NSLocalizedString(...);
    objc_msgSend(...);
    objc_retainAutoreleasedReturnValue(...);
    swift_bridgeObjectRelease(...);
    sub_1000041d0();
    return 0;
}"""
        elif entry_point == 0x1040f4124:  # viewDidLoad
            return """int -[_TtC6Signal29AccountSettingsViewController viewDidLoad]() {
    [r0 retain];
    sub_100004000();
    r0 = [r20 release];
    return r0;
}"""
        elif entry_point == 0x1040f414c:  # viewWillAppear
            return """int -[_TtC6Signal29AccountSettingsViewController viewWillAppear:](BOOL animated) {
    // Setup for view appearance
    return 0;
}"""
        elif entry_point == 0x1040f41d0:  # sub_1000041d0
            return """int sub_1000041d0() {
    // Complex Signal function with 29 basic blocks
    // Signal-specific logic here
    return 0;
}"""
    
    return "int unknown_function() {\n    return 0;\n}"

def procedureSignature(seg_id, proc_index):
    procedures = _mock.segments.get(seg_id, {}).get('procedures', [])
    if 0 <= proc_index < len(procedures):
        proc_id = procedures[proc_index]
        entry_point = _mock.procedures.get(proc_id, {}).get('entry_point', 0)
        
        # Return realistic signatures based on entry point
        if entry_point == 0x10411ead0:  # EntryPoint
            return "int EntryPoint()"
        elif entry_point == 0x1040f4000:  # sub_100004000
            return "int sub_100004000()"
        elif entry_point == 0x1040f4124:  # viewDidLoad
            return "int -[_TtC6Signal29AccountSettingsViewController viewDidLoad]()"
        elif entry_point == 0x1040f414c:  # viewWillAppear
            return "/* @class _TtC6Signal29AccountSettingsViewController */\n-(int)viewWillAppear:(int)arg2"
        elif entry_point == 0x1040f41d0:  # sub_1000041d0
            return "int sub_1000041d0()"
    
    return "int unknown_function(void)"

# String functions
def getStringCount(seg_id):
    return len(_mock.segments.get(seg_id, {}).get('strings', []))

def getStringAtIndex(seg_id, index):
    strings = _mock.segments.get(seg_id, {}).get('strings', [])
    if 0 <= index < len(strings):
        return strings[index][1]
    return ""

def getStringAddressAtIndex(seg_id, index):
    strings = _mock.segments.get(seg_id, {}).get('strings', [])
    if 0 <= index < len(strings):
        return strings[index][0]
    return 0

# Label functions
def getLabelCount(seg_id):
    return len(_mock.names)

def getLabelName(seg_id, index):
    names = list(_mock.names.values())
    if 0 <= index < len(names):
        return names[index]
    return ""

def getLabelsList(seg_id):
    return list(_mock.names.values())

def getNamedAddresses(seg_id):
    return list(_mock.names.keys())

# Output functions
def outputString(tag, message):
    # Avoid recursion by doing nothing - just a stub for testing
    pass

# Assembly functions
def assemble(doc_id, instruction, address, syntax):
    # Mock assembly - return some bytes
    return b'\x48\x89\xe5'

# Mock functions for missing operations
def getCurrentSegmentIndex(doc_id):
    return 0

def getSelectionAddressRange(doc_id):
    return [_mock.current_address, _mock.current_address + 10]

def moveCursorAtAddress(doc_id, addr):
    _mock.current_address = addr

def selectAddressRange(doc_id, start, end):
    pass

def getFileOffsetFromAddress(doc_id, addr):
    return addr - 0x1000  # Mock file offset

def getAddressFromFileOffset(doc_id, offset):
    return offset + 0x1000  # Mock address

def refreshView(doc_id):
    pass

def moveCursorOneLineDown(doc_id):
    return True

def moveCursorOneLineUp(doc_id):
    return True

def getRawSelectedLines(doc_id):
    return ["mov rax, rbx", "call sub_1100"]

def getHighlightedWord(doc_id):
    return "rax"

# Tag functions (simplified)
def addTagAtAddress(doc_id, tag_ptr, addr):
    pass

def removeTagAtAddress(doc_id, tag_ptr, addr):
    pass

def hasTagAtAddress(doc_id, tag_ptr, addr):
    return False

def getTagCountAtAddress(doc_id, addr):
    return 0

def getTagAtAddressByIndex(doc_id, addr, index):
    return 0

def getTagCount(doc_id):
    return 0

def getTagPtrAtIndex(doc_id, index):
    return 0

def buildTagPtrWithName(doc_id, name):
    return 1

def getTagPtrWithName(doc_id, name):
    return 0

def destroyTag(doc_id, tag_ptr):
    pass

def getTagName(tag_ptr):
    return "test_tag"

# Color functions (simplified)
def hasColorAtAddress(doc_id, addr):
    return False

def setColorAtAddress(doc_id, color, addr):
    return True

def colorAtAddress(doc_id, addr):
    return 0xFF000000

def removeColorAtAddress(doc_id, addr):
    pass

# Operand format functions (simplified)
def getOperandFormat(doc_id, addr, index):
    return 0

def getOperandFormatRelativeTo(doc_id, addr, index):
    return 0

def setOperandFormat(doc_id, addr, index, fmt):
    return True

def setOperandRelativeFormat(doc_id, addr, relto, index, fmt):
    return True

# Version functions
def getMajorVersion():
    return 5

def getMinorVersion():
    return 0

def getRevision():
    return 0

# Additional mock functions
def generateObjectiveCHeader(doc_id):
    return b"// Mock Objective-C header\n"

def produceNewExecutable(doc_id, remove_sig):
    return b"Mock executable data"

# Bookmark functions (simplified)
def setBookmark(doc_id, addr, name):
    return True

def removeBookmark(doc_id, addr):
    return True

def hasBookmark(doc_id, addr):
    return False

def renameBookmark(doc_id, addr, name):
    return True

def findBookmark(doc_id, name):
    return []

def bookmarkName(doc_id, addr):
    return ""

def bookmarks(doc_id):
    return []

# Additional segment functions
def newSegment(doc_id, start_addr, length):
    new_id = max(_mock.segments.keys()) + 1 if _mock.segments else 1
    _mock.segments[new_id] = {
        'name': f'SEG_{new_id}',
        'start_address': start_addr,
        'length': length,
        'file_offset': 0,
        'sections': [],
        'procedures': [],
        'strings': []
    }
    return True

def deleteSegment(doc_id, seg_index):
    segment_ids = list(_mock.segments.keys())
    if 0 <= seg_index < len(segment_ids):
        del _mock.segments[segment_ids[seg_index]]
        return True
    return False

def renameSegment(doc_id, seg_index, name):
    segment_ids = list(_mock.segments.keys())
    if 0 <= seg_index < len(segment_ids):
        _mock.segments[segment_ids[seg_index]]['name'] = name
        return True
    return False

# Background process functions
def requestBackgroundProcessStop(doc_id):
    if doc_id in _mock.documents:
        _mock.documents[doc_id]['background_active'] = False

def waitForBackgroundProcessToEnd(doc_id):
    pass

# Additional data functions
def partOfAnArray(seg_id, addr):
    return False

def arrayStartAddress(seg_id, addr):
    return -1

def arrayElementCount(seg_id, addr):
    return 0

def arrayElementAddress(seg_id, addr, index):
    return -1

def arrayElementSize(seg_id, addr):
    return 0

# ARM specific functions
def isThumbAtAddress(seg_id, addr):
    return False

def setThumbModeAtAddress(seg_id, addr):
    return True

def setARMModeAtAddress(seg_id, addr):
    return True

# Additional instruction functions
def getNextAddressWithType(seg_id, addr, type_value):
    for test_addr in range(addr, addr + 0x1000):
        if _mock.types.get(test_addr) == type_value:
            return test_addr
    return -1

def makeAlignment(seg_id, addr, size):
    return True

# Section lookup functions
def getSectionIndexAtAddress(seg_id, addr):
    sections = _mock.segments.get(seg_id, {}).get('sections', [])
    for i, section in enumerate(sections):
        start = section['start']
        end = start + section['length']
        if start <= addr < end:
            return i
    return -1

def getSectionAddressByName(doc_id, name):
    for seg_id, seg_data in _mock.segments.items():
        for i, section in enumerate(seg_data.get('sections', [])):
            if section['name'] == name:
                return i + 1000  # Mock section address
    return 0xffffffffffffffff

# Basic block functions
def getBasicBlockIndexAtAddress(seg_id, proc_index, addr):
    return 0

def getBasicBlockStartingAddress(seg_id, proc_index, bb_index):
    procedures = _mock.segments.get(seg_id, {}).get('procedures', [])
    if 0 <= proc_index < len(procedures):
        proc_id = procedures[proc_index]
        proc_data = _mock.procedures.get(proc_id, {})
        entry_point = proc_data.get('entry_point', 0x1040f0000)
        
        # Return realistic basic block addresses based on procedure - updated for Signal
        if entry_point == 0x10411ead0:  # EntryPoint
            bb_starts = [0x10411ead0]
            return bb_starts[bb_index] if bb_index < len(bb_starts) else entry_point + bb_index * 0x4
        elif entry_point == 0x1040f4000:  # sub_100004000
            bb_starts = [0x1040f4000]
            return bb_starts[bb_index] if bb_index < len(bb_starts) else entry_point + bb_index * 0x4
        elif entry_point == 0x1040f4124:  # viewDidLoad
            bb_starts = [0x1040f4124]
            return bb_starts[bb_index] if bb_index < len(bb_starts) else entry_point + bb_index * 0x4
        elif entry_point == 0x1040f414c:  # viewWillAppear
            bb_starts = [0x1040f414c]
            return bb_starts[bb_index] if bb_index < len(bb_starts) else entry_point + bb_index * 0x4
        elif entry_point == 0x1040f41d0:  # sub_1000041d0 (29 basic blocks)
            bb_starts = [0x1040f41d0 + i * 0x20 for i in range(29)]
            return bb_starts[bb_index] if bb_index < len(bb_starts) else entry_point + bb_index * 0x20
        
        return entry_point + bb_index * 0x4
    
    return 0x1040f0000 + bb_index * 0x4

def getBasicBlockEndingAddress(seg_id, proc_index, bb_index):
    start_addr = getBasicBlockStartingAddress(seg_id, proc_index, bb_index)
    procedures = _mock.segments.get(seg_id, {}).get('procedures', [])
    if 0 <= proc_index < len(procedures):
        proc_id = procedures[proc_index]
        proc_data = _mock.procedures.get(proc_id, {})
        entry_point = proc_data.get('entry_point', 0x1040f0000)
        
        # Return realistic basic block sizes - updated for Signal
        if entry_point == 0x10411ead0:  # EntryPoint
            bb_sizes = [0x4]
            size = bb_sizes[bb_index] if bb_index < len(bb_sizes) else 0x4
        elif entry_point == 0x1040f4000:  # sub_100004000
            bb_sizes = [0x120]  # Large initialization function
            size = bb_sizes[bb_index] if bb_index < len(bb_sizes) else 0x120
        elif entry_point == 0x1040f4124:  # viewDidLoad
            bb_sizes = [0x24]  # Size from actual disassembly
            size = bb_sizes[bb_index] if bb_index < len(bb_sizes) else 0x24
        elif entry_point == 0x1040f414c:  # viewWillAppear
            bb_sizes = [0x84]  # Standard method size
            size = bb_sizes[bb_index] if bb_index < len(bb_sizes) else 0x84
        elif entry_point == 0x1040f41d0:  # sub_1000041d0 (29 basic blocks)
            bb_sizes = [0x20] * 29  # 29 basic blocks of 0x20 each
            size = bb_sizes[bb_index] if bb_index < len(bb_sizes) else 0x20
        else:
            size = 0x10
        
        return start_addr + size
    
    return start_addr + 0x10

def getBasicBlockSuccessorCount(seg_id, proc_index, bb_index):
    return 1

def getBasicBlockSuccessorIndex(seg_id, proc_index, bb_index, succ_index):
    return bb_index + 1

def getBasicBlockSuccessorAddress(seg_id, proc_index, bb_index, succ_index):
    return 0x1000 + (bb_index + 1) * 0x10

# Tag functions for procedures and basic blocks
def addTagToProcedure(seg_id, proc_index, tag_ptr):
    pass

def removeTagFromProcedure(seg_id, proc_index, tag_ptr):
    pass

def procedureHasTag(seg_id, proc_index, tag_ptr):
    return False

def getProcedureTagCount(seg_id, proc_index):
    return 0

def getProcedureTagAtIndex(seg_id, proc_index, index):
    return 0

def addTagToBasicBlock(seg_id, proc_index, bb_index, tag_ptr):
    pass

def removeTagFromBasicBlock(seg_id, proc_index, bb_index, tag_ptr):
    pass

def basicBlockHasTag(seg_id, proc_index, bb_index, tag_ptr):
    return False

def getBasicBlockTagCount(seg_id, proc_index, bb_index):
    return 0

def getBasicBlockTagAtIndex(seg_id, proc_index, bb_index, index):
    return 0

# Local label functions
def hasLocalLabelAtAddress(seg_id, proc_index, addr):
    return False

def localLabelAtAddress(seg_id, proc_index, addr):
    return None

def setLocalLabelAtAddress(seg_id, proc_index, label, addr):
    return True

def declareLocalLabelAt(seg_id, proc_index, addr):
    return f"loc_{addr:x}"

def removeLocalLabelAtAddress(seg_id, proc_index, addr):
    return True

def addressOfLocalLabel(seg_id, proc_index, label):
    return 0

# Register functions
def renameRegister(seg_id, proc_index, reg_cls, reg_idx, name):
    return True

def registerNameOverride(seg_id, proc_index, reg_cls, reg_idx):
    return None

def clearRegisterNameOverride(seg_id, proc_index, reg_cls, reg_idx):
    return True

# Procedure caller/callee functions
def getAllCallerProcedures(seg_id, proc_index):
    return []

def getAllCalleeProcedures(seg_id, proc_index):
    return []

# Document loading/saving functions
def loadDocumentAt(doc_id, path):
    pass

def saveDocumentAt(doc_id, path):
    pass

def setExecutableFilePath(doc_id, path):
    if doc_id in _mock.documents:
        _mock.documents[doc_id]['executable_path'] = path

# User interaction functions (simplified)
def ask(message):
    return "test_input"

def askFile(message, path, save):
    return "/path/to/file"

def askDirectory(message, path):
    return "/path/to/directory"

def message(msg, buttons):
    return 0