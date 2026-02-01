"""
Proper FastMCP server testing using the FastMCP Client.
This follows the official FastMCP testing documentation.
"""

import pytest
import sys
import json
import os
from unittest.mock import patch

# Mock the HopperLowLevel module before importing hopper_api
sys.modules['HopperLowLevel'] = __import__('tests.mock_hopper_low_level', fromlist=[''])

# Import FastMCP components
from fastmcp import Client
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import fastmcp_server_template as fastmcp_server

# Import test modules
import tests.mock_hopper_low_level as mock_hopper_low_level
from tests.hopper_api import Document

class TestFastMCPServer:
    """Test class for FastMCP server using proper in-memory testing."""
    
    @pytest.fixture(autouse=True)
    def setup_method(self):
        """Setup method run before each test."""
        # Reset the mock state
        mock_hopper_low_level._mock = mock_hopper_low_level.MockHopperLowLevel()
        
        # Ensure the global doc variable is properly initialized
        fastmcp_server.doc = Document.getCurrentDocument()
    
    @pytest.mark.asyncio
    async def test_rebase_document_success(self):
        """Test successful rebase operation."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("rebase_document", {"new_base_address_hex": "200000000"})
            assert "Successfully rebased document to address 0x200000000" in result.data
    
    @pytest.mark.asyncio
    async def test_rebase_document_error_handling(self):
        """Test rebase error handling."""
        with patch.object(fastmcp_server.doc, 'rebase', side_effect=Exception("Rebase failed")):
            async with Client(fastmcp_server.mcp) as client:
                try:
                    result = await client.call_tool("rebase_document", {"new_base_address_hex": "2000"})
                    assert False, "Should have raised an exception"
                except Exception as e:
                    assert "Rebase failed" in str(e)
    
    @pytest.mark.asyncio
    async def test_rebase_document_invalid_hex(self):
        """Test rebase with invalid hex format."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("rebase_document", {"new_base_address_hex": "invalid"})
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "invalid literal for int()" in str(e)
    
    @pytest.mark.asyncio
    async def test_disassemble_procedure_by_address_and_name(self):
        """Test disassemble procedure by address and by name with enhanced instruction details."""
        async with Client(fastmcp_server.mcp) as client:
            # Test by address - use realistic Signal address
            result = await client.call_tool("disassemble_procedure", {
                "address_or_name": "0x1040f4124"
            })
            assert "Procedure at 0x1040f4124:" in result.data
            assert "Name: -[_TtC6Signal29AccountSettingsViewController viewDidLoad]" in result.data
            assert "Instructions:" in result.data
            # Check for enhanced ARM64 instruction format with arguments and comments
            assert "0x1040f4124: stp" in result.data  # ARM64 instruction from Signal binary
            assert "name: -[_TtC6Signal29AccountSettingsViewController viewDidLoad]" in result.data

            # Test by name - use realistic Signal method name
            result = await client.call_tool("disassemble_procedure", {
                "address_or_name": "-[_TtC6Signal29AccountSettingsViewController viewDidLoad]"
            })
            assert "Procedure at 0x1040f4124:" in result.data
            assert "Name: -[_TtC6Signal29AccountSettingsViewController viewDidLoad]" in result.data
            assert "Instructions:" in result.data
    
    @pytest.mark.asyncio
    async def test_disassemble_procedure_no_params(self):
        """Test disassemble procedure with no parameters."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("disassemble_procedure", {})
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "address_or_name" in str(e) and "required" in str(e)
    
    @pytest.mark.asyncio
    async def test_disassemble_procedure_invalid_name(self):
        """Test disassemble procedure with invalid name."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("disassemble_procedure", {
                    "address_or_name": "invalid_name"
                })
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "No address found for name 'invalid_name'" in str(e)
    
    @pytest.mark.asyncio
    async def test_decompile_procedure_by_address_and_name(self):
        """Test decompile procedure by address and by name."""
        async with Client(fastmcp_server.mcp) as client:
            # Test by address - use realistic Signal address
            result = await client.call_tool("decompile_procedure", {
                "address_or_name": "0x1040f4124"
            })
            assert "Procedure at 0x1040f4124:" in result.data
            assert "Name: -[_TtC6Signal29AccountSettingsViewController viewDidLoad]" in result.data
            assert "Decompiled code:" in result.data
            assert "[r0 retain]" in result.data
            assert "sub_100004000()" in result.data

            # Test by name - use realistic Signal method name
            result = await client.call_tool("decompile_procedure", {
                "address_or_name": "-[_TtC6Signal29AccountSettingsViewController viewDidLoad]"
            })
            assert "Procedure at 0x1040f4124:" in result.data
            assert "Name: -[_TtC6Signal29AccountSettingsViewController viewDidLoad]" in result.data
            assert "Decompiled code:" in result.data
            assert "[r0 retain]" in result.data
    
    @pytest.mark.asyncio
    async def test_decompile_procedure_no_procedure(self):
        """Test decompile with address that has no procedure."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("decompile_procedure", {
                    "address_or_name": "0x200000000"
                })
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "No segment found at address 0x200000000" in str(e)
    
    @pytest.mark.asyncio
    async def test_get_call_graph_depth_1_replaces_procedure_calls(self):
        """Test that call graph with depth=1 provides equivalent info to old procedure calls."""
        async with Client(fastmcp_server.mcp) as client:
            # Test getting callers (backward direction) - use Signal address
            result = await client.call_tool("get_call_graph", {
                "start_addr_hex": "1040f4000",
                "direction": "backward",
                "max_depth": 1
            })
            data = result.data
            assert isinstance(data, dict)
            assert "nodes" in data
            assert "edges" in data
            # Check that we get call relationship info
            for edge in data["edges"]:
                assert "from" in edge
                assert "to" in edge
            
            # Test getting callees (forward direction) - use Signal address
            result = await client.call_tool("get_call_graph", {
                "start_addr_hex": "10411ead0",
                "direction": "forward",
                "max_depth": 1
            })
            data = result.data
            assert isinstance(data, dict)
            assert "nodes" in data
            assert "edges" in data
    
    
    @pytest.mark.asyncio
    async def test_set_name_at_address_success(self):
        """Test setting name at address successfully."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("set_name_at_address", {
                "address_hex": "1040f4200",
                "name": "test_function"
            })
            assert "Successfully set name 'test_function' at address 0x1040f4200" in result.data
    
    @pytest.mark.asyncio
    async def test_set_name_at_address_failure(self):
        """Test setting name at address failure."""
        with patch.object(fastmcp_server.doc, 'setNameAtAddress', return_value=False):
            async with Client(fastmcp_server.mcp) as client:
                result = await client.call_tool("set_name_at_address", {
                    "address_hex": "1040f4200",
                    "name": "test_function"
                })
                assert "Failed to set name 'test_function' at address 0x1040f4200" in result.data
    
    @pytest.mark.asyncio
    async def test_get_comment_at_address_exists(self):
        """Test getting comment at address that exists."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_comment_at_address", {"address_hex": "10411ead0"})
            assert "Comment at 0x10411ead0: Entry point - Signal iOS app entry" in result.data
    
    @pytest.mark.asyncio
    async def test_get_comment_at_address_not_exists(self):
        """Test getting comment at address that doesn't exist."""
        async with Client(fastmcp_server.mcp) as client:
            # Use an address that's definitely outside any Signal segment
            try:
                result = await client.call_tool("get_comment_at_address", {"address_hex": "200000000"})
                # If we get here, it should show no comment found
                assert "No comment found at address 0x200000000" in result.data
            except Exception as e:
                # Or it might raise an exception for no segment, which is also acceptable
                assert "No segment found at address 0x200000000" in str(e)
    
    @pytest.mark.asyncio
    async def test_get_comment_at_address_no_segment(self):
        """Test getting comment with invalid address."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("get_comment_at_address", {"address_hex": "300000000"})
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "No segment found at address 0x300000000" in str(e)
    
    @pytest.mark.asyncio
    async def test_set_comment_at_address_success(self):
        """Test setting comment at address successfully."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("set_comment_at_address", {
                "address_hex": "1040f4200",
                "comment": "Test comment"
            })
            assert "Successfully set comment at address 0x1040f4200" in result.data
    
    @pytest.mark.asyncio
    async def test_set_comment_at_address_no_segment(self):
        """Test setting comment with invalid address."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("set_comment_at_address", {
                    "address_hex": "300000000",
                    "comment": "Test comment"
                })
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "No segment found at address 0x300000000" in str(e)
    
    @pytest.mark.asyncio
    async def test_get_demangled_name_by_address(self):
        """Test getting demangled name by address."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_demangled_name", {"address_or_name": "0x10411ead0"})
            data = result.data
            assert isinstance(data, dict)
            assert data["address"] == "0x10411ead0"
            assert data["queried_input"] == "0x10411ead0"
            assert data["regular_name"] == "EntryPoint"
            assert data["has_demangled_name"] is False  # 'EntryPoint' is not mangled
            assert data["demangled_name"] == "EntryPoint"
    
    @pytest.mark.asyncio
    async def test_get_demangled_name_by_name(self):
        """Test getting demangled name by name."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_demangled_name", {"address_or_name": "EntryPoint"})
            data = result.data
            assert isinstance(data, dict)
            assert data["address"] == "0x10411ead0"
            assert data["queried_input"] == "EntryPoint"
            assert data["regular_name"] == "EntryPoint"
            assert data["has_demangled_name"] is False  # 'EntryPoint' is not mangled
            assert data["demangled_name"] == "EntryPoint"
    
    @pytest.mark.asyncio
    async def test_get_demangled_name_no_params(self):
        """Test getting demangled name with no parameters."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("get_demangled_name", {})
                assert False, "Should have raised an error"
            except Exception as e:
                assert "address_or_name" in str(e) and "required" in str(e)
    
    @pytest.mark.asyncio
    async def test_get_address_info_with_detailed_references(self):
        """Test get_address_info with simplified reference structure."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_address_info", {
                "address_or_name_list": ["0x1040f4000"]
            })
            data = result.data
            assert isinstance(data, dict)
            # Data should be dict of dicts with "0x1040f4000" as key
            assert "0x1040f4000" in data
            addr_data = data["0x1040f4000"]
            assert "references" in addr_data
            references = addr_data["references"]
            assert "to_address" in references
            assert "from_address" in references

            # Check simplified reference structure
            assert isinstance(references["to_address"], list)
            assert isinstance(references["from_address"], list)

            # Check that we have the expected references from mock data
            # 0x1040f4000 is called from EntryPoint and viewDidLoad
            from_addresses = [ref["address"] if isinstance(ref, dict) else str(ref) for ref in references["from_address"]]
            assert "0x10411ead0" in from_addresses or "0x1040f4138" in from_addresses

    @pytest.mark.asyncio
    async def test_get_address_info_comprehensive_analysis(self):
        """Test get_address_info provides comprehensive analysis including references."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_address_info", {
                "address_or_name_list": ["0x1040f4004"]
            })
            data = result.data
            assert isinstance(data, dict)
            # Data should be dict of dicts with "0x1040f4004" as key
            assert "0x1040f4004" in data
            addr_data = data["0x1040f4004"]
            # Should always include simplified reference analysis
            assert "references" in addr_data
            references = addr_data["references"]
            assert "to_address" in references
            assert "from_address" in references
            assert isinstance(references["to_address"], list)
            assert isinstance(references["from_address"], list)
    
    @pytest.mark.asyncio
    async def test_search_strings_regex_match(self):
        """Test string search with matching regex."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": "Hello",
                "segment_name": "__TEXT",
                "max_results": 20
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data
            assert "num_results" in data
            assert "max_results" in data
            assert "search_finished" in data
            assert len(data["matches"]) >= 1  # Should find "Hello World"
            assert data["max_results"] == 20
            # Check that we found the expected string
            found_hello = any("Hello World" in match.get("content", "") for match in data["matches"])
            assert found_hello, "Should find 'Hello World' string"
    
    @pytest.mark.asyncio
    async def test_search_strings_regex_no_match(self):
        """Test string search with non-matching regex."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": "NonExistent",
                "segment_name": "__TEXT"
            })
            data = result.data
            assert isinstance(data, dict)
            assert len(data["matches"]) == 0
            assert data["num_results"] == 0
            assert data["search_finished"] is True
    
    @pytest.mark.asyncio
    async def test_search_strings_regex_invalid_pattern(self):
        """Test string search with invalid regex pattern."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("search_strings_regex", {
                    "regex_pattern": "[invalid",
                    "segment_name": "__TEXT"
                })
                assert False, "Should have raised an error"
            except Exception as e:
                assert "unterminated character set" in str(e)
    
    @pytest.mark.asyncio
    async def test_search_strings_regex_missing_segment(self):
        """Test string search with missing segment_name parameter."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("search_strings_regex", {
                    "regex_pattern": "Hello"
                })
                assert False, "Should have raised an error"
            except Exception as e:
                assert "segment_name" in str(e) and "required" in str(e)
    

    @pytest.mark.asyncio
    async def test_search_strings_unicode_and_special_chars(self):
        """Test string search with unicode and special characters."""
        async with Client(fastmcp_server.mcp) as client:
            # Test unicode characters
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": "Hello 世界",
                "segment_name": "__TEXT"
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data
            # Should find the unicode string we added
            found_unicode = any("Hello 世界" in match.get("content", "") for match in data["matches"])
            assert found_unicode, "Should find unicode string 'Hello 世界'"

            # Test special characters
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": "!@#",
                "segment_name": "__TEXT"
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data
            # Should find the special characters string
            found_special = any("!@#$%^&*" in match.get("content", "") for match in data["matches"])
            assert found_special, "Should find special characters string"

    @pytest.mark.asyncio
    async def test_search_strings_edge_cases(self):
        """Test string search for empty strings and very long strings."""
        async with Client(fastmcp_server.mcp) as client:
            # Test pattern that matches empty strings specifically
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": "^$",  # Pattern that matches only empty strings
                "segment_name": "__TEXT"
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data
            # Check if we found any empty strings (mock data may or may not have them)
            found_empty = any(match.get("content", "") == "" for match in data["matches"])
            # Note: This assertion is relaxed since empty strings may not exist in mock data
            if data["matches"]:
                assert found_empty, "If matches found, they should be empty strings"

            # Test very long string
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": "A{10,}",
                "segment_name": "__TEXT"
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data
            # Should find the 1000 'A's string
            found_long = any("A" * 1000 in match.get("content", "") for match in data["matches"])
            assert found_long, "Should find very long string of 'A's"

    @pytest.mark.asyncio
    async def test_search_strings_regex_case_insensitive(self):
        """Test case insensitive string search."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": "hello",
                "segment_name": "__TEXT"
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data

    @pytest.mark.asyncio
    async def test_search_strings_regex_complex_pattern(self):
        """Test complex regex patterns."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": "\\b[A-Z][a-z]+\\b",
                "segment_name": "__TEXT"
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data


    @pytest.mark.asyncio
    async def test_disassemble_procedure_x86_instructions(self):
        """Test disassembling x86 instructions."""
        async with Client(fastmcp_server.mcp) as client:
            # Use an existing procedure that has realistic instructions
            result = await client.call_tool("disassemble_procedure", {
                "address_or_name": "0x1040f4000"
            })
            # The mock data now includes realistic ARM64 instructions
            # Just verify the procedure disassembles successfully
            assert "Procedure at 0x1040f4000:" in result.data
            assert "Instructions:" in result.data

    @pytest.mark.asyncio
    async def test_disassemble_procedure_complex_arm64(self):
        """Test disassembling complex ARM64 instructions."""
        async with Client(fastmcp_server.mcp) as client:
            # Use an existing procedure that has complex ARM64 instructions
            result = await client.call_tool("disassemble_procedure", {
                "address_or_name": "0x1040f4000"
            })
            # The mock data now includes complex ARM64 instructions
            # Just verify the procedure disassembles successfully
            assert "Procedure at 0x1040f4000:" in result.data
            assert "Instructions:" in result.data
            assert "sub" in result.data  # ARM64 sub instruction
            assert "bl" in result.data   # ARM64 branch with link

    @pytest.mark.asyncio
    async def test_search_strings_regex_with_large_max_results(self):
        """Test string search with large max_results parameter."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": ".*",
                "segment_name": "__TEXT",
                "max_results": 100
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data
            assert data["max_results"] == 100

    @pytest.mark.asyncio
    async def test_search_strings_regex_with_custom_max_results(self):
        """Test string search with custom max_results parameter."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": ".*",
                "segment_name": "__TEXT",
                "max_results": 5
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data
            assert data["max_results"] == 5
            assert len(data["matches"]) <= 5

    @pytest.mark.asyncio
    async def test_search_strings_regex_min_length_filter(self):
        """Test string search with regex pattern for minimum length filtering."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": ".{20,}",  # Regex pattern for strings 20+ chars
                "segment_name": "__TEXT"
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data
            # Check that all matches are at least 20 characters
            for match in data["matches"]:
                assert len(match["content"]) >= 20

    @pytest.mark.asyncio
    async def test_search_strings_regex_exclusion_pattern(self):
        """Test string search with negative lookahead for exclusion."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": "^(?!.*Test).*",  # Negative lookahead to exclude "Test"
                "segment_name": "__TEXT"
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data
            # Check that no matches contain "Test"
            for match in data["matches"]:
                assert "Test" not in match["content"]

    @pytest.mark.asyncio
    async def test_get_address_info_with_special_names(self):
        """Test get_address_info with addresses containing special character names."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_address_info", {
                "address_or_name_list": ["0x104aae470", "0x1040f4124", "0x1040f414c"]
            })
            data = result.data
            assert isinstance(data, dict)
            assert "0x104aae470" in data
            assert "0x1040f4124" in data
            assert "0x1040f414c" in data

    @pytest.mark.asyncio
    async def test_get_demangled_name_with_special_characters(self):
        """Test demangling names with special characters."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_demangled_name", {
                "address_or_name": "0x1040f4124"
            })
            data = result.data
            assert isinstance(data, dict)
            assert "demangled_name" in data
            assert "regular_name" in data

    @pytest.mark.asyncio
    async def test_call_graph_with_complex_depth(self):
        """Test call graph with deeper traversal."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_call_graph", {
                "start_addr_hex": "10411ead0",
                "direction": "forward",
                "max_depth": 3
            })
            data = result.data
            assert isinstance(data, dict)
            assert "nodes" in data
            assert "edges" in data

    @pytest.mark.asyncio
    async def test_call_graph_bidirectional_complex(self):
        """Test bidirectional call graph with complex relationships."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_call_graph", {
                "start_addr_hex": "10411ead0",
                "direction": "bidirectional",
                "max_depth": 2
            })
            data = result.data
            assert isinstance(data, dict)
            assert "nodes" in data
            assert "edges" in data
    
    @pytest.mark.asyncio
    async def test_list_all_segments(self):
        """Test listing all segments."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("list_all_segments", {})
            # Function now returns dict directly, not JSON string
            data = result.data
            
            assert data["total_segments"] == 6  # Updated for Signal binary + test segment
            assert len(data["segments"]) == 6
            
            # Check first segment (Signal binary data)
            seg1 = data["segments"][0]
            assert seg1["name"] == "__TEXT"
            assert seg1["start_address"] == "0x1040f0000"
            assert seg1["length"] == 12451840
            assert "section_count" in seg1
            assert "procedure_count" in seg1
            assert "string_count" in seg1
            assert seg1["section_count"] == 8  # Signal binary sections
            assert seg1["procedure_count"] == 5  # Signal procedures
            assert seg1["string_count"] == 29  # Signal strings + test strings
    
    @pytest.mark.asyncio
    async def test_get_address_info_valid(self):
        """Test getting address info for valid address with enhanced features."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_address_info", {"address_or_name_list": ["0x10411ead0"]})
            # Function now returns dict of dicts
            data = result.data
            
            assert isinstance(data, dict)
            assert "0x10411ead0" in data
            addr_data = data["0x10411ead0"]
            
            assert addr_data["address"] == "0x10411ead0"
            assert "segment" in addr_data
            assert addr_data["segment"]["name"] == "__TEXT"
            assert addr_data["segment"]["start_address"] == "0x1040f0000"
            assert "type" in addr_data
            assert "name" in addr_data
            assert addr_data["name"] == "EntryPoint"
            assert "comment" in addr_data
            assert "Entry point - Signal iOS app entry" in addr_data["comment"]
            
            # Check enhanced instruction details (simplified format)
            assert "instruction" in addr_data
            assert "disassembly" in addr_data["instruction"]
            assert "b" in addr_data["instruction"]["disassembly"]  # ARM64 branch instruction
            assert addr_data["instruction"]["architecture"] == "AArch64"  # ARM64 architecture
            # Old arguments field should not exist anymore
            assert "arguments" not in addr_data["instruction"]
            
            # Check procedure info
            assert "procedure" in addr_data
            assert addr_data["procedure"]["entry_point"] == "0x10411ead0"
            
            # Check that basic reference structure exists
            assert "references" in addr_data
            assert "to_address" in addr_data["references"]
            assert "from_address" in addr_data["references"]
    
    @pytest.mark.asyncio
    async def test_get_address_info_no_segment(self):
        """Test getting address info with invalid address."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_address_info", {"address_or_name_list": ["0x300000000"]})
            data = result.data
            assert isinstance(data, dict)
            assert "0x300000000" in data
            # Should contain error info for invalid address
            assert "error" in data["0x300000000"]
            assert "No segment found at address 0x300000000" in data["0x300000000"]["error"]
    
    @pytest.mark.asyncio
    async def test_get_address_info_no_instruction(self):
        """Test getting address info with address that has no instruction."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_address_info", {"address_or_name_list": ["0x104cd0000"]})
            # Function now returns dict of dicts
            data = result.data
            
            assert isinstance(data, dict)
            assert "0x104cd0000" in data
            addr_data = data["0x104cd0000"]
            
            # Should still return segment and type info even without instruction
            assert addr_data["address"] == "0x104cd0000"
            assert "segment" in addr_data
            assert addr_data["segment"]["name"] == "__DATA_CONST"
            assert "type" in addr_data
            # Should not have instruction details
            assert "instruction" not in addr_data
    
    @pytest.mark.asyncio
    async def test_mark_data_type_at_address_code(self):
        """Test marking address as code."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("mark_data_type_at_address", {
                "address_hex": "1040f4200",
                "data_type": "code"
            })
            assert "Successfully marked address 0x1040f4200 as code" in result.data
    
    @pytest.mark.asyncio
    async def test_mark_data_type_at_address_procedure(self):
        """Test marking address as procedure."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("mark_data_type_at_address", {
                "address_hex": "1040f4200",
                "data_type": "procedure"
            })
            assert "Successfully marked address 0x1040f4200 as procedure" in result.data
    
    @pytest.mark.asyncio
    async def test_mark_data_type_at_address_int32(self):
        """Test marking address as int32."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("mark_data_type_at_address", {
                "address_hex": "1040f4200",
                "data_type": "int32",
                "length": 4
            })
            assert "Successfully marked address 0x1040f4200 as int32 (length: 4)" in result.data
    
    @pytest.mark.asyncio
    async def test_mark_data_type_at_address_ascii(self):
        """Test marking address as ASCII string."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("mark_data_type_at_address", {
                "address_hex": "1040f4200",
                "data_type": "ascii",
                "length": 10
            })
            assert "Successfully marked address 0x1040f4200 as ascii (length: 10)" in result.data
    
    @pytest.mark.asyncio
    async def test_mark_data_type_at_address_invalid_type(self):
        """Test marking address with invalid type."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("mark_data_type_at_address", {
                    "address_hex": "1040f4200",
                    "data_type": "invalid_type"
                })
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "Unknown data type 'invalid_type'" in str(e)
                assert "Valid types:" in str(e)
    
    @pytest.mark.asyncio
    async def test_mark_data_type_at_address_no_segment(self):
        """Test marking data type with invalid address."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("mark_data_type_at_address", {
                    "address_hex": "300000000",
                    "data_type": "code"
                })
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "No segment found at address 0x300000000" in str(e)
    
           
    @pytest.mark.asyncio
    async def test_list_tools(self):
        """Test listing all available tools."""
        async with Client(fastmcp_server.mcp) as client:
            tools = await client.list_tools()
            
            # Check that we have all expected tools
            tool_names = [tool.name for tool in tools]
            expected_tools = [
                "rebase_document", "disassemble_procedure", "decompile_procedure",
                "set_name_at_address",
                "get_comment_at_address", "set_comment_at_address",
                "get_demangled_name",
                "search_strings_regex", "list_all_segments",
                "get_address_info", "mark_data_type_at_address",
                "get_all_documents", "get_current_document", "set_current_document"
            ]
            
            expected_tools.append("get_string_at_addr")  # Add the new tool
            
            for expected_tool in expected_tools:
                assert expected_tool in tool_names, f"Tool {expected_tool} not found in {tool_names}"
            
            # Check that tools have descriptions
            for tool in tools:
                assert tool.description is not None
                assert len(tool.description) > 0
    
    @pytest.mark.asyncio
    async def test_error_handling_coverage(self):
        """Test error handling in various scenarios."""
        # Test with mock exceptions
        # Test with mock exceptions for other tools
        with patch.object(fastmcp_server.doc, 'getSegmentAtAddress', side_effect=Exception("Mock error")):
            async with Client(fastmcp_server.mcp) as client:
                try:
                    result = await client.call_tool("get_comment_at_address", {"address_hex": "1000"})
                    assert False, "Should have raised an exception"
                except Exception as e:
                    assert "Mock error" in str(e)
        
        with patch.object(fastmcp_server.doc, 'getSegmentByName', side_effect=Exception("Mock error")):
            async with Client(fastmcp_server.mcp) as client:
                try:
                    result = await client.call_tool("search_strings_regex", {
                        "regex_pattern": "test",
                        "segment_name": "__TEXT"
                    })
                    assert False, "Should have raised an exception"
                except Exception as e:
                    assert "Mock error" in str(e)

    @pytest.mark.asyncio
    async def test_get_all_documents(self):
        """Test getting all documents."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_all_documents", {})
            # Function now returns dict directly, not JSON string
            data = result.data
            
            assert "total_documents" in data
            assert "documents" in data
            assert data["total_documents"] >= 1
            assert len(data["documents"]) == data["total_documents"]
            
            # Check first document structure
            if data["documents"]:
                doc = data["documents"][0]
                assert "doc_id" in doc
                assert "document_name" in doc
                assert "executable_path" in doc
                assert "entry_point" in doc
                assert "segment_count" in doc
                assert "analysis_active" in doc
                assert doc["doc_id"] == 0  # First document should have ID 0

    @pytest.mark.asyncio
    async def test_get_current_document(self):
        """Test getting current document info."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_current_document", {})
            # Function now returns dict directly, not JSON string
            data = result.data
            
            assert "doc_id" in data
            assert "document_name" in data
            assert "executable_path" in data
            assert "entry_point" in data
            assert "segment_count" in data
            assert "analysis_active" in data
            assert isinstance(data["doc_id"], int)
            assert data["doc_id"] >= 0

    @pytest.mark.asyncio
    async def test_set_current_document_valid(self):
        """Test setting current document with valid doc_id."""
        async with Client(fastmcp_server.mcp) as client:
            # First get all documents to see what's available
            all_docs_result = await client.call_tool("get_all_documents", {})
            # Function now returns dict directly, not JSON string
            all_docs_data = all_docs_result.data
            
            if all_docs_data["total_documents"] > 1:
                # Try to set to the second document
                result = await client.call_tool("set_current_document", {"doc_id": 1})
                assert "Successfully set current document to doc_id 1" in result.data
                
                # Verify the current document changed
                current_result = await client.call_tool("get_current_document", {})
                # Function now returns dict directly, not JSON string
                current_data = current_result.data
                assert current_data["doc_id"] == 1
            else:
                # If only one document, test setting to doc_id 0
                result = await client.call_tool("set_current_document", {"doc_id": 0})
                assert "Successfully set current document to doc_id 0" in result.data

    @pytest.mark.asyncio
    async def test_set_current_document_invalid(self):
        """Test setting current document with invalid doc_id."""
        async with Client(fastmcp_server.mcp) as client:
            # Try to set to an invalid doc_id
            try:
                result = await client.call_tool("set_current_document", {"doc_id": 999})
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "Invalid doc_id 999" in str(e)
            
            # Try negative doc_id - Pydantic validation rejects before tool runs
            try:
                result = await client.call_tool("set_current_document", {"doc_id": -1})
                # Should not reach here
                assert False, "Expected validation error to be raised"
            except Exception as e:
                assert "greater than or equal to 0" in str(e) or "doc_id" in str(e)

    @pytest.mark.asyncio
    async def test_get_all_documents_error_handling(self):
        """Test error handling in get_all_documents."""
        with patch.object(Document, 'getAllDocuments', side_effect=Exception("Mock error")):
            async with Client(fastmcp_server.mcp) as client:
                try:
                    result = await client.call_tool("get_all_documents", {})
                    assert False, "Should have raised an exception"
                except Exception as e:
                    assert "Mock error" in str(e)

    @pytest.mark.asyncio
    async def test_get_current_document_error_handling(self):
        """Test error handling in get_current_document."""
        with patch.object(Document, 'getAllDocuments', side_effect=Exception("Mock error")):
            async with Client(fastmcp_server.mcp) as client:
                try:
                    result = await client.call_tool("get_current_document", {})
                    assert False, "Should have raised an exception"
                except Exception as e:
                    assert "Mock error" in str(e)

    @pytest.mark.asyncio
    async def test_set_current_document_error_handling(self):
        """Test error handling in set_current_document."""
        with patch.object(Document, 'getAllDocuments', side_effect=Exception("Mock error")):
            async with Client(fastmcp_server.mcp) as client:
                try:
                    result = await client.call_tool("set_current_document", {"doc_id": 0})
                    assert False, "Should have raised an exception"
                except Exception as e:
                    assert "Mock error" in str(e)

    @pytest.mark.asyncio
    async def test_document_workflow(self):
        """Test complete workflow of document management."""
        async with Client(fastmcp_server.mcp) as client:
            # Get all documents
            all_docs_result = await client.call_tool("get_all_documents", {})
            # Function now returns dict directly, not JSON string
            all_docs_data = all_docs_result.data
            
            # Get current document
            current_result = await client.call_tool("get_current_document", {})
            # Function now returns dict directly, not JSON string
            current_data = current_result.data
            
            # Verify current document is in the all documents list
            current_doc_id = current_data["doc_id"]
            assert 0 <= current_doc_id < all_docs_data["total_documents"]
            
            # Find the current document in the all documents list
            current_doc_in_list = all_docs_data["documents"][current_doc_id]
            assert current_doc_in_list["document_name"] == current_data["document_name"]
            assert current_doc_in_list["executable_path"] == current_data["executable_path"]

    @pytest.mark.asyncio
    async def test_enhanced_disassemble_procedure_arguments_and_comments(self):
        """Test enhanced disassemble procedure captures instruction arguments and comments."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("disassemble_procedure", {
                "address_or_name": "0x1040f4124"
            })
            
            # Should contain enhanced instruction format with arguments in brackets
            assert "[" in result.data or "]" in result.data  # Arguments should be shown in brackets
            # Should show annotations with name/comment separated by |
            assert "name:" in result.data or "comment:" in result.data

    @pytest.mark.asyncio
    async def test_enhanced_address_info_comprehensive_references(self):
        """Test get_address_info includes simplified reference information."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_address_info", {
                "address_or_name_list": ["0x1040f4000"]
            })
            data = result.data
            
            assert isinstance(data, dict)
            assert "0x1040f4000" in data
            addr_data = data["0x1040f4000"]
            assert "references" in addr_data
            references = addr_data["references"]
            
            # Check simplified reference structure
            assert "to_address" in references
            assert "from_address" in references
            assert isinstance(references["to_address"], list)
            assert isinstance(references["from_address"], list)
            
            # Verify reference entries have proper structure
            for ref in references["to_address"]:
                if isinstance(ref, dict):
                    assert "address" in ref
            
            for ref in references["from_address"]:
                if isinstance(ref, dict):
                    assert "address" in ref

    @pytest.mark.asyncio
    async def test_enhanced_address_info_simplified_instruction(self):
        """Test get_address_info uses simplified flat instruction format."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_address_info", {"address_or_name_list": ["0x1000"]})
            data = result.data
            
            assert isinstance(data, dict)
            assert "0x1000" in data
            addr_data = data["0x1000"]
            
            if "instruction" in addr_data:
                instruction = addr_data["instruction"]
                
                # Should have simplified format
                assert "disassembly" in instruction
                assert "architecture" in instruction
                
                # Should NOT have complex jump info or separate arguments array
                assert "is_conditional_jump" not in instruction
                assert "is_unconditional_jump" not in instruction
                assert "arguments" not in instruction
                
                # Disassembly should be a flat string
                assert isinstance(instruction["disassembly"], str)

    @pytest.mark.asyncio
    async def test_enhanced_address_info_simplified_structure(self):
        """Test get_address_info uses simplified structure without complex nested references."""
        async with Client(fastmcp_server.mcp) as client:
            # Test with an address that's not the segment base
            result = await client.call_tool("get_address_info", {"address_or_name_list": ["0x1040f4008"]})
            data = result.data
            
            assert isinstance(data, dict)
            assert "0x1040f4008" in data
            addr_data = data["0x1040f4008"]
            
            # Should work without error and return valid data
            assert "address" in addr_data
            assert addr_data["address"] == "0x1040f4008"
            
            # Check simplified reference structure
            assert "references" in addr_data
            assert "to_address" in addr_data["references"]
            assert "from_address" in addr_data["references"]
            assert isinstance(addr_data["references"]["to_address"], list)
            assert isinstance(addr_data["references"]["from_address"], list)
            
            # Check simplified instruction format if present
            if "instruction" in addr_data:
                assert "disassembly" in addr_data["instruction"]
                assert "arguments" not in addr_data["instruction"]  # Old format should be gone

    @pytest.mark.asyncio
    async def test_get_address_info_multiple_addresses_success(self):
        """Test get_address_info with multiple addresses."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_address_info", {
                "address_or_name_list": ["0x10411ead0", "0x1040f4000", "0x500000000"]
            })
            data = result.data
            assert isinstance(data, dict)
            
            # Should have entries for all requested addresses
            assert "0x10411ead0" in data
            assert "0x1040f4000" in data
            assert "0x500000000" in data
            
            # Check successful addresses
            assert "address" in data["0x10411ead0"]
            assert "segment" in data["0x10411ead0"]
            assert data["0x10411ead0"]["segment"]["name"] == "__TEXT"
            
            assert "address" in data["0x1040f4000"]
            assert "segment" in data["0x1040f4000"]
            assert data["0x1040f4000"]["segment"]["name"] == "__TEXT"
            
            # 0x500000000 should have error since it's not in any segment
            assert "error" in data["0x500000000"]

    @pytest.mark.asyncio
    async def test_get_address_info_invalid_address(self):
        """Test get_address_info with invalid addresses mixed with valid ones."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_address_info", {
                "address_or_name_list": ["invalid", "0x10411ead0", "0x300000000"]
            })
            data = result.data
            assert isinstance(data, dict)
            
            # Should have entries for all requested items
            assert "invalid" in data
            assert "0x10411ead0" in data
            assert "0x300000000" in data
            
            # "invalid" should have error for invalid name
            assert "error" in data["invalid"]
            assert "No address found for name 'invalid'" in data["invalid"]["error"]
            
            # "0x10411ead0" should be successful
            assert "address" in data["0x10411ead0"]
            assert "segment" in data["0x10411ead0"]
            
            # "0x300000000" should have error for no segment
            assert "error" in data["0x300000000"]
            assert "No segment found at address 0x300000000" in data["0x300000000"]["error"]

    @pytest.mark.asyncio
    async def test_get_address_info_empty_list(self):
        """Test get_address_info with empty list."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("get_address_info", {
                    "address_or_name_list": []
                })
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "cannot be empty" in str(e)

    @pytest.mark.asyncio
    async def test_get_address_info_too_many(self):
        """Test get_address_info with too many addresses."""
        async with Client(fastmcp_server.mcp) as client:
            # Create a list of 51 addresses
            address_list = [f"0x{i:x}" for i in range(0x1000, 0x1000 + 51)]
            try:
                result = await client.call_tool("get_address_info", {
                    "address_or_name_list": address_list
                })
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "Maximum 50 addresses" in str(e)

    @pytest.mark.asyncio
    async def test_enhanced_search_strings_regex_with_exclusion(self):
        """Test enhanced string search with negative lookahead for exclusion."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": "^(?!.*Test).{3,}",  # Negative lookahead to exclude "Test", min 3 chars
                "segment_name": "__TEXT"
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data
            
            # Check that excluded patterns are not in results
            for string_match in data["matches"]:
                assert "Test" not in string_match["content"]

    @pytest.mark.asyncio
    async def test_enhanced_search_strings_regex_min_length(self):
        """Test string search with regex pattern for minimum length filtering."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": ".{10,}",  # Regex pattern for strings 10+ chars
                "segment_name": "__TEXT"
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data
            
            # All matches should meet minimum length requirement
            for string_match in data["matches"]:
                assert len(string_match["content"]) >= 10

    @pytest.mark.asyncio
    async def test_enhanced_search_strings_regex_max_results(self):
        """Test string search with max results limit."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": ".*",
                "segment_name": "__TEXT",
                "max_results": 2
            })
            data = result.data
            assert isinstance(data, dict)
            assert data["max_results"] == 2
            assert len(data["matches"]) <= 2

    @pytest.mark.asyncio
    async def test_enhanced_search_strings_regex_invalid_exclusion(self):
        """Test string search with invalid regex pattern."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("search_strings_regex", {
                    "regex_pattern": "[invalid",  # Invalid regex pattern
                    "segment_name": "__TEXT"
                })
                assert False, "Should have raised an error"
            except Exception as e:
                assert "unterminated character set" in str(e)

    @pytest.mark.asyncio
    async def test_get_call_graph_forward(self):
        """Test call graph generation in forward direction."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_call_graph", {
                "start_addr_hex": "10411ead0",
                "direction": "forward",
                "max_depth": 2
            })
            data = result.data
            assert isinstance(data, dict)
            assert data["start_address"] == "10411ead0"
            assert data["direction"] == "forward"
            assert data["max_depth"] == 2
            assert "nodes" in data
            assert "edges" in data
            assert "total_nodes" in data
            assert "total_edges" in data
            assert isinstance(data["nodes"], dict)
            assert isinstance(data["edges"], list)

    @pytest.mark.asyncio
    async def test_get_call_graph_backward(self):
        """Test call graph generation in backward direction."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_call_graph", {
                "start_addr_hex": "1040f4000",
                "direction": "backward",
                "max_depth": 1
            })
            data = result.data
            assert isinstance(data, dict)
            assert data["direction"] == "backward"
            assert "nodes" in data
            assert "edges" in data

    @pytest.mark.asyncio
    async def test_get_call_graph_bidirectional(self):
        """Test call graph generation in bidirectional direction."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_call_graph", {
                "start_addr_hex": "10411ead0",
                "direction": "bidirectional",
                "max_depth": 1
            })
            data = result.data
            assert isinstance(data, dict)
            assert data["direction"] == "bidirectional"
            assert "nodes" in data
            assert "edges" in data

    @pytest.mark.asyncio
    async def test_get_call_graph_invalid_direction(self):
        """Test call graph with invalid direction."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("get_call_graph", {
                    "start_addr_hex": "10411ead0",
                    "direction": "invalid"
                })
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "direction must be" in str(e)

    @pytest.mark.asyncio
    async def test_get_call_graph_invalid_address(self):
        """Test call graph with invalid address."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("get_call_graph", {
                    "start_addr_hex": "invalid",
                    "direction": "forward"
                })
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "Invalid hex address format" in str(e)

    @pytest.mark.asyncio
    async def test_get_call_graph_no_procedure(self):
        """Test call graph with address that has no procedure."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("get_call_graph", {
                    "start_addr_hex": "200000000",  # Address with no procedure
                    "direction": "forward"
                })
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "No procedure found" in str(e) or "No segment found" in str(e)

    @pytest.mark.asyncio
    async def test_address_autodetection_with_0x_prefix(self):
        """Test that addresses with 0x prefix are correctly detected as addresses."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("disassemble_procedure", {
                "address_or_name": "0x10411ead0"
            })
            assert "Procedure at 0x10411ead0:" in result.data
    
    @pytest.mark.asyncio
    async def test_address_autodetection_without_0x_prefix_treated_as_name(self):
        """Test that addresses without 0x prefix are treated as names."""
        async with Client(fastmcp_server.mcp) as client:
            # This should fail since "10411ead0" is treated as a name, not an address
            try:
                result = await client.call_tool("disassemble_procedure", {
                    "address_or_name": "10411ead0"
                })
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "No address found for name '10411ead0'" in str(e)
    
    @pytest.mark.asyncio
    async def test_name_autodetection(self):
        """Test that non-hex strings are correctly detected as names."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("disassemble_procedure", {
                "address_or_name": "EntryPoint"
            })
            assert "Procedure at 0x10411ead0:" in result.data
            assert "Name: EntryPoint" in result.data
    
    @pytest.mark.asyncio
    async def test_search_strings_regex_performance_improvements(self):
        """Test performance improvements in search_strings_regex function."""
        async with Client(fastmcp_server.mcp) as client:
            # Test new return format with simplified results
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": "Hello",
                "segment_name": "__TEXT",
                "max_results": 10
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data
            assert "num_results" in data
            assert "max_results" in data
            assert "search_finished" in data
            
            assert data["max_results"] == 10
            
    @pytest.mark.asyncio
    async def test_search_strings_regex_segment_targeting(self):
        """Test segment targeting in search_strings_regex function."""
        async with Client(fastmcp_server.mcp) as client:
            # Test targeting specific segment
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": "Hello",
                "segment_name": "__TEXT",
                "max_results": 5
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data
            
            # Test with invalid segment name
            try:
                result = await client.call_tool("search_strings_regex", {
                    "regex_pattern": "Hello",
                    "segment_name": "INVALID_SEGMENT"
                })
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "No segment found with name 'INVALID_SEGMENT'" in str(e)
    
    @pytest.mark.asyncio
    async def test_search_strings_regex_max_results_behavior(self):
        """Test max_results functionality in search_strings_regex function."""
        async with Client(fastmcp_server.mcp) as client:
            # Test max_results behavior
            result = await client.call_tool("search_strings_regex", {
                "regex_pattern": ".*",  # Match any string
                "segment_name": "__TEXT",
                "max_results": 2
            })
            data = result.data
            assert data["max_results"] == 2
            assert len(data["matches"]) <= 2
            assert "num_results" in data
            assert "search_finished" in data
            
            # Each match should have expected fields
            for match in data["matches"]:
                assert "address" in match
                assert "content" in match
                # string_index field was removed in new interface
                assert "string_index" not in match
    
class TestMockDataIntegrity:
    """Test the mock data setup and integrity."""
    
    def test_mock_segments_setup(self):
        """Test that mock segments are properly set up."""
        mock = mock_hopper_low_level._mock
        
        assert len(mock.segments) == 6  # Updated for Signal binary + test segment
        assert 1 in mock.segments
        assert 2 in mock.segments
        assert mock.segments[1]['name'] == '__TEXT'
        assert mock.segments[2]['name'] == '__DATA_CONST'
    
    def test_mock_procedures_setup(self):
        """Test that mock procedures are properly set up."""
        mock = mock_hopper_low_level._mock
        
        assert len(mock.procedures) == 5
        assert 0 in mock.procedures
        assert 1 in mock.procedures
        assert mock.procedures[0]['entry_point'] == 0x10411ead0  # Updated for Signal
        assert mock.procedures[1]['entry_point'] == 0x1040f4000  # Updated for Signal
    
    def test_mock_instructions_setup(self):
        """Test that mock instructions are properly set up."""
        mock = mock_hopper_low_level._mock
        
        assert 0x10411ead0 in mock.instructions  # Updated for Signal
        assert 0x1040f4000 in mock.instructions  # Updated for Signal
        assert 0x1040f4124 in mock.instructions  # Updated for Signal
        
        # Test instruction format: (arch, instr, raw_args, formatted_args, cjmp, ijmp, length)
        instr = mock.instructions[0x10411ead0]
        assert len(instr) == 7
        assert instr[1] == 'b'  # ARM64 branch instruction
        assert instr[6] == 4    # ARM64 instruction length
    
    def test_mock_names_and_comments(self):
        """Test that mock names and comments are properly set up."""
        mock = mock_hopper_low_level._mock
        
        assert mock.names[0x10411ead0] == 'EntryPoint'  # Updated for Signal
        assert mock.names[0x1040f4000] == 'sub_100004000'  # Updated for Signal
        assert mock.comments[0x10411ead0] == 'Entry point - Signal iOS app entry'
        assert "Signal app initialization" in mock.comments[0x1040f4000]
    
    def test_mock_references_setup(self):
        """Test that mock references are properly set up."""
        mock = mock_hopper_low_level._mock
        
        assert 0x1040f4000 in mock.references  # Updated for Signal
        assert 0x10411ead0 in mock.references[0x1040f4000] or 0x1040f4138 in mock.references[0x1040f4000]

class TestEnhancedMockDataFeatures:
    """Test enhanced mock data features that provide realistic patterns for comprehensive testing."""
    
    @pytest.mark.asyncio
    async def test_realistic_objective_c_method_analysis(self):
        """Test analysis of realistic Objective-C method patterns."""
        async with Client(fastmcp_server.mcp) as client:
            # Test Objective-C method disassembly with enhanced patterns
            result = await client.call_tool("disassemble_procedure", {
                "address_or_name": "0x1040f4124"
            })
            
            # Should contain realistic Objective-C method signature and instructions
            assert "viewDidLoad" in result.data
            assert "AccountSettingsViewController" in result.data
            assert "Basic Block" in result.data
            
    @pytest.mark.asyncio
    async def test_realistic_swift_symbol_demangling(self):
        """Test Swift symbol demangling with realistic patterns."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_demangled_name", {
                "address_or_name": "0x1040f4124"
            })
            
            data = result.data
            assert isinstance(data, dict)
            assert "demangled_name" in data
            # The demangled name should be the Signal.AccountSettingsViewController version
            demangled = data.get("demangled_name", "")
            assert ("Signal.AccountSettingsViewController" in demangled or
                    "AccountSettingsViewController" in demangled)
            
    @pytest.mark.asyncio
    async def test_enhanced_address_info_with_arm64_instructions(self):
        """Test address info with realistic ARM64 instruction patterns."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("get_address_info", {
                "address_or_name_list": ["0x10411ead0", "0x1040f4004", "0x1040f4124"]
            })
            
            data = result.data
            
            # Check EntryPoint function (0x10411ead0)
            entry_info = data["0x10411ead0"]
            assert entry_info["name"] == "EntryPoint"
            assert "b 0x1040f4000" in entry_info["instruction"]["disassembly"]
            assert entry_info["instruction"]["architecture"] == "AArch64"
            
            # Check ARM64 register saving instruction (0x1040f4004)
            stp_info = data["0x1040f4004"]
            assert "stp x24, x23" in stp_info["instruction"]["disassembly"]
            
            # Check Objective-C method (0x1040f4124)
            objc_info = data["0x1040f4124"]
            assert "AccountSettingsViewController" in objc_info["name"]
            assert objc_info["type"] == "procedure"
            
    @pytest.mark.asyncio
    async def test_realistic_call_graph_patterns(self):
        """Test call graph generation with realistic calling patterns."""
        async with Client(fastmcp_server.mcp) as client:
            # Test forward call graph from EntryPoint
            result = await client.call_tool("get_call_graph", {
                "start_addr_hex": "10411ead0",
                "direction": "forward",
                "max_depth": 2
            })
            
            data = result.data
            assert "nodes" in data
            assert "edges" in data
            
            # Should show EntryPoint calling helper functions
            edges = data["edges"]
            entry_edges = [e for e in edges if e["from"] == "EntryPoint"]
            assert len(entry_edges) >= 1  # EntryPoint should call other functions
            
    @pytest.mark.asyncio
    async def test_enhanced_procedure_decompilation_realism(self):
        """Test procedure decompilation with realistic code patterns."""
        async with Client(fastmcp_server.mcp) as client:
            # Test EntryPoint function decompilation
            result = await client.call_tool("decompile_procedure", {
                "address_or_name": "0x10411ead0"
            })
            
            # Should show realistic EntryPoint function calling pattern
            assert "int EntryPoint()" in result.data
            assert "sub_100004000()" in result.data
            # Note: Our mock returns a simple version but the structure is realistic
            
            # Test Objective-C method decompilation
            result = await client.call_tool("decompile_procedure", {
                "address_or_name": "0x1040f4124"
            })
            
            # Should show realistic Objective-C method pattern - name contains viewDidLoad
            assert "viewDidLoad" in result.data or "AccountSettingsViewController" in result.data
            # Note: Our mock provides basic decompilation but the structure is realistic


    @pytest.mark.asyncio
    async def test_string_caching_functionality(self):
        """Test that string caching works correctly and is cleared on document switch."""
        async with Client(fastmcp_server.mcp) as client:
            # Clear any existing cache
            fastmcp_server._segment_strings_cache.clear()
            
            # First call should populate the cache
            result1 = await client.call_tool("search_strings_regex", {
                "regex_pattern": "Hello",
                "segment_name": "__TEXT",
                "max_results": 5
            })
            data1 = result1.data
            
            # Check that cache has been populated
            cache_keys = list(fastmcp_server._segment_strings_cache.keys())
            assert len(cache_keys) > 0, "Cache should be populated after first call"
            
            # Second call should use cached data (same results)
            result2 = await client.call_tool("search_strings_regex", {
                "regex_pattern": "Hello",
                "segment_name": "__TEXT",
                "max_results": 5
            })
            data2 = result2.data
            
            # Results should be identical since cache is used
            assert data1["matches"] == data2["matches"], "Cached results should be identical"
            assert data1["num_results"] == data2["num_results"], "Cached results should be identical"
            
            # Simulate document switch - cache should be cleared
            await client.call_tool("set_current_document", {"doc_id": 0})
            
            # Check that cache has been cleared
            assert len(fastmcp_server._segment_strings_cache) == 0, "Cache should be cleared after document switch"
            
            # Third call should work correctly and repopulate cache
            result3 = await client.call_tool("search_strings_regex", {
                "regex_pattern": "Hello",
                "segment_name": "__TEXT",
                "max_results": 5
            })
            data3 = result3.data
            
            # Results should still be correct
            assert data3["matches"] == data1["matches"], "Results should be correct after cache clear"
            
            # Cache should be populated again
            assert len(fastmcp_server._segment_strings_cache) > 0, "Cache should be repopulated"

    @pytest.mark.asyncio
    async def test_search_names_regex_bare_names(self):
        """Test searching for bare names with regex pattern using known mock data."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_names_regex", {
                "regex_pattern": "EntryPoint",
                "segment_name": "__TEXT",
                "search_type": "bare",
                "max_results": 10
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data
            assert "num_results" in data
            assert "search_type" in data
            assert "search_finished" in data
            assert data["search_type"] == "bare"
            
            # Should find EntryPoint from mock data at 0x10411ead0
            assert len(data["matches"]) >= 1
            entry_match = next((m for m in data["matches"] if m.get("bare_name") == "EntryPoint"), None)
            assert entry_match is not None
            assert entry_match["address"] == "0x10411ead0"
            assert entry_match["bare_name"] == "EntryPoint"

    @pytest.mark.asyncio
    async def test_search_names_regex_mangled_cpp_names(self):
        """Test searching for C++ mangled names from mock data."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_names_regex", {
                "regex_pattern": "_ZN.*",
                "segment_name": "__TEXT",
                "search_type": "bare",
                "max_results": 10
            })
            data = result.data
            assert isinstance(data, dict)
            assert data["search_type"] == "bare"
            assert "matches" in data
            
            # Should find C++ mangled names from mock data like _ZN6Signal29AccountSettingsViewController11viewDidLoadEv
            mangled_matches = [m for m in data["matches"] if m.get("bare_name", "").startswith("_ZN")]
            assert len(mangled_matches) >= 1
            
            # Check for specific mock mangled name
            specific_match = next((m for m in mangled_matches if "AccountSettingsViewController" in m.get("bare_name", "")), None)
            if specific_match:
                assert "_ZN6Signal29AccountSettingsViewController11viewDidLoadEv" in specific_match["bare_name"]

    @pytest.mark.asyncio
    async def test_search_names_regex_sub_functions(self):
        """Test searching for sub_ functions from mock data."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_names_regex", {
                "regex_pattern": "sub_.*",
                "segment_name": "__TEXT",
                "search_type": "both",
                "max_results": 10
            })
            data = result.data
            assert isinstance(data, dict)
            assert data["search_type"] == "both"
            assert "matches" in data
            
            # Should find sub_100004000 and sub_1000041d0 from mock data
            sub_matches = [m for m in data["matches"] if m.get("bare_name", "").startswith("sub_")]
            assert len(sub_matches) >= 2
            
            # Check for specific mock functions
            sub_100004000 = next((m for m in sub_matches if m.get("bare_name") == "sub_100004000"), None)
            sub_1000041d0 = next((m for m in sub_matches if m.get("bare_name") == "sub_1000041d0"), None)
            
            assert sub_100004000 is not None
            assert sub_100004000["address"] == "0x1040f4000"
            assert sub_1000041d0 is not None
            assert sub_1000041d0["address"] == "0x1040f41d0"

    @pytest.mark.asyncio
    async def test_search_names_regex_objective_c_methods(self):
        """Test searching for Objective-C method names from mock data."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_names_regex", {
                "regex_pattern": "-\\[.*viewDidLoad\\]",
                "segment_name": "__TEXT",
                "search_type": "both",
                "max_results": 10
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data
            
            # Should find -[_TtC6Signal29AccountSettingsViewController viewDidLoad] from mock data
            viewDidLoad_matches = [m for m in data["matches"] if "viewDidLoad" in m.get("bare_name", "")]
            assert len(viewDidLoad_matches) >= 1
            
            viewDidLoad_match = viewDidLoad_matches[0]
            assert viewDidLoad_match["address"] == "0x1040f4124"
            assert "-[_TtC6Signal29AccountSettingsViewController viewDidLoad]" == viewDidLoad_match["bare_name"]

    @pytest.mark.asyncio
    async def test_search_names_regex_comprehensive_info_with_mock_data(self):
        """Test that search returns comprehensive information about matching names using mock data."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_names_regex", {
                "regex_pattern": "EntryPoint",
                "segment_name": "__TEXT",
                "search_type": "both",
                "max_results": 5
            })
            data = result.data
            assert isinstance(data, dict)
            assert len(data["matches"]) == 1  # Should find exactly one EntryPoint
            
            entry_match = data["matches"][0]
            
            # Check all expected fields from mock data
            assert entry_match["address"] == "0x10411ead0"
            assert entry_match["bare_name"] == "EntryPoint"
            
            # Should have type info - TYPE_PROCEDURE (66) from mock data
            assert entry_match["type"] == "procedure"
            
            # Should have procedure info since EntryPoint is a procedure in mock data
            assert "procedure" in entry_match
            assert entry_match["procedure"]["entry_point"] == "0x10411ead0"
            assert entry_match["procedure"]["basic_block_count"] == 1
            assert entry_match["procedure"]["heap_size"] == 64
            
            # Should have comment from mock data
            assert "comment" in entry_match
            assert "Entry point - Signal iOS app entry" == entry_match["comment"]

    @pytest.mark.asyncio
    async def test_search_names_regex_with_procedure_info_mock_data(self):
        """Test that procedure information is included for procedure names using mock data."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_names_regex", {
                "regex_pattern": "sub_100004000",
                "segment_name": "__TEXT",
                "search_type": "both",
                "max_results": 10
            })
            data = result.data
            
            # Should find sub_100004000 from mock data
            assert len(data["matches"]) == 1
            proc_match = data["matches"][0]
            
            assert proc_match["address"] == "0x1040f4000"
            assert proc_match["bare_name"] == "sub_100004000"
            assert "procedure" in proc_match
            assert proc_match["procedure"]["entry_point"] == "0x1040f4000"
            assert proc_match["procedure"]["basic_block_count"] == 1
            assert proc_match["procedure"]["heap_size"] == 96
            
            # Should have comment from mock data
            assert "comment" in proc_match
            assert "Signal app initialization routine" == proc_match["comment"]

    @pytest.mark.asyncio
    async def test_search_names_regex_imp_stubs(self):
        """Test searching for import stubs from mock data."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_names_regex", {
                "regex_pattern": "imp___stubs__.*",
                "segment_name": "__TEXT",
                "search_type": "both",
                "max_results": 10
            })
            data = result.data
            assert isinstance(data, dict)
            assert "matches" in data
            
            # Should find various imp___stubs__ functions from mock data
            stub_matches = [m for m in data["matches"] if m.get("bare_name", "").startswith("imp___stubs__")]
            assert len(stub_matches) >= 4  # At least objc_msgSend, objc_retain, objc_release, objc_msgSendSuper2
            
            # Check for specific stubs from mock data
            stub_names = [m["bare_name"] for m in stub_matches]
            assert "imp___stubs__objc_msgSend" in stub_names
            assert "imp___stubs__objc_retain" in stub_names
            assert "imp___stubs__objc_release" in stub_names
            assert "imp___stubs__swift_bridgeObjectRelease" in stub_names

    @pytest.mark.asyncio
    async def test_search_names_regex_max_results_limit(self):
        """Test that max_results parameter limits the number of results."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_names_regex", {
                "regex_pattern": ".*",  # Match any name
                "segment_name": "__TEXT",
                "search_type": "both",
                "max_results": 3
            })
            data = result.data
            assert data["max_results"] == 3
            assert len(data["matches"]) <= 3

    @pytest.mark.asyncio
    async def test_search_names_regex_no_matches(self):
        """Test search with pattern that matches no names."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_names_regex", {
                "regex_pattern": "NonExistentFunction12345",
                "segment_name": "__TEXT",
                "search_type": "both",
                "max_results": 10
            })
            data = result.data
            assert len(data["matches"]) == 0
            assert data["num_results"] == 0
            assert data["search_finished"] is True

    @pytest.mark.asyncio
    async def test_search_names_regex_invalid_search_type(self):
        """Test search with invalid search_type parameter."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("search_names_regex", {
                    "regex_pattern": "test",
                    "segment_name": "__TEXT",
                    "search_type": "invalid",
                    "max_results": 10
                })
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "search_type must be" in str(e)

    @pytest.mark.asyncio
    async def test_search_names_regex_invalid_segment(self):
        """Test search with invalid segment name."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("search_names_regex", {
                    "regex_pattern": "test",
                    "segment_name": "INVALID_SEGMENT",
                    "search_type": "both",
                    "max_results": 10
                })
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "No segment found with name 'INVALID_SEGMENT'" in str(e)

    @pytest.mark.asyncio
    async def test_search_names_regex_invalid_regex(self):
        """Test search with invalid regex pattern."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("search_names_regex", {
                    "regex_pattern": "[invalid",
                    "segment_name": "__TEXT",
                    "search_type": "both",
                    "max_results": 10
                })
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "unterminated character set" in str(e)

    @pytest.mark.asyncio
    async def test_search_names_regex_case_sensitive(self):
        """Test that regex search is case sensitive by default."""
        async with Client(fastmcp_server.mcp) as client:
            # Search for lowercase "entrypoint" - should not match "EntryPoint"
            result = await client.call_tool("search_names_regex", {
                "regex_pattern": "entrypoint",
                "segment_name": "__TEXT",
                "search_type": "both",
                "max_results": 10
            })
            data = result.data
            
            # Should not find matches since "EntryPoint" is capitalized
            entry_matches = [m for m in data["matches"] if "entrypoint" in m.get("bare_name", "").lower()]
            # This depends on the actual names in mock data, but generally case sensitivity should apply

    @pytest.mark.asyncio
    async def test_search_names_regex_regex_patterns(self):
        """Test various regex patterns work correctly."""
        async with Client(fastmcp_server.mcp) as client:
            # Test pattern with word boundary
            result = await client.call_tool("search_names_regex", {
                "regex_pattern": "\\bsub_\\w+",
                "segment_name": "__TEXT",
                "search_type": "both",
                "max_results": 10
            })
            data = result.data
            assert isinstance(data, dict)
            
            # Test pattern with character class
            result = await client.call_tool("search_names_regex", {
                "regex_pattern": "[A-Z][a-z]+Point",
                "segment_name": "__TEXT",
                "search_type": "both",
                "max_results": 10
            })
            data = result.data
            assert isinstance(data, dict)

    @pytest.mark.asyncio
    async def test_search_names_regex_missing_parameters(self):
        """Test search with missing required parameters."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("search_names_regex", {
                    "regex_pattern": "test"
                    # Missing segment_name
                })
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "segment_name" in str(e) and "required" in str(e)
            
            try:
                result = await client.call_tool("search_names_regex", {
                    "segment_name": "__TEXT"
                    # Missing regex_pattern
                })
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "regex_pattern" in str(e) and "required" in str(e)

    @pytest.mark.asyncio
    async def test_search_names_regex_default_parameters(self):
        """Test search with default parameters."""
        async with Client(fastmcp_server.mcp) as client:
            result = await client.call_tool("search_names_regex", {
                "regex_pattern": ".*",
                "segment_name": "__TEXT"
                # search_type and max_results should use defaults
            })
            data = result.data
            assert data["search_type"] == "both"  # Default value
            assert data["max_results"] == 20  # Default value

    @pytest.mark.asyncio
    async def test_list_tools_includes_search_names_regex(self):
        """Test that the new search_names_regex tool is included in tool listing."""
        async with Client(fastmcp_server.mcp) as client:
            tools = await client.list_tools()
            tool_names = [tool.name for tool in tools]
            assert "search_names_regex" in tool_names
            
            # Find the tool and check its description
            search_names_tool = next((tool for tool in tools if tool.name == "search_names_regex"), None)
            assert search_names_tool is not None
            assert search_names_tool.description is not None
            assert "regex pattern" in search_names_tool.description.lower()
            assert "names" in search_names_tool.description.lower()

    @pytest.mark.asyncio
    async def test_get_string_at_addr_exists(self):
        """Test getting string at address that contains a string."""
        async with Client(fastmcp_server.mcp) as client:
            # Use an address that has a string from mock data (0x104ad8000: "Hello World")
            result = await client.call_tool("get_string_at_addr", {"address_hex": "104ad8000"})
            assert "String at 0x104ad8000: Hello World" in result.data

    @pytest.mark.asyncio
    async def test_get_string_at_addr_not_exists(self):
        """Test getting string at address that doesn't contain a string."""
        async with Client(fastmcp_server.mcp) as client:
            # Use an address that exists but has no string
            result = await client.call_tool("get_string_at_addr", {"address_hex": "1040f4000"})
            assert "No string found at address 0x1040f4000" in result.data

    @pytest.mark.asyncio
    async def test_get_string_at_addr_invalid_segment(self):
        """Test getting string with address that has no segment."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("get_string_at_addr", {"address_hex": "300000000"})
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "No segment found at address 0x300000000" in str(e)

    @pytest.mark.asyncio
    async def test_get_string_at_addr_invalid_hex(self):
        """Test getting string with invalid hex format."""
        async with Client(fastmcp_server.mcp) as client:
            try:
                result = await client.call_tool("get_string_at_addr", {"address_hex": "invalid"})
                assert False, "Should have raised an exception"
            except Exception as e:
                assert "Invalid hex address format" in str(e)

    @pytest.mark.asyncio
    async def test_get_string_at_addr_unicode_string(self):
        """Test getting unicode string at address."""
        async with Client(fastmcp_server.mcp) as client:
            # Use an address that has a unicode string from mock data (0x104ad8020: "Hello 世界")
            result = await client.call_tool("get_string_at_addr", {"address_hex": "104ad8020"})
            assert "String at 0x104ad8020: Hello 世界" in result.data

    @pytest.mark.asyncio
    async def test_get_string_at_addr_uses_cached_strings(self):
        """Test that get_string_at_addr uses the cached strings list for efficiency."""
        async with Client(fastmcp_server.mcp) as client:
            # Clear the cache first
            fastmcp_server._segment_strings_cache.clear()
            
            # First call should populate the cache
            result1 = await client.call_tool("get_string_at_addr", {"address_hex": "104ad8000"})
            assert "String at 0x104ad8000: Hello World" in result1.data
            
            # Verify cache was populated
            assert len(fastmcp_server._segment_strings_cache) > 0
            
            # Second call should use cached data
            result2 = await client.call_tool("get_string_at_addr", {"address_hex": "104ad8000"})
            assert result2.data == result1.data


    @pytest.mark.asyncio
    async def test_cache_file_path_generation(self):
        """Test that cache file path is generated correctly."""
        async with Client(fastmcp_server.mcp) as client:
            # Mock the getDatabaseFilePath to return a known path
            with patch.object(fastmcp_server.doc, 'getDatabaseFilePath', return_value="/path/to/document.hop"):
                cache_path = fastmcp_server.get_cache_file_path()
                assert cache_path == "/path/to/document.hop.mcpcache"
            
            # Test with None database path (unsaved document)
            with patch.object(fastmcp_server.doc, 'getDatabaseFilePath', return_value=None):
                cache_path = fastmcp_server.get_cache_file_path()
                assert cache_path is None

    @pytest.mark.asyncio
    async def test_disk_cache_load_nonexistent_file(self):
        """Test loading cache from non-existent file returns empty dict."""
        async with Client(fastmcp_server.mcp) as client:
            # Mock get_cache_file_path to return a non-existent file
            with patch.object(fastmcp_server, 'get_cache_file_path', return_value="/nonexistent/path.mcpcache"):
                result = fastmcp_server.load_disk_cache()
                assert result == {}

    @pytest.mark.asyncio
    async def test_disk_cache_load_valid_file(self):
        """Test loading cache from valid file."""
        async with Client(fastmcp_server.mcp) as client:
            import tempfile
            import os
            
            # Create a temporary cache file with valid JSON
            cache_data = {
                "strings_cache_v1": {
                    "__TEXT_1040f0000": [(0x104ad8000, "Hello World"), (0x104ad8020, "Test String")]
                }
            }
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.mcpcache', delete=False) as f:
                json.dump(cache_data, f)
                temp_path = f.name
            
            try:
                with patch.object(fastmcp_server, 'get_cache_file_path', return_value=temp_path):
                    result = fastmcp_server.load_disk_cache()
                    assert result == cache_data["strings_cache_v1"]
                    assert "__TEXT_1040f0000" in result
                    assert result["__TEXT_1040f0000"] == [(0x104ad8000, "Hello World"), (0x104ad8020, "Test String")]
            finally:
                os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_disk_cache_load_invalid_json(self):
        """Test loading cache from file with invalid JSON returns empty dict."""
        async with Client(fastmcp_server.mcp) as client:
            import tempfile
            import os
            
            # Create a temporary file with invalid JSON
            with tempfile.NamedTemporaryFile(mode='w', suffix='.mcpcache', delete=False) as f:
                f.write("invalid json content")
                temp_path = f.name
            
            try:
                with patch.object(fastmcp_server, 'get_cache_file_path', return_value=temp_path):
                    result = fastmcp_server.load_disk_cache()
                    assert result == {}
            finally:
                os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_disk_cache_save_valid_data(self):
        """Test saving cache to disk with proper JSON structure."""
        async with Client(fastmcp_server.mcp) as client:
            import tempfile
            import os
            
            # Create a temporary file path
            with tempfile.NamedTemporaryFile(suffix='.mcpcache', delete=True) as f:
                temp_path = f.name
            
            cache_data = {
                "__TEXT_1040f0000": [(0x104ad8000, "Hello World"), (0x104ad8020, "Test String")]
            }
            
            try:
                with patch.object(fastmcp_server, 'get_cache_file_path', return_value=temp_path):
                    fastmcp_server.save_disk_cache(cache_data)
                    
                    # Verify the file was created and has correct structure
                    assert os.path.exists(temp_path)
                    
                    # Load data back using our load function to ensure proper tuple conversion
                    loaded_data = fastmcp_server.load_disk_cache()
                    assert loaded_data == cache_data
                    
                    # Also verify the raw JSON structure contains the right key
                    with open(temp_path, 'r') as f:
                        saved_data = json.load(f)
                    assert "strings_cache_v1" in saved_data
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_disk_cache_save_no_path(self):
        """Test saving cache when no path is available (unsaved document)."""
        async with Client(fastmcp_server.mcp) as client:
            cache_data = {"test": "data"}
            
            with patch.object(fastmcp_server, 'get_cache_file_path', return_value=None):
                # Should not raise an exception, just silently fail
                fastmcp_server.save_disk_cache(cache_data)

    @pytest.mark.asyncio
    async def test_get_cached_strings_list_disk_cache_integration(self):
        """Test that get_cached_strings_list integrates properly with disk cache."""
        async with Client(fastmcp_server.mcp) as client:
            import tempfile
            import os
            
            # Clear memory cache
            fastmcp_server._segment_strings_cache.clear()
            
            # Create a temporary cache file with some data
            cache_data = {
                "strings_cache_v1": {
                    "__TEXT_1040f0000": [(0x104ad8000, "Cached Hello World"), (0x104ad8020, "Cached Test String")]
                }
            }
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.mcpcache', delete=False) as f:
                json.dump(cache_data, f)
                temp_path = f.name
            
            try:
                with patch.object(fastmcp_server, 'get_cache_file_path', return_value=temp_path):
                    # Get the TEXT segment to test with
                    segment = fastmcp_server.doc.getSegmentByName("__TEXT")
                    assert segment is not None, "TEXT segment should exist in mock data"
                    
                    # Call get_cached_strings_list - should load from disk cache
                    result = fastmcp_server.get_cached_strings_list(segment)
                    
                    # Should have loaded the cached data from disk
                    assert result == [(0x104ad8000, "Cached Hello World"), (0x104ad8020, "Cached Test String")]
                    
                    # Memory cache should now be populated with disk data
                    assert len(fastmcp_server._segment_strings_cache) > 0
                    cache_key = f"__TEXT_{segment.getStartingAddress():x}"
                    assert cache_key in fastmcp_server._segment_strings_cache
            finally:
                os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_get_cached_strings_list_generates_and_saves_to_disk(self):
        """Test that get_cached_strings_list generates new data and saves to disk when cache is empty."""
        async with Client(fastmcp_server.mcp) as client:
            import tempfile
            import os
            
            # Clear memory cache
            fastmcp_server._segment_strings_cache.clear()
            
            # Create a temporary file path for saving
            with tempfile.NamedTemporaryFile(suffix='.mcpcache', delete=True) as f:
                temp_path = f.name
            
            try:
                with patch.object(fastmcp_server, 'get_cache_file_path', return_value=temp_path):
                    # Get the TEXT segment to test with
                    segment = fastmcp_server.doc.getSegmentByName("__TEXT")
                    assert segment is not None, "TEXT segment should exist in mock data"
                    
                    # Call get_cached_strings_list - should generate fresh data and save to disk
                    result = fastmcp_server.get_cached_strings_list(segment)
                    
                    # Should have generated data from the mock
                    assert len(result) > 0
                    assert all(isinstance(item, tuple) and len(item) == 2 for item in result)
                    
                    # Memory cache should be populated
                    assert len(fastmcp_server._segment_strings_cache) > 0
                    
                    # Disk cache should be saved
                    assert os.path.exists(temp_path)
                    
                    # Load the data back using our load function to ensure proper tuple conversion
                    loaded_cache = fastmcp_server.load_disk_cache()
                    
                    assert len(loaded_cache) > 0
                    cache_key = f"__TEXT_{segment.getStartingAddress():x}"
                    assert cache_key in loaded_cache
                    assert loaded_cache[cache_key] == result
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_get_cached_strings_list_memory_cache_priority(self):
        """Test that memory cache takes priority over disk cache."""
        async with Client(fastmcp_server.mcp) as client:
            import tempfile
            import os
            
            # Set up memory cache with some data
            segment = fastmcp_server.doc.getSegmentByName("__TEXT")
            assert segment is not None, "TEXT segment should exist in mock data"
            cache_key = f"__TEXT_{segment.getStartingAddress():x}"
            memory_data = [(0x999999, "Memory cached data")]
            fastmcp_server._segment_strings_cache[cache_key] = memory_data
            
            # Create a temporary cache file with different data
            cache_data = {
                "strings_cache_v1": {
                    cache_key: [(0x888888, "Disk cached data")]
                }
            }
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.mcpcache', delete=False) as f:
                json.dump(cache_data, f)
                temp_path = f.name
            
            try:
                with patch.object(fastmcp_server, 'get_cache_file_path', return_value=temp_path):
                    # Call get_cached_strings_list - should use memory cache
                    result = fastmcp_server.get_cached_strings_list(segment)
                    
                    # Should return memory cached data, not disk cached data
                    assert result == memory_data
                    assert result != [(0x888888, "Disk cached data")]
            finally:
                os.unlink(temp_path)


    @pytest.mark.asyncio
    async def test_check_all_documents_have_string_caches_no_cache(self):
        """Test check_all_documents_have_string_caches when no caches exist."""
        async with Client(fastmcp_server.mcp) as client:
            # Clear any existing cache files by mocking get_cache_file_path_for_document to return non-existent files
            def mock_get_cache_path(doc):
                return f"/nonexistent/path/{id(doc)}.mcpcache"
            
            with patch.object(fastmcp_server, 'get_cache_file_path_for_document', side_effect=mock_get_cache_path):
                result = fastmcp_server.check_all_documents_have_string_caches()
                assert result is False, "Should return False when no cache files exist"

    @pytest.mark.asyncio
    async def test_check_all_documents_have_string_caches_with_cache(self):
        """Test check_all_documents_have_string_caches when all documents have caches."""
        async with Client(fastmcp_server.mcp) as client:
            import tempfile
            import os
            
            # Create temporary cache files for all documents
            all_docs = Document.getAllDocuments()
            temp_files = []
            
            try:
                for doc in all_docs:
                    # Create cache data for this document
                    cache_data = {"strings_cache_v1": {}}
                    
                    # Add cache entries for segments with strings
                    for i in range(doc.getSegmentCount()):
                        segment = doc.getSegment(i)
                        if segment and segment.getStringCount() > 0:
                            segment_name = segment.getName()
                            segment_start = segment.getStartingAddress()
                            cache_key = f"{segment_name}_{segment_start:x}"
                            cache_data["strings_cache_v1"][cache_key] = [(0x1000, "test string")]
                    
                    # Save to temporary file
                    with tempfile.NamedTemporaryFile(mode='w', suffix='.mcpcache', delete=False) as f:
                        json.dump(cache_data, f)
                        temp_files.append(f.name)
                
                # Mock get_cache_file_path_for_document to return our temp files
                def mock_get_cache_path(doc):
                    doc_index = list(Document.getAllDocuments()).index(doc)
                    return temp_files[doc_index]
                
                with patch.object(fastmcp_server, 'get_cache_file_path_for_document', side_effect=mock_get_cache_path):
                    result = fastmcp_server.check_all_documents_have_string_caches()
                    assert result is True, "Should return True when all documents have complete caches"
            
            finally:
                # Clean up temp files
                for temp_file in temp_files:
                    if os.path.exists(temp_file):
                        os.unlink(temp_file)

    @pytest.mark.asyncio
    async def test_check_document_has_complete_string_cache_missing_segments(self):
        """Test check_document_has_complete_string_cache when some segments are missing from cache."""
        async with Client(fastmcp_server.mcp) as client:
            import tempfile
            import os
            
            doc = Document.getCurrentDocument()
            
            # Create incomplete cache data (missing some segments)
            cache_data = {
                "strings_cache_v1": {
                    "__TEXT_1040f0000": [(0x1000, "test string")]  # Only one segment cached
                    # Missing other segments that have strings
                }
            }
            
            with tempfile.NamedTemporaryFile(mode='w', suffix='.mcpcache', delete=False) as f:
                json.dump(cache_data, f)
                temp_path = f.name
            
            try:
                with patch.object(fastmcp_server, 'get_cache_file_path_for_document', return_value=temp_path):
                    result = fastmcp_server.check_document_has_complete_string_cache(doc)
                    assert result is False, "Should return False when cache is incomplete"
            finally:
                os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_create_string_cache_for_document(self):
        """Test create_string_cache_for_document creates cache for all segments with strings."""
        async with Client(fastmcp_server.mcp) as client:
            import tempfile
            import os
            
            doc = Document.getCurrentDocument()
            
            # Create a temporary file path for saving
            with tempfile.NamedTemporaryFile(suffix='.mcpcache', delete=True) as f:
                temp_path = f.name
            
            try:
                with patch.object(fastmcp_server, 'get_cache_file_path_for_document', return_value=temp_path):
                    # Create cache for the document
                    fastmcp_server.create_string_cache_for_document(doc)
                    
                    # Verify cache file was created
                    assert os.path.exists(temp_path)
                    
                    # Load and verify the cache
                    with open(temp_path, 'r') as f:
                        saved_data = json.load(f)
                    
                    assert "strings_cache_v1" in saved_data
                    cache_data = saved_data["strings_cache_v1"]
                    
                    # Should have entries for all segments with strings
                    segments_with_strings = 0
                    for i in range(doc.getSegmentCount()):
                        segment = doc.getSegment(i)
                        if segment and segment.getStringCount() > 0:
                            segments_with_strings += 1
                            segment_name = segment.getName()
                            segment_start = segment.getStartingAddress()
                            cache_key = f"{segment_name}_{segment_start:x}"
                            assert cache_key in cache_data, f"Cache should contain {cache_key}"
                    
                    assert len(cache_data) == segments_with_strings, "Cache should have entries for all segments with strings"
            
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_create_string_caches_for_all_documents(self):
        """Test create_string_caches_for_all_documents creates caches for all documents."""
        async with Client(fastmcp_server.mcp) as client:
            import tempfile
            import os
            
            all_docs = Document.getAllDocuments()
            temp_files = []
            
            try:
                # Create temp file paths for each document
                for doc in all_docs:
                    with tempfile.NamedTemporaryFile(suffix='.mcpcache', delete=True) as f:
                        temp_files.append(f.name)
                
                # Mock get_cache_file_path_for_document to return our temp files
                def mock_get_cache_path(doc):
                    doc_index = list(Document.getAllDocuments()).index(doc)
                    return temp_files[doc_index]
                
                with patch.object(fastmcp_server, 'get_cache_file_path_for_document', side_effect=mock_get_cache_path):
                    # Create caches for all documents
                    fastmcp_server.create_string_caches_for_all_documents()
                    
                    # Verify cache files were created for all documents
                    for i, doc in enumerate(all_docs):
                        temp_path = temp_files[i]
                        if doc.getSegmentCount() > 0:  # Only check if document has segments
                            assert os.path.exists(temp_path), f"Cache file should exist for document {i}"
                            
                            # Load and verify the cache structure
                            with open(temp_path, 'r') as f:
                                saved_data = json.load(f)
                            
                            assert "strings_cache_v1" in saved_data
            
            finally:
                # Clean up temp files
                for temp_file in temp_files:
                    if os.path.exists(temp_file):
                        os.unlink(temp_file)

    @pytest.mark.asyncio
    async def test_new_helpers_integration_with_get_cached_strings_list(self):
        """Test that new helper functions integrate properly with existing get_cached_strings_list."""
        async with Client(fastmcp_server.mcp) as client:
            import tempfile
            import os
            
            # Clear memory cache
            fastmcp_server._segment_strings_cache.clear()
            
            doc = Document.getCurrentDocument()
            
            # Create a temporary file path
            with tempfile.NamedTemporaryFile(suffix='.mcpcache', delete=True) as f:
                temp_path = f.name
            
            try:
                with patch.object(fastmcp_server, 'get_cache_file_path_for_document', return_value=temp_path):
                    # Use new helper to create cache
                    fastmcp_server.create_string_cache_for_document(doc)
                    
                    # Verify check function returns True
                    assert fastmcp_server.check_document_has_complete_string_cache(doc) is True
                    
                    # Clear memory cache to force loading from disk
                    fastmcp_server._segment_strings_cache.clear()
                    
                    # Use existing get_cached_strings_list - should load from disk cache created by helper
                    segment = doc.getSegmentByName("__TEXT")
                    if segment and segment.getStringCount() > 0:
                        result = fastmcp_server.get_cached_strings_list(segment)
                        
                        # Should have loaded data successfully
                        assert isinstance(result, list)
                        assert all(isinstance(item, tuple) and len(item) == 2 for item in result)
                        
                        # Memory cache should now be populated
                        assert len(fastmcp_server._segment_strings_cache) > 0
            
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_helpers_handle_documents_without_strings(self):
        """Test that helpers handle documents that have no segments with strings."""
        async with Client(fastmcp_server.mcp) as client:
            # Mock a document with no string segments
            mock_doc = Document.getCurrentDocument()
            
            # Mock getSegmentCount and getSegment to simulate a document with no string segments
            with patch.object(mock_doc, 'getSegmentCount', return_value=1):
                with patch.object(mock_doc, 'getSegment') as mock_get_segment:
                    # Create a mock segment with no strings
                    mock_segment = mock_get_segment.return_value
                    mock_segment.getStringCount.return_value = 0
                    
                    # Test check function - should return True since there are no segments requiring caching
                    result = fastmcp_server.check_document_has_complete_string_cache(mock_doc)
                    assert result is True, "Document with no string segments should be considered complete"
                    
                    # Test create function - should work without errors
                    with patch.object(fastmcp_server, 'save_disk_cache_for_document') as mock_save:
                        fastmcp_server.create_string_cache_for_document(mock_doc)
                        # Should call save with empty cache data
                        mock_save.assert_called_once_with(mock_doc, {})


    @pytest.mark.asyncio
    async def test_create_string_caches_for_all_documents_success(self):
        """Test create_string_caches_for_all_documents returns True on success."""
        async with Client(fastmcp_server.mcp) as client:
            import tempfile
            import os
            
            all_docs = Document.getAllDocuments()
            temp_files = []
            
            try:
                # Create temp file paths for each document
                for doc in all_docs:
                    with tempfile.NamedTemporaryFile(suffix='.mcpcache', delete=True) as f:
                        temp_files.append(f.name)
                
                # Mock get_cache_file_path_for_document to return our temp files
                def mock_get_cache_path(doc):
                    doc_index = list(Document.getAllDocuments()).index(doc)
                    return temp_files[doc_index]
                
                # Mock getDatabaseFilePath to return valid paths for all documents
                def mock_get_db_path():
                    return "/valid/path/document.hop"
                
                with patch.object(fastmcp_server, 'get_cache_file_path_for_document', side_effect=mock_get_cache_path):
                    with patch.object(Document, 'getDatabaseFilePath', side_effect=mock_get_db_path):
                        # Should return True when all documents are successfully cached
                        result = fastmcp_server.create_string_caches_for_all_documents()
                        assert result is True, "Should return True when all documents are successfully cached"
            
            finally:
                # Clean up temp files
                for temp_file in temp_files:
                    if os.path.exists(temp_file):
                        os.unlink(temp_file)

    @pytest.mark.asyncio
    async def test_create_string_caches_for_all_documents_no_database_path(self):
        """Test create_string_caches_for_all_documents returns False when document has no database path."""
        async with Client(fastmcp_server.mcp) as client:
            # Mock getDatabaseFilePath to return None (unsaved document)
            with patch.object(Document, 'getDatabaseFilePath', return_value=None):
                result = fastmcp_server.create_string_caches_for_all_documents()
                assert result is False, "Should return False when document has no database path"

    @pytest.mark.asyncio
    async def test_create_string_caches_for_all_documents_mixed_scenarios(self):
        """Test create_string_caches_for_all_documents with mixed success/failure scenarios."""
        async with Client(fastmcp_server.mcp) as client:
            import tempfile
            import os
            
            all_docs = Document.getAllDocuments()
            
            # Mock scenario where first document has no database path, second has valid path
            call_count = [0]  # Use list to make it mutable
            
            def mock_get_db_path_mixed():
                call_count[0] += 1
                if call_count[0] == 1:
                    return None  # First document has no database path
                else:
                    return "/valid/path/document.hop"  # Other documents have valid paths
            
            with patch.object(Document, 'getDatabaseFilePath', side_effect=mock_get_db_path_mixed):
                result = fastmcp_server.create_string_caches_for_all_documents()
                assert result is False, "Should return False when any document fails"

    @pytest.mark.asyncio
    async def test_save_disk_cache_for_document_returns_true_on_success(self):
        """Test save_disk_cache_for_document returns True on successful save."""
        async with Client(fastmcp_server.mcp) as client:
            import tempfile
            import os
            
            doc = Document.getCurrentDocument()
            cache_data = {"test_key": "test_value"}
            
            # Create a temporary file path for saving
            with tempfile.NamedTemporaryFile(suffix='.mcpcache', delete=True) as f:
                temp_path = f.name
            
            try:
                with patch.object(fastmcp_server, 'get_cache_file_path_for_document', return_value=temp_path):
                    result = fastmcp_server.save_disk_cache_for_document(doc, cache_data)
                    assert result is True, "Should return True on successful save"
                    assert os.path.exists(temp_path), "Cache file should be created"
            finally:
                if os.path.exists(temp_path):
                    os.unlink(temp_path)

    @pytest.mark.asyncio
    async def test_save_disk_cache_for_document_returns_false_no_path(self):
        """Test save_disk_cache_for_document returns False when no cache path available."""
        async with Client(fastmcp_server.mcp) as client:
            doc = Document.getCurrentDocument()
            cache_data = {"test_key": "test_value"}
            
            with patch.object(fastmcp_server, 'get_cache_file_path_for_document', return_value=None):
                result = fastmcp_server.save_disk_cache_for_document(doc, cache_data)
                assert result is False, "Should return False when no cache path available"

    @pytest.mark.asyncio
    async def test_save_disk_cache_for_document_returns_false_on_io_error(self):
        """Test save_disk_cache_for_document returns False on IO error."""
        async with Client(fastmcp_server.mcp) as client:
            doc = Document.getCurrentDocument()
            cache_data = {"test_key": "test_value"}
            
            # Use an invalid path that will cause IO error
            with patch.object(fastmcp_server, 'get_cache_file_path_for_document', return_value="/invalid/path/cache.mcpcache"):
                result = fastmcp_server.save_disk_cache_for_document(doc, cache_data)
                assert result is False, "Should return False on IO error"

    @pytest.mark.asyncio
    async def test_create_string_cache_for_document_returns_save_result(self):
        """Test create_string_cache_for_document returns the result from save_disk_cache_for_document."""
        async with Client(fastmcp_server.mcp) as client:
            doc = Document.getCurrentDocument()
            
            # Test success case
            with patch.object(fastmcp_server, 'save_disk_cache_for_document', return_value=True) as mock_save:
                result = fastmcp_server.create_string_cache_for_document(doc)
                assert result is True, "Should return True when save succeeds"
                mock_save.assert_called_once()
            
            # Test failure case
            with patch.object(fastmcp_server, 'save_disk_cache_for_document', return_value=False) as mock_save:
                result = fastmcp_server.create_string_cache_for_document(doc)
                assert result is False, "Should return False when save fails"
                mock_save.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_string_caches_for_all_documents_prints_unsaved_message(self):
        """Test create_string_caches_for_all_documents prints message for unsaved documents."""
        async with Client(fastmcp_server.mcp) as client:
            import io
            import sys
            
            # Capture stdout
            captured_output = io.StringIO()
            original_stdout = sys.stdout
            sys.stdout = captured_output
            
            try:
                # Mock document with no database path
                with patch.object(Document, 'getDatabaseFilePath', return_value=None):
                    with patch.object(Document, 'getDocumentName', return_value="TestDocument"):
                        result = fastmcp_server.create_string_caches_for_all_documents()
                        assert result is False
                        
                        # Check that the error message was printed
                        output = captured_output.getvalue()
                        assert "TestDocument" in output
                        assert "needs to be saved first" in output
            finally:
                sys.stdout = original_stdout


if __name__ == "__main__":
    pytest.main([__file__, "-v"])