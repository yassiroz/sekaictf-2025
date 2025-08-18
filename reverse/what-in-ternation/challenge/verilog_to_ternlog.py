from dataclasses import dataclass
from typing import Dict, Tuple
import networkx as nx
import json
import sys
import sys

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)

BITS_PER_REG = 512 // 8
INPUT_NODE = "input"
OUTPUT_NODE = "output"

def cell_type_to_ternlog(cell_type: str) -> Tuple[int, int]:
    A = 0xf0
    B = 0xcc
    C = 0xaa

    if cell_type == "$_AND_":
        return A & B & C, 2 # false dependency on C to avoid clang/gcc turning it back into an and instruction
        # return A & B, 2
    elif cell_type == "$_NAND_":
        return ~(A & B) & 0xff, 2
    elif cell_type == "$_OR_":
        return A | B | C, 2 # false dependency on C to avoid clang/gcc turning it back into an or instruction
        # return A | B, 2
    elif cell_type == "$_NOR_":
        return ~(A | B) & 0xff, 2
    elif cell_type == "$_XOR_":
        return A ^ B, 2
    elif cell_type == "$_XNOR_":
        return ~(A ^ B) & 0xff, 2
    elif cell_type == "$_ANDNOT_":
        return (A & ~B) & 0xff, 2
    elif cell_type == "$_ORNOT_":
        return (A | ~B) & 0xff, 2
    elif cell_type == "$_AOI3_":
        return ~((A & B) | C) & 0xff, 3
    elif cell_type == "$_OAI3_":
        return ~((A | B) & C) & 0xff, 3
    else:
        raise ValueError(f"Unknown cell type: {cell_type}")

"""
Operand information.
"""
@dataclass
class CellOperands:
    A: int
    B: int
    C: int | None
    Y: int

    def __getitem__(self, item: int) -> int:
        if item == 0:
            return self.A
        elif item == 1:
            return self.B
        elif item == 2:
            return getattr(self, "C")
        elif item == 3:
            return self.Y
        else:
            raise IndexError("CellOperands only supports indexing with 0-3.")

"""
The location of a single "wire". This is the name of a register, and the bit index within that register.
"""
@dataclass(frozen=True)
class WirePos:
    wire_id: int
    reg: str
    bit: int

"""
Metadata for a single parallelized cell. This includes the type, the vpternlogd value, and a list of cell operands.
"""
@dataclass
class CellMetadata:
    cell_type: str
    vpternlogd: int
    arity: int
    operands: list[CellOperands]

@dataclass
class CellIOLayout:
    input_registers: list[str]
    output_bit_mapping: dict[int, int] # wire id to bit index mapping

@dataclass(frozen=True)
class BitMapping:
    from_pos: WirePos
    to_index: int

class Assembler:
    def __init__(self):
        self.G = nx.MultiDiGraph()

        self._add_node_unique(INPUT_NODE, type="input_symbolic")
        self._add_node_unique(OUTPUT_NODE, type="output_symbolic")

    def _add_node_unique(self, name, **kwargs):
        if name in self.G:
            raise ValueError(f"Node {name} already exists in the graph.")
        self.G.add_node(name, **kwargs)

    # Create initial set of base nodes using the module's ports and cells.
    def process_initial(self, module):
        # inputs and outputs
        for port_name, port in module["ports"].items():
            for bit in port["bits"]:
                if port["direction"] == "input":
                    self._add_node_unique(bit, type="input")
                    self.G.add_edge(INPUT_NODE, bit)
                elif port["direction"] == "output":
                    self._add_node_unique(bit, type="output")
                    self.G.add_edge(bit, OUTPUT_NODE)
                else:
                    raise ValueError(f"Unknown port direction: {port['direction']}")
            
        # cells
        for cell_name, cell in module["cells"].items():
            if cell["type"] == "$_NOT_":
                # convert not to nand with B connection equal to A connection
                cell["type"] = "$_NAND_"
                cell["connections"]["B"] = cell["connections"]["A"]

            ternlog_imm, arity = cell_type_to_ternlog(cell["type"])
            metadata = CellMetadata(
                cell_type=cell["type"],
                vpternlogd=ternlog_imm,
                arity=arity,
                operands=[]
            )
            self._add_node_unique(cell_name, type="cell", metadata=metadata)

            oplen = len(cell["connections"]["A"])
            for A, B, C, Y in zip(
                cell["connections"]["A"],
                cell["connections"]["B"],
                cell["connections"].get("C", [None] * oplen),
                cell["connections"]["Y"]
            ):
                metadata.operands.append(CellOperands(
                    A=A,
                    B=B,
                    C=C,
                    Y=Y
                ))

                self.G.add_edge(A, cell_name)
                if B is not None: 
                    self.G.add_edge(B, cell_name)
                if C is not None:
                    self.G.add_edge(C, cell_name)
                self.G.add_edge(cell_name, Y)

    # remove all intermediate nodes that are not inputs, outputs, or cells; these
    # are wires that we can just directly connect the inputs to the outputs
    def collapse_wires(self):
        for node in list(self.G.nodes):
            if self.G.nodes[node].get("type") is None:
                incoming = list(self.G.predecessors(node))
                outgoing = list(self.G.successors(node))
                for u in incoming:
                    for v in outgoing:
                        self.G.add_edge(u, v)
                self.G.remove_node(node)

    # Merge together the cells with the given names. The total operand count must not
    # exceed BITS_PER_REG. It is assumed that the cells all have the same type and
    # vpternlogd value.
    def merge_cells(self, cell_names):
        if len(cell_names) == 0:
            return
        
        # merge cell_names[1:] into cell_names[0], adding the operands to the first cell
        # and updating all edges (both incoming and outgoing) to point to the first cell
        # finally, remove the other cells
        first_cell = cell_names[0]
        first_metadata: CellMetadata = self.G.nodes[first_cell]["metadata"]
        first_operands = first_metadata.operands

        for cell_name in cell_names[1:]:
            metadata: CellMetadata = self.G.nodes[cell_name]["metadata"]
            if metadata.cell_type != first_metadata.cell_type or metadata.vpternlogd != first_metadata.vpternlogd:
                raise ValueError("Cannot merge cells with different types or vpternlogd values.")

            # check operand count
            if len(first_operands) + len(metadata.operands) > BITS_PER_REG:
                raise ValueError("Cannot merge cells: operand count exceeds BITS_PER_REG.")

            # add operands to the first cell
            first_operands.extend(metadata.operands)

            # update edges
            for u in list(self.G.predecessors(cell_name)):
                self.G.add_edge(u, first_cell)
            for v in list(self.G.successors(cell_name)):
                self.G.add_edge(first_cell, v)

            # remove the cell
            self.G.remove_node(cell_name)

    # Traverse the graph in topological generations and attempt to find cells that are
    # mergeable. Returns True if any cells were merged, False otherwise.
    def collapse_iteration(self):
        merged = False
        for generation in nx.topological_generations(self.G):
            cell_names_by_vpternlogd = {}

            for node in generation:
                if self.G.nodes[node].get("type") != "cell":
                    continue
                metadata: CellMetadata = self.G.nodes[node]["metadata"]
                key = metadata.vpternlogd
                if key not in cell_names_by_vpternlogd:
                    cell_names_by_vpternlogd[key] = []
                cell_names_by_vpternlogd[key].append(node)

            for cell_names in cell_names_by_vpternlogd.values():
                if len(cell_names) == 1:
                    continue # no need to merge single cells

                # convert the list of cell names into sub-arrays whose total operand count does not exceed BITS_PER_REG
                merged_cells = []
                current_cells = []
                current_operand_count = 0
                for cell_name in cell_names:
                    metadata: CellMetadata = self.G.nodes[cell_name]["metadata"]
                    operand_count = len(metadata.operands)
                    if current_operand_count + operand_count > BITS_PER_REG:
                        if current_cells:
                            merged_cells.append(current_cells)
                        current_cells = [cell_name]
                        current_operand_count = operand_count
                    else:
                        current_cells.append(cell_name)
                        current_operand_count += operand_count
                if current_cells:
                    merged_cells.append(current_cells)

                for cells in merged_cells:
                    if len(cells) > 1:
                        self.merge_cells(cells)
                        merged = True

        return merged
    
    # Traverse the graph and check whether there are any potential sequential cells that
    # can be combined into a single cell. Sequential cells can be merged if the following
    # conditions are met:
    # - Both cells have an arity of 2.
    # - All outputs of the first cell are inputs to the second cell.
    # - The second cell only has two predecessors, one of which is the first cell.
    def collapse_sequential_cells(self):
        merged = False
        for node in self.G.nodes:
            if self.G.nodes[node].get("type") != "cell":
                continue
            metadata: CellMetadata = self.G.nodes[node]["metadata"]
            if metadata.arity != 2:
                continue
            
            successors = list(self.G.successors(node))
            if len(successors) != 1:
                continue
            
            successor = successors[0]
            if self.G.nodes[successor].get("type") != "cell":
                continue
            successor_metadata: CellMetadata = self.G.nodes[successor]["metadata"]
            if successor_metadata.arity != 2:
                continue
            
            # check if all outputs of the first cell are inputs to the second cell
            all_outputs_are_inputs = True
            for operand in metadata.operands:
                if operand.Y not in self.G.predecessors(successor):
                    all_outputs_are_inputs = False
                    break
            
            if not all_outputs_are_inputs:
                continue
            
            # check if the second cell has only two predecessors, one of which is the first cell
            predecessor_nodes = list(self.G.predecessors(successor))
            if len(predecessor_nodes) != 2 or node not in predecessor_nodes:
                continue
            
            print(f"We could merge sequential cells: {node} -> {successor}")
            raise ValueError("Sequential cells merging is not implemented yet.")
        
        return merged

    # Emit the current state of the graph into code.
    def emit_code(self, module):
        regctr = 0
        def reg():
            nonlocal regctr
            reg_name = f"reg_{regctr:02x}"
            regctr += 1
            return reg_name

        def make_mask(mapping: list[int]) -> str:
            set_bits = set(i for i in mapping if i != -1)
            if len(set_bits) == 1:
                return f"_mm512_set1_epi8({set_bits.pop()})"
            else:
                mapping = [x if x != -1 else 0 for x in mapping]  # replace -1 with 0
                return f"_mm512_set_epi8({', '.join(map(str, reversed(mapping)))})"

        def find_existing_register(source_wires: list[WirePos], target_indices: list[int]) -> str | None:
            for known_bits, reg_name in registers_with_known_bits:
                valid = True
                for i, bit in enumerate(target_indices):
                    source_wire_id = source_wires[i].wire_id
                    if known_bits[bit] != source_wire_id:
                        valid = False
                        break
                if valid:
                    # we found a register that contains the bits in the right order
                    return reg_name
            return None
        
        # given a list of source indices and a list of target bit positions, compute the "cost" needed of producing
        # such an alignment operation; the cost is equal to the number of permutations that need to be performed,
        # unless the source indices are already from a single register whose relevant bits are in the same indexes
        # as the target indices, in which case the cost is 0. The final cost is roughly equal to the number of permute
        # operations that need to be emitted
        def compute_rearrange_cost(source_wires: list[WirePos], target_indices: list[int]) -> int:
            if len(source_wires) == 0:
                return 0
            assert len(source_wires) == len(target_indices), "Source wires and target indices must have the same length."

            # if there's a known register for these wires, we can just use that
            existing_reg = find_existing_register(source_wires, target_indices)
            if existing_reg is not None:
                # we can just use the existing register, no cost
                return 0
            
            # group source wires by their register
            source_indices_by_reg: Dict[str, list[BitMapping]] = {}
            for i, wire_pos in enumerate(source_wires):
                if wire_pos.reg not in source_indices_by_reg:
                    source_indices_by_reg[wire_pos.reg] = []
                source_indices_by_reg[wire_pos.reg].append(BitMapping(wire_pos, target_indices[i]))

            source_reg_mappings = list(source_indices_by_reg.values())

            # if there's only one register, it's either 0 cost if the bits are already in the right order, or 1 cost if we need to permute them
            if len(source_reg_mappings) == 1:
                source_mapping = source_reg_mappings[0]
                if all(x.from_pos.bit == x.to_index for x in source_mapping):
                    return 0
                return 1

            return len(source_reg_mappings) - 1

        # perform a rearrangement operation on the given source wires to match the target indices. returns the
        # register name of the register that contains the rearranged bits.
        def rearrange_impl(source_wires: list[WirePos], target_indices: list[int]) -> str:
            assert len(target_indices) <= BITS_PER_REG, "Target indices exceed the number of bits in a register."
            if len(source_wires) == 0:
                raise ValueError("Cannot rearrange empty source wires.")
            assert len(source_wires) == len(target_indices), f"Source wires and target indices must have the same length. Got {len(source_wires)} and {len(target_indices)} {target_indices}."
            # print(f"    // rearrange of {', '.join([f'{x.reg}[{x.bit}]' for x in source_wires])} to {', '.join(map(str, target_indices))}")

            known_reg = find_existing_register(source_wires, target_indices)
            if known_reg is not None:
                # we can just use the existing register, no need to rearrange
                eprint(f"Reusing known register {known_reg} for bits {target_indices}")
                return known_reg

            # group source wires by their register
            source_indices_by_reg: Dict[str, list[BitMapping]] = {}
            for i, wire_pos in enumerate(source_wires):
                if wire_pos.reg not in source_indices_by_reg:
                    source_indices_by_reg[wire_pos.reg] = []
                source_indices_by_reg[wire_pos.reg].append(BitMapping(wire_pos, target_indices[i]))

            source_reg_mappings = list(source_indices_by_reg.values())
            if len(source_reg_mappings) == 1:
                # if the bits are already in the right order, we can just return the register
                source_mapping = source_reg_mappings[0]
                if all(x.from_pos.bit == x.to_index for x in source_mapping):
                    return source_mapping[0].from_pos.reg

                # all bits are in the same register, we can just permute them
                source_mapping = source_reg_mappings[0]
                pos = [-1] * BITS_PER_REG
                for bit_mapping in source_mapping:
                    pos[bit_mapping.to_index] = bit_mapping.from_pos.bit
                r = reg()
                print(f"  __m512i {r} = _mm512_permutexvar_epi8({make_mask(pos)}, {source_mapping[0].from_pos.reg});")
                return r
            
            if len(source_reg_mappings) == 2:
                # we can combine two registers into a single register
                first_mapping = source_reg_mappings[0]
                second_mapping = source_reg_mappings[1]
                pos = [-1] * BITS_PER_REG
                for bit_mapping in first_mapping:
                    pos[bit_mapping.to_index] = bit_mapping.from_pos.bit
                for bit_mapping in second_mapping:
                    pos[bit_mapping.to_index] = bit_mapping.from_pos.bit + 64
                r = reg()
                print(f"  __m512i {r} = _mm512_permutex2var_epi8({first_mapping[0].from_pos.reg}, {make_mask(pos)}, {second_mapping[0].from_pos.reg});")
                return r
            
            # see if we can find a register that already has all of its bits in the right place; if so, we can start there
            # otherwise, we need to start on a zero register
            for mapping in source_reg_mappings:
                if all(x.from_pos.bit == x.to_index for x in mapping):
                    # we can use this register as the base register
                    r = mapping[0].from_pos.reg
                    source_reg_mappings.remove(mapping)  # remove this mapping from the list
                    break
            else:
                # no register has all bits in the right place, so we start with a zero register
                r = reg()
                print(f"  __m512i {r} = _mm512_setzero_si512();")
            
            # more than two registers, repeatedly mix in new registers, starting with the first
            for mapping in source_reg_mappings:
                # we can combine the current register with the next one
                pos = list(range(BITS_PER_REG))  # positions in the new register
                for bit_mapping in mapping:
                    pos[bit_mapping.to_index] = bit_mapping.from_pos.bit + 64
                newr = reg()
                print(f"  __m512i {newr} = _mm512_permutex2var_epi8({r}, {make_mask(pos)}, {mapping[0].from_pos.reg});")
                r = newr  # update the register to the new one
            return r

        def rearrange(source_wires: list[WirePos], target_indices: list[int]) -> str:
            res = rearrange_impl(source_wires, target_indices)
            mapping = [-1] * BITS_PER_REG
            for i, wire_pos in enumerate(source_wires):
                mapping[target_indices[i]] = wire_pos.wire_id
            registers_with_known_bits.append((mapping, res))
            return res
        
        def compute_cell_input(ops: list[CellOperands]) -> CellIOLayout:
            # We need to settle on which bits of the input operands we want to assign to the input operands.
            # To do so, we'll try all registers as the "base" alignment one-by-one, then try to align the
            # remaining registers to that base alignment. The cost of that arrangement is the cost of combining
            # the base register (zero if all bits from the base register are from the same register, in which
            # case we can just use that register as-is), plus the cost of rearranging the other registers
            # to match the base register's bit positions. We'll pick the arrangement with the lowest cost.
            arity = 3 if ops[0].C is not None else 2

            align_options = []
            if arity == 2:
                align_options = [("A", ["B"]), ("B", ["A"])]
            else:
                align_options = [
                    ("A", ["B", "C"]),
                    ("B", ["A", "C"]),
                    ("C", ["A", "B"])
                ]
            
            best_bit_layout: list[int] = []
            best_cost = float("inf")
            for align_target, alignees in align_options:
                base_locations = [bit_locations[getattr(op, align_target)] for op in ops]
                if all(x.reg == base_locations[0].reg for x in base_locations):
                    target_bit_alignment = [x.bit for x in base_locations]
                else:
                    target_bit_alignment = list(range(len(base_locations)))
                cost = compute_rearrange_cost(base_locations, target_bit_alignment) # this is zero if all bits are already in the same register
                for alignee in alignees:
                    source_locations = [bit_locations[getattr(op, alignee)] for op in ops]
                    if len(source_locations) == 0:
                        continue
                    cost += compute_rearrange_cost(source_locations, target_bit_alignment)
                if cost < best_cost:
                    best_cost = cost
                    best_bit_layout = target_bit_alignment

            # we can now just rearrange all the inputs to match this alignment; this will be no-ops
            # for any inputs already in the right orientation
            input_registers = [
                rearrange([bit_locations[op.A] for op in ops], best_bit_layout),
                rearrange([bit_locations[op.B] for op in ops], best_bit_layout)
            ]
            if arity == 3:
                input_registers.append(rearrange([bit_locations[op[2]] for op in ops], best_bit_layout))
            output_bit_mapping = {op.Y: best_bit_layout[i] for i, op in enumerate(ops)}
            return CellIOLayout(
                input_registers=input_registers,
                output_bit_mapping=output_bit_mapping
            )
        
        bit_locations: Dict[int, WirePos] = {}
        registers_with_known_bits: list[Tuple[list[int], str]] = [] # list of bit ids mapped to register that contains them

        # create bit locations for the inputs; we assume those are already in a variable with
        # the same name as the input node, and the bits in order as listed in the module's ports
        for port_name, port in module["ports"].items():
            if port["direction"] != "input":
                continue
            assert len(port["bits"]) <= BITS_PER_REG, f"Port {port_name} has too many bits: {len(port['bits'])} > {BITS_PER_REG}"
            for i, bit in enumerate(port["bits"]):
                wire_pos = WirePos(bit, port_name, i)
                bit_locations[bit] = wire_pos
    
        # iterate over cells in topological order
        for cell in nx.topological_sort(self.G):
            if self.G.nodes[cell].get("type") != "cell":
                continue
            
            metadata: CellMetadata = self.G.nodes[cell]["metadata"]
            vpternlogd = metadata.vpternlogd
            operands = metadata.operands

            eprint(f"Processing cell {cell} with type {metadata.cell_type} and vpternlogd {vpternlogd}...")
            layout = compute_cell_input(operands)

            rega = layout.input_registers[0]
            regb = layout.input_registers[1]
            regc = layout.input_registers[2] if len(layout.input_registers) > 2 else rega

            Yreg = reg()
            print(f"  __m512i {Yreg} = _mm512_ternarylogic_epi32({rega}, {regb}, {regc}, {vpternlogd}); // {metadata.cell_type} ({len(operands)} operands)")
            # print(f"  __m512i {Yreg} = {rega};")
            # print(f"  asm(\"vpternlogd %2 {'{k0}'}, %1, %0, {vpternlogd}\" : \"=v\"({Yreg}) : \"v\"({regb}), \"v\"({regc})); // {metadata.cell_type} ({len(operands)} operands)")
            out_bits = [-1] * BITS_PER_REG
            for operand in operands:
                bit_locations[operand.Y] = WirePos(operand.Y, Yreg, layout.output_bit_mapping[operand.Y])
                out_bits[layout.output_bit_mapping[operand.Y]] = operand.Y
            registers_with_known_bits.append((out_bits, Yreg))

        # create output nodes for the outputs
        for port_name, port in module["ports"].items():
            if port["direction"] != "output":
                continue
            assert len(port["bits"]) <= BITS_PER_REG, f"Port {port_name} has too many bits: {len(port['bits'])} > {BITS_PER_REG}"
            src_locs = [bit_locations[x] for x in port["bits"]]
            result = rearrange(src_locs, [i for i in range(len(src_locs))])
            print(f"  __m512i {port_name} = {result};")

    # Print the graph in Graphviz format.
    def print_graphviz(self):
        print("digraph G {")
        for node in self.G.nodes:
            node_type = self.G.nodes[node].get("type", "unknown")
            if node_type == "input":
                print(f'    "{node}" [shape=box, style=filled, fillcolor=lightblue];')
            elif node_type == "output":
                print(f'    "{node}" [shape=box, style=filled, fillcolor=lightgreen];')
            elif node_type == "cell":
                metadata: CellMetadata = self.G.nodes[node].get("metadata")
                print(f'    "{node}" [shape=box, label="{metadata.cell_type} {metadata.vpternlogd}"];')
            else:
                print(f'    "{node}" [shape=circle];')
        for u, v, d in self.G.edges:
            print(f'    "{u}" -> "{v}";')
        print("}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python assembler.py <input.json>")
        sys.exit(1)

    # load yosys output
    with open(sys.argv[1], "r") as f:
        data = json.load(f)

    module = data["modules"][next(iter(data["modules"].keys()))]

    assembler = Assembler()
    assembler.process_initial(module)
    assembler.collapse_wires()
    while True:
        if not assembler.collapse_iteration() and not assembler.collapse_sequential_cells():
            break
    # assembler.print_graphviz()
    assembler.emit_code(module)
