from enum import Enum


class MSVCTupleKind(int, Enum):
    FunctionPrologue = 2361
    BeginEpilogue = 2362
    FunctionEpilogue = 2356
    ScopeCleanup = 2353
    ObjectInitializationStmt = 2127
    SimpleStmt = 2130
    DeclarationWithCastStmt = 2134
    ComplexExprStmt = 2163
    ConditionalStmt = 2193
    FunctionCallStmt = 2201
    ReturnStmt = 2156
    JumpOnFalse = 2202
    Jump = 2203
    EH_Jump = 2204
    EH_Setup = 2209
    ThrowStmt = 2210
    EH_Rethrow = 2211
    VirtualCallStmt = 2216
    DestructorEHBlock = 2327
    BeginTryBlock = 2333
    BeginCatchBlock = 2334
    EndEHBlock = 2337
    BeginCompoundStmt = 2355
    EndCompoundStmt = 2354


class AlchemyMaterialType(int, Enum):
    LEAD = 1 << 0
    AETHER = 1 << 1
    QUICKSILVER = 1 << 2
    IRON = 1 << 3
    WATER = 1 << 4
    SALT = 1 << 5
    SULFUR = 1 << 6


def index(material: AlchemyMaterialType) -> int:
    return (material & -material).bit_length() - 1


reactions = [
    (MSVCTupleKind.SimpleStmt, AlchemyMaterialType.SULFUR | AlchemyMaterialType.WATER, AlchemyMaterialType.QUICKSILVER),
    (
        MSVCTupleKind.ThrowStmt,
        AlchemyMaterialType.QUICKSILVER | AlchemyMaterialType.SULFUR | AlchemyMaterialType.WATER,
        AlchemyMaterialType.AETHER,
    ),
    (MSVCTupleKind.EH_Rethrow, AlchemyMaterialType.SULFUR | AlchemyMaterialType.LEAD, AlchemyMaterialType.WATER),
    (MSVCTupleKind.FunctionCallStmt, AlchemyMaterialType.LEAD | AlchemyMaterialType.SULFUR, AlchemyMaterialType.IRON),
    (MSVCTupleKind.ReturnStmt, AlchemyMaterialType.LEAD | AlchemyMaterialType.WATER, AlchemyMaterialType.SALT),
]
