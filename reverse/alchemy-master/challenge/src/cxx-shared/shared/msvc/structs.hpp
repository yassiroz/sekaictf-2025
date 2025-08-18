#pragma once
#include "context.hpp"
#include <cstdint>

#pragma pack(push, 1)
namespace msvc {
    // c1xx.dll

    class s_tree {
    public:
        //
    };

    class ExprGrammarActionVisitor {
    public:
        //
    };

    using token_t = std::uint16_t;

    class Token {
    public:
        token_t tag;
    };

    class TokenStream {
    public:
    };

    class TokenStreamStack {
    public:
        //
    };

    namespace Parser {
        class CxxParser {
        public:
            //
        };
    } // namespace Parser

    namespace ParseTree {
        class Expression {
        public:
            std::uint32_t pad_0;
            std::uint16_t tag;
        };
    } // namespace ParseTree

    // c2.dll

    enum struct TupleInternalKind : std::uint8_t {
        Statement = 12,
        FunctionCall = 14,
        ReturnStatement = 15,
        ControlFlow = 17,
        VirtualCallSetup = 18,
        ExceptionHandler = 20,
        PrologueEpilogue = 22,
        BeginCompoundStmt = 23,
        Epilogue = 24,
        EndCompoundStmt = 25,
        Cleanup = 26,
    };

    enum struct TupleKind : std::uint32_t {
        FunctionPrologue = 2361,
        BeginEpilogue = 2362,
        FunctionEpilogue = 2356,
        ScopeCleanup = 2353,
        ObjectInitializationStmt = 2127,
        SimpleStmt = 2130,
        DeclarationWithCastStmt = 2134,
        ComplexExprStmt = 2163,
        ConditionalStmt = 2193,
        FunctionCallStmt = 2201,
        ReturnStmt = 2156,
        JumpOnFalse = 2202,
        Jump = 2203,
        EH_Jump = 2204,
        EH_Setup = 2209,
        ThrowStmt = 2210,
        EH_Rethrow = 2211,
        VirtualCallStmt = 2216,
        DestructorEHBlock = 2327,
        BeginTryBlock = 2333,
        BeginCatchBlock = 2334,
        EndEHBlock = 2337,
        BeginCompoundStmt = 2355,
        EndCompoundStmt = 2354,
    };

    class Symbol {
    public:
    };

    struct Tuple {
    public:
        Tuple* next;
        TupleKind kind;
        TupleInternalKind internal_node_kind;
    };

    class TupleContainerInner {
    public:
        uint8_t pad_0[56];
        Tuple* first;
    };

    class TupleContainer {
    public:
        TupleContainerInner* inner;
    };

    class tagFUNC {
    public:
        Symbol* symbol;
        uint64_t pad_0;
        TupleContainer* tuple_container;
    };
} // namespace msvc
#pragma pack(pop)
