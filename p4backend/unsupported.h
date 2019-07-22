/**
 * \file unsupported.h
 * \brief Contains inspector base classes with preorder methods that raises error when called.
 * \date 2019
 * \author Jiri Havranek <havranek@cesnet.cz>
 */
/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.

 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
*/

#ifndef _BACKENDS_P4E_UNSUPPORTED_H_
#define _BACKENDS_P4E_UNSUPPORTED_H_

#include "ir/ir.h"

namespace exporter {

#define UNSUPPORTED_NODE(_NODE_) \
   bool preorder(const IR::_NODE_ *expr) override { BUG("%3%: Unsupported node %1%, expression: %2%", expr->node_type_name(), expr, typeid(*this).name()); return true; }

/**
 * Unsupported types.
 */
class UnsupportedTypesInspector : public Inspector
{
public:
   UNSUPPORTED_NODE(Type)
   UNSUPPORTED_NODE(P4Control)
   UNSUPPORTED_NODE(P4Parser)
   UNSUPPORTED_NODE(Type_Action)
   UNSUPPORTED_NODE(Type_ActionEnum)
   UNSUPPORTED_NODE(Type_AnyTable)
   UNSUPPORTED_NODE(Type_ArchBlock)
   UNSUPPORTED_NODE(Type_Base)
   UNSUPPORTED_NODE(Type_Bits)
   UNSUPPORTED_NODE(Type_Block)
   UNSUPPORTED_NODE(Type_Boolean)
   UNSUPPORTED_NODE(Type_Control)
   UNSUPPORTED_NODE(Type_Counter)
   UNSUPPORTED_NODE(Type_Declaration)
   UNSUPPORTED_NODE(Type_Dontcare)
   UNSUPPORTED_NODE(Type_Enum)
   UNSUPPORTED_NODE(Type_Error)
   UNSUPPORTED_NODE(Type_Expression)
   UNSUPPORTED_NODE(Type_Extern)
   UNSUPPORTED_NODE(Type_FieldListCalculation)
   UNSUPPORTED_NODE(Type_Header)
   UNSUPPORTED_NODE(Type_HeaderUnion)
   UNSUPPORTED_NODE(Type_InfInt)
   UNSUPPORTED_NODE(Type_MatchKind)
   UNSUPPORTED_NODE(Type_Meter)
   UNSUPPORTED_NODE(Type_Method)
   UNSUPPORTED_NODE(Type_MethodBase)
   UNSUPPORTED_NODE(Type_MethodCall)
   UNSUPPORTED_NODE(Type_Name)
   UNSUPPORTED_NODE(Type_Package)
   UNSUPPORTED_NODE(Type_Parser)
   UNSUPPORTED_NODE(Type_Register)
   UNSUPPORTED_NODE(Type_Set)
   UNSUPPORTED_NODE(Type_Specialized)
   UNSUPPORTED_NODE(Type_SpecializedCanonical)
   UNSUPPORTED_NODE(Type_Stack)
   UNSUPPORTED_NODE(Type_State)
   UNSUPPORTED_NODE(Type_String)
   UNSUPPORTED_NODE(Type_Struct)
   UNSUPPORTED_NODE(Type_StructLike)
   UNSUPPORTED_NODE(Type_Table)
   UNSUPPORTED_NODE(Type_Tuple)
   UNSUPPORTED_NODE(Type_Type)
   UNSUPPORTED_NODE(Type_Typedef)
   UNSUPPORTED_NODE(Type_Unknown)
   UNSUPPORTED_NODE(Type_Var)
   UNSUPPORTED_NODE(Type_Varbits)
   UNSUPPORTED_NODE(Type_Void)
};

/**
 * Unsupported blocks.
 */
class UnsupportedBlocksInspector : public Inspector
{
public:
   UNSUPPORTED_NODE(InstantiatedBlock)
   UNSUPPORTED_NODE(TableBlock)
   UNSUPPORTED_NODE(ToplevelBlock)
   UNSUPPORTED_NODE(ControlBlock)
   UNSUPPORTED_NODE(ExternBlock)
   UNSUPPORTED_NODE(PackageBlock)
   UNSUPPORTED_NODE(ParserBlock)
};

#define UNSUPPORTED_OP_RELATION \
   UNSUPPORTED_NODE(Operation_Relation) \
   UNSUPPORTED_NODE(Equ) \
   UNSUPPORTED_NODE(Geq) \
   UNSUPPORTED_NODE(Grt) \
   UNSUPPORTED_NODE(Leq) \
   UNSUPPORTED_NODE(Lss) \
   UNSUPPORTED_NODE(Neq)

/**
 * Unsupported relation operations.
 */
class UnsupportedRelOpInspector : public Inspector
{
public:
   UNSUPPORTED_OP_RELATION
};

#define UNSUPPORTED_OP_BINARY \
   UNSUPPORTED_NODE(Operation_Binary) \
   UNSUPPORTED_NODE(Add) \
   UNSUPPORTED_NODE(ArrayIndex) \
   UNSUPPORTED_NODE(BAnd) \
   UNSUPPORTED_NODE(BOr) \
   UNSUPPORTED_NODE(BXor) \
   UNSUPPORTED_NODE(Concat) \
   UNSUPPORTED_NODE(Div) \
   UNSUPPORTED_NODE(LAnd) \
   UNSUPPORTED_NODE(LOr) \
   UNSUPPORTED_NODE(Mask) \
   UNSUPPORTED_NODE(Mod) \
   UNSUPPORTED_NODE(Mul) \
   UNSUPPORTED_OP_RELATION \
   UNSUPPORTED_NODE(Range) \
   UNSUPPORTED_NODE(Shl) \
   UNSUPPORTED_NODE(Shr) \
   UNSUPPORTED_NODE(Sub)

/**
 * Unsupported binary operations.
 */
class UnsupportedBinOpInspector : public UnsupportedRelOpInspector
{
public:
   UNSUPPORTED_OP_BINARY
};

#define UNSUPPORTED_OP_TERNARY \
   UNSUPPORTED_NODE(Operation_Ternary) \
   UNSUPPORTED_NODE(Mux) \
   UNSUPPORTED_NODE(Slice)

/**
 * Unsupported ternary operations.
 */
class UnsupportedTerOpInspector : public Inspector
{
public:
   UNSUPPORTED_OP_TERNARY
};

#define UNSUPPORTED_OP_UNARY \
   UNSUPPORTED_NODE(Operation_Unary) \
   UNSUPPORTED_NODE(Cast) \
   UNSUPPORTED_NODE(Cmpl) \
   UNSUPPORTED_NODE(LNot) \
   UNSUPPORTED_NODE(Member) \
   UNSUPPORTED_NODE(Neg)

/**
 * Unsupported unary operations.
 */
class UnsupportedUnOpInspector : public Inspector
{
public:
   UNSUPPORTED_OP_UNARY
};

#define UNSUPPORTED_OP \
   UNSUPPORTED_NODE(Operation) \
   UNSUPPORTED_OP_BINARY \
   UNSUPPORTED_OP_TERNARY \
   UNSUPPORTED_OP_UNARY \
   UNSUPPORTED_NODE(Primitive);

/**
 * Unsupported operations.
 */
class UnsupportedOpInspector : public Inspector
{
public:
   UNSUPPORTED_OP
};

/**
 * Unsupported expressions.
 */
class UnsupportedExpressionInspector : public UnsupportedOpInspector
{
public:
   UNSUPPORTED_NODE(ActionArg)
   UNSUPPORTED_NODE(Apply)
   UNSUPPORTED_NODE(AttribLocal)
   UNSUPPORTED_NODE(AttributeRef)
   UNSUPPORTED_NODE(ConstructorCallExpression)
   UNSUPPORTED_NODE(DefaultExpression)
   UNSUPPORTED_NODE(GlobalRef)
   UNSUPPORTED_NODE(HeaderRef)
   UNSUPPORTED_NODE(ConcreteHeaderRef)
   UNSUPPORTED_NODE(HeaderStackItemRef)
   UNSUPPORTED_NODE(If)
   UNSUPPORTED_NODE(NamedCond)
   UNSUPPORTED_NODE(ListExpression)
   UNSUPPORTED_NODE(Literal)
   UNSUPPORTED_NODE(BoolLiteral)
   UNSUPPORTED_NODE(Constant)
   UNSUPPORTED_NODE(StringLiteral)
   UNSUPPORTED_NODE(MethodCallExpression)
   UNSUPPORTED_OP
   UNSUPPORTED_NODE(PathExpression)
   UNSUPPORTED_NODE(SelectExpression)
   UNSUPPORTED_NODE(This)
   UNSUPPORTED_NODE(TypeNameExpression)
};

/**
 * Unsupported declarations.
 */
class UnsupportedDeclarationInspector : public Inspector
{
public:
   UNSUPPORTED_NODE(Declaration)
   UNSUPPORTED_NODE(Attribute)
   UNSUPPORTED_NODE(Declaration_Constant)
   UNSUPPORTED_NODE(Declaration_ID)
   UNSUPPORTED_NODE(Declaration_Instance)
   UNSUPPORTED_NODE(Declaration_Variable)
   UNSUPPORTED_NODE(Function)
   UNSUPPORTED_NODE(Method)
   UNSUPPORTED_NODE(P4Action)
   UNSUPPORTED_NODE(P4Table)
   UNSUPPORTED_NODE(Parameter)
   UNSUPPORTED_NODE(ParserState)
   UNSUPPORTED_NODE(Property)
   UNSUPPORTED_NODE(StructField)
};

/**
 * Unsupported statements.
 */
class UnsupportedStatementInspector : public Inspector
{
public:
   UNSUPPORTED_NODE(Statement)
   UNSUPPORTED_NODE(AssignmentStatement)
   UNSUPPORTED_NODE(BlockStatement)
   UNSUPPORTED_NODE(EmptyStatement)
   UNSUPPORTED_NODE(ExitStatement)
   UNSUPPORTED_NODE(IfStatement)
   UNSUPPORTED_NODE(MethodCallStatement)
   UNSUPPORTED_NODE(ReturnStatement)
   UNSUPPORTED_NODE(SwitchStatement)
};

} // namespace exporter
#endif // _BACKENDS_P4E_UNSUPPORTED_H_
