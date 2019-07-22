/**
 * \file utils.h
 * \brief Contains useful objects for code generation, node inspection and logging.
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

#ifndef _BACKENDS_P4E_UTILS_H_
#define _BACKENDS_P4E_UTILS_H_

#include <nlohmann/json.hpp>
#include <boost/format.hpp>

#include "ir/ir.h"
#include "lib/error.h"
#include "lib/log.h"

#include "unsupported.h"
#include "options.h"

namespace exporter
{

enum variableType
{
   typeUnknown = 0,
   typeIntU = 1,
   typeInt = 2,
   typeBool = 3,
   typeStruct = 4,
   typeHeader = 5,
   typeUnion = 6,
   typeError = 7,
   typeString = 8,
   typeEnum,
   typeVoid
};

void getLoadParameters(uint32_t width, std::string &loaderFunc, std::string &transformFunc, uint32_t &toLoad);
void fillJsonTypeBasic(nlohmann::json &container, std::string typeName, std::string typeNameShort, variableType type);
void fillJsonTypeWidth(nlohmann::json &container, uint32_t width, uint32_t implementationWidth);
void fillJsonTypeArray(nlohmann::json &container, bool array, unsigned arraySize);
void fillJsonVar(nlohmann::json &container, std::string typeName, std::string typeNameShort, variableType type, std::string name);

bool fileExists(const std::string &file);
bool generateOutputFolder(const std::string &dir);
bool copy(const std::string &src, const std::string &dst);

/**
 * \brief Translates P4 types into C.
 */
class TypeTranslator
{
public:
   TypeTranslator(const IR::Type *type, P4::TypeMap *typeMap);
   TypeTranslator(const IR::StructField *decl, P4::TypeMap *typeMap);
   TypeTranslator(const IR::Declaration_Variable *decl, P4::TypeMap *typeMap);

   /**
    * \brief Fill JSON container with generated C code of variable.
    *
    * \param [in] container Output JSON container.
    */
   void fillJson(nlohmann::json &container) const;
   /**
    * \brief Get width of variable in P4 in number of bits.
    */
   uint32_t getWidth() const;
   /**
    * \brief Get width of variable in C in number of bits.
    */
   uint32_t getImplementationWidth() const;
   /**
    * \brief Get length of array in number of bytes.
    */
   int getArrayLength() const;
   /**
    * \brief Check if variable is string and return it's length.
    */
   int isString() const;
   /**
    * \brief Get full name of variable. For example `struct ethernet_h`.
    */
   std::string getName() const;
   /**
    * \brief Get short name of variable. For example `ethernet_h`.
    */
   std::string getNameShort() const;

private:
   const IR::Type *type_;
   P4::TypeMap *typeMap_;

   bool decl_;
   std::vector<TypeTranslator> fields_;
   std::vector<std::string> fieldNames_;

   uint32_t width_; /**< Width in number of bits of P4 variable. */
   uint32_t implementationWidth_; /**< Width in number of bits of C variable. */
   bool array_; /**< Variable is array. */
   bool string_; /**< Variable is string. */
   uint32_t arraySize_; /**< Length of array or string. */
   variableType typeCode_; /**< Type of variable - struct, enum, integer ... */

   std::string typeName_; /**< Full name of type. */
   std::string typeNameShort_; /**< Short name of type. */

   void initialize();
   void compileTypeWithAnnotations(const IR::Declaration *decl);
   void compileType(const IR::Type *type);
};

/**
 * \brief Code builder base class.
 */
class CodeBuilder
{
public:
   CodeBuilder(P4::ReferenceMap *refMap, P4::TypeMap *typeMap, nlohmann::json &container, int spacesPerIndent = 3);

protected:
   P4::ReferenceMap *refMap_;
   P4::TypeMap *typeMap_;

   nlohmann::json &container_; /**< Container with C source code. */

   int indentLevel_; /**< Indentation level of source code. */
   const int spacesPerIndent_; /**< Number of spaces per one indentation level. */

   /**
    * \brief Add code into container.
    *
    * \param [in] container Output container.
    * \param [in] name Name of JSON node.
    * \param [in] code Generated code.
    */
   void addCode(nlohmann::json &container, const std::string &name, const std::string &code);
   /**
    * \brief Add code in `statement` JSON node in container.
    *
    * \param [in] stat Statement code.
    */
   void addStatement(const std::string &stat);
   /**
    * \brief Increase `indetLevel_` variable by 1.
    */
   void increaseIndent();
   /**
    * \brief Decrease `indetLevel_` variable by 1.
    */
   void decreaseIndent();
};

class Generator
{
public:
   Generator(const P4EOptions &options, const IR::ToplevelBlock *topLevel, P4::ReferenceMap *refMap, P4::TypeMap *typeMap);
   virtual void generate() = 0;
   bool checkTemplateFile(const std::string &file);

protected:
   const P4EOptions &options_;
   const IR::ToplevelBlock *topLevel_;
   P4::ReferenceMap *refMap_;
   P4::TypeMap *typeMap_;
};

/**
 * Compiles arithmetic expression.
 */
class ConstructArithmeticExpression : public UnsupportedExpressionInspector
{
public:
   ConstructArithmeticExpression(P4::ReferenceMap *refMap, P4::TypeMap *typeMap);
   bool preorder(const IR::BoolLiteral *lit) override;
   bool preorder(const IR::Add *expr) override;
   bool preorder(const IR::Sub *expr) override;
   bool preorder(const IR::Mul *expr) override;
   bool preorder(const IR::Div *expr) override;
   bool preorder(const IR::Mod *expr) override;
   bool preorder(const IR::Shl *expr) override;
   bool preorder(const IR::Shr *expr) override;
   bool preorder(const IR::BXor *expr) override;
   bool preorder(const IR::BAnd *expr) override;
   bool preorder(const IR::BOr *expr) override;
   bool preorder(const IR::Constant *expr) override;
   bool preorder(const IR::Member *expr) override;
   bool preorder(const IR::PathExpression *expr) override;
   bool preorder(const IR::Cast *expr) override;
   std::string getExpression() const;

protected:
   P4::ReferenceMap *refMap_;
   P4::TypeMap *typeMap_;
   std::string expression_; /**< String with generated expression. */
};

/**
 * Compiles arithmetic and logical expression.
 */
class ConstructLogicalExpression : public ConstructArithmeticExpression
{
public:
   ConstructLogicalExpression(P4::ReferenceMap *refMap, P4::TypeMap *typeMap);
   bool preorder(const IR::LOr *expr) override;
   bool preorder(const IR::LAnd *expr) override;
   bool preorder(const IR::LNot *expr) override;
   bool preorder(const IR::Equ *expr) override;
   bool preorder(const IR::Neq *expr) override;
   bool preorder(const IR::Geq *expr) override;
   bool preorder(const IR::Grt *expr) override;
   bool preorder(const IR::Leq *expr) override;
   bool preorder(const IR::Lss *expr) override;
};

class ConstructExpression : public ConstructLogicalExpression
{
public:
   ConstructExpression(P4::ReferenceMap *refMap, P4::TypeMap *typeMap);
};


inline std::string formatHelper(boost::format &msg)
{
   return boost::str(msg);
}

template <typename T, typename... Args>
std::string formatHelper(boost::format &msg, T &&arg, Args &&... args)
{
   msg % std::forward<T>(arg);
   return formatHelper(msg, std::forward<Args>(args)...);
}

template <typename... Args>
std::string format(const char *fmt, Args &&... args)
{
   boost::format msg(fmt);
   return formatHelper(msg, std::forward<Args>(args)...);
}

template <typename... T>
void log(const char *fmt, T &&... args)
{
   if (Log::verbose()) {
      std::cerr << format(fmt, args...) << std::endl;
   }
}

} // namespace exporter
#endif // _BACKENDS_P4E_UTILS_H_
