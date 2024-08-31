const std = @import("std");
pub const builtin = @import("builtin");

pub const SourceLocation = extern struct {
    ID: c_uint,

    pub const eq = ZigClangSourceLocation_eq;
    extern fn zig_clang_source_location_eq(a: SourceLocation, b: SourceLocation) bool;
};

pub const QualType = extern struct {
    ptr: ?*anyopaque,

    pub const getCanonicalType = ZigClangQualType_getCanonicalType;
    extern fn zig_clang_qual_type_get_canonical_type(QualType) QualType;

    pub const getTypePtr = ZigClangQualType_getTypePtr;
    extern fn zig_clang_qual_type_get_type_ptr(QualType) *const Type;

    pub const getTypeClass = ZigClangQualType_getTypeClass;
    extern fn zig_clang_qual_type_get_type_class(QualType) TypeClass;

    pub const addConst = ZigClangQualType_addConst;
    extern fn zig_clang_qual_type_add_const(*QualType) void;

    pub const eq = ZigClangQualType_eq;
    extern fn zig_clang_qual_type_eq(QualType, arg1: QualType) bool;

    pub const isConstQualified = ZigClangQualType_isConstQualified;
    extern fn zig_clang_qual_type_is_const_qualified(QualType) bool;

    pub const isVolatileQualified = ZigClangQualType_isVolatileQualified;
    extern fn zig_clang_qual_type_is_volatile_qualified(QualType) bool;

    pub const isRestrictQualified = ZigClangQualType_isRestrictQualified;
    extern fn zig_clang_qual_type_is_restrict_qualified(QualType) bool;
};

pub const APValueLValueBase = extern struct {
    Ptr: ?*anyopaque,
    CallIndex: c_uint,
    Version: c_uint,

    pub const dyn_cast_Expr = ZigClangAPValueLValueBase_dyn_cast_Expr;
    extern fn zig_clang_apvalue_lvalue_base_dyn_cast_expr(APValueLValueBase) ?*const Expr;
};

pub const APValueKind = enum(c_int) {
    None,
    Indeterminate,
    Int,
    Float,
    FixedPoint,
    ComplexInt,
    ComplexFloat,
    LValue,
    Vector,
    Array,
    Struct,
    Union,
    MemberPointer,
    AddrLabelDiff,
};

pub const APValue = extern struct {
    Kind: APValueKind,
    Data: if (builtin.os.tag == .windows and builtin.abi == .msvc) [52]u8 else [68]u8,

    pub const getKind = ZigClangAPValue_getKind;
    extern fn zig_clang_apvalue_get_kind(*const APValue) APValueKind;

    pub const getInt = ZigClangAPValue_getInt;
    extern fn zig_clang_apvalue_get_int(*const APValue) *const APSInt;

    pub const getArrayInitializedElts = ZigClangAPValue_getArrayInitializedElts;
    extern fn zig_clang_apvalue_get_array_initialized_elts(*const APValue) c_uint;

    pub const getArraySize = ZigClangAPValue_getArraySize;
    extern fn zig_clang_apvalue_get_array_size(*const APValue) c_uint;

    pub const getLValueBase = ZigClangAPValue_getLValueBase;
    extern fn zig_clang_apvalue_get_lvalue_base(*const APValue) APValueLValueBase;
};

pub const ExprEvalResult = extern struct {
    HasSideEffects: bool,
    HasUndefinedBehavior: bool,
    SmallVectorImpl: ?*anyopaque,
    Val: APValue,
};

pub const AbstractConditionalOperator = opaque {
    pub const getCond = ZigClangAbstractConditionalOperator_getCond;
    extern fn zig_clang_abstract_conditional_operator_get_cond(*const AbstractConditionalOperator) *const Expr;

    pub const getTrueExpr = ZigClangAbstractConditionalOperator_getTrueExpr;
    extern fn zig_clang_abstract_conditional_operator_get_true_expr(*const AbstractConditionalOperator) *const Expr;

    pub const getFalseExpr = ZigClangAbstractConditionalOperator_getFalseExpr;
    extern fn zig_clang_abstract_conditional_operator_get_false_expr(*const AbstractConditionalOperator) *const Expr;
};

pub const APFloat = opaque {
    pub const toString = ZigClangAPFloat_toString;
    extern fn zig_clang_apfloat_to_string(*const APFloat, precision: c_uint, maxPadding: c_uint, truncateZero: bool) [*:0]const u8;
};

pub const APFloatBaseSemantics = enum(c_int) {
    IEEEhalf,
    BFloat,
    IEEEsingle,
    IEEEdouble,
    IEEEquad,
    PPCDoubleDouble,
    Float8E5M2,
    Float8E5M2FNUZ,
    Float8E4M3FN,
    Float8E4M3FNUZ,
    Float8E4M3B11FNUZ,
    FloatTF32,
    x87DoubleExtended,
};

pub const APInt = opaque {
    pub fn get_limited_value(self: *const APInt, comptime T: type) T {
        return @as(T, @truncate(ZigClangAPInt_getLimitedValue(self, std.math.maxInt(T))));
    }
    extern fn zig_clang_apint_get_limited_value(*const APInt, limit: u64) u64;
};

pub const APSInt = opaque {
    pub const isSigned = ZigClangAPSInt_isSigned;
    extern fn zig_clang_apsint_is_signed(*const APSInt) bool;

    pub const isNegative = ZigClangAPSInt_isNegative;
    extern fn zig_clang_apsint_is_negative(*const APSInt) bool;

    pub const negate = ZigClangAPSInt_negate;
    extern fn zig_clang_apsint_negate(*const APSInt) *const APSInt;

    pub const free = ZigClangAPSInt_free;
    extern fn zig_clang_apsint_free(*const APSInt) void;

    pub const getRawData = ZigClangAPSInt_getRawData;
    extern fn zig_clang_apsint_get_raw_data(*const APSInt) [*:0]const u64;

    pub const getNumWords = ZigClangAPSInt_getNumWords;
    extern fn zig_clang_apsint_get_num_words(*const APSInt) c_uint;

    pub const lessThanEqual = ZigClangAPSInt_lessThanEqual;
    extern fn zig_clang_apsint_less_than_equal(*const APSInt, rhs: u64) bool;
};

pub const ASTContext = opaque {
    pub const getPointerType = ZigClangASTContext_getPointerType;
    extern fn zig_clang_astcontext_get_pointer_type(*const ASTContext, T: QualType) QualType;
};

pub const ASTUnit = opaque {
    pub const delete = ZigClangASTUnit_delete;
    extern fn zig_clang_astunit_delete(*ASTUnit) void;

    pub const getASTContext = ZigClangASTUnit_getASTContext;
    extern fn zig_clang_astunit_get_astcontext(*ASTUnit) *ASTContext;

    pub const getSourceManager = ZigClangASTUnit_getSourceManager;
    extern fn zig_clang_astunit_get_source_manager(*ASTUnit) *SourceManager;

    pub const visitLocalTopLevelDecls = ZigClangASTUnit_visitLocalTopLevelDecls;
    extern fn zig_clang_astunit_visit_local_top_level_decls(
        *ASTUnit,
        context: ?*anyopaque,
        Fn: ?*const fn (?*anyopaque, *const Decl) callconv(.C) bool,
    ) bool;

    pub const getLocalPreprocessingEntities_begin = ZigClangASTUnit_getLocalPreprocessingEntities_begin;
    extern fn zig_clang_astunit_get_local_preprocessing_entities_begin(*ASTUnit) PreprocessingRecord.iterator;

    pub const getLocalPreprocessingEntities_end = ZigClangASTUnit_getLocalPreprocessingEntities_end;
    extern fn zig_clang_astunit_get_local_preprocessing_entities_end(*ASTUnit) PreprocessingRecord.iterator;
};

pub const ArraySubscriptExpr = opaque {
    pub const getBase = ZigClangArraySubscriptExpr_getBase;
    extern fn zig_clang_array_subscript_expr_get_base(*const ArraySubscriptExpr) *const Expr;

    pub const getIdx = ZigClangArraySubscriptExpr_getIdx;
    extern fn zig_clang_array_subscript_expr_get_idx(*const ArraySubscriptExpr) *const Expr;
};

pub const ArrayType = opaque {
    pub const getElementType = ZigClangArrayType_getElementType;
    extern fn zig_clang_array_type_get_element_type(*const ArrayType) QualType;
};

pub const ASTRecordLayout = opaque {
    pub const getFieldOffset = ZigClangASTRecordLayout_getFieldOffset;
    extern fn zig_clang_astrecord_layout_get_field_offset(*const ASTRecordLayout, c_uint) u64;

    pub const getAlignment = ZigClangASTRecordLayout_getAlignment;
    extern fn zig_clang_astrecord_layout_get_alignment(*const ASTRecordLayout) i64;
};

pub const AttributedType = opaque {
    pub const getEquivalentType = ZigClangAttributedType_getEquivalentType;
    extern fn zig_clang_attributed_type_get_equivalent_type(*const AttributedType) QualType;
};

pub const BinaryOperator = opaque {
    pub const getOpcode = ZigClangBinaryOperator_getOpcode;
    extern fn zig_clang_binary_operator_get_opcode(*const BinaryOperator) BO;

    pub const getBeginLoc = ZigClangBinaryOperator_getBeginLoc;
    extern fn zig_clang_binary_operator_get_begin_loc(*const BinaryOperator) SourceLocation;

    pub const getLHS = ZigClangBinaryOperator_getLHS;
    extern fn zig_clang_binary_operator_get_lhs(*const BinaryOperator) *const Expr;

    pub const getRHS = ZigClangBinaryOperator_getRHS;
    extern fn zig_clang_binary_operator_get_rhs(*const BinaryOperator) *const Expr;

    pub const getType = ZigClangBinaryOperator_getType;
    extern fn zig_clang_binary_operator_get_type(*const BinaryOperator) QualType;
};

pub const BinaryConditionalOperator = opaque {};

pub const BreakStmt = opaque {};

pub const BuiltinType = opaque {
    pub const getKind = ZigClangBuiltinType_getKind;
    extern fn zig_clang_builtin_type_get_kind(*const BuiltinType) BuiltinTypeKind;
};

pub const CStyleCastExpr = opaque {
    pub const getBeginLoc = ZigClangCStyleCastExpr_getBeginLoc;
    extern fn zig_clang_cstyle_cast_expr_get_begin_loc(*const CStyleCastExpr) SourceLocation;

    pub const getSubExpr = ZigClangCStyleCastExpr_getSubExpr;
    extern fn zig_clang_cstyle_cast_expr_get_sub_expr(*const CStyleCastExpr) *const Expr;

    pub const getType = ZigClangCStyleCastExpr_getType;
    extern fn zig_clang_cstyle_cast_expr_get_type(*const CStyleCastExpr) QualType;
};

pub const CallExpr = opaque {
    pub const getCallee = ZigClangCallExpr_getCallee;
    extern fn zig_clang_call_expr_get_callee(*const CallExpr) *const Expr;

    pub const getNumArgs = ZigClangCallExpr_getNumArgs;
    extern fn zig_clang_call_expr_get_num_args(*const CallExpr) c_uint;

    pub const getArgs = ZigClangCallExpr_getArgs;
    extern fn zig_clang_call_expr_get_args(*const CallExpr) [*]const *const Expr;
};

pub const CaseStmt = opaque {
    pub const getLHS = ZigClangCaseStmt_getLHS;
    extern fn zig_clang_case_stmt_get_lhs(*const CaseStmt) *const Expr;

    pub const getRHS = ZigClangCaseStmt_getRHS;
    extern fn zig_clang_case_stmt_get_rhs(*const CaseStmt) ?*const Expr;

    pub const getBeginLoc = ZigClangCaseStmt_getBeginLoc;
    extern fn zig_clang_case_stmt_get_begin_loc(*const CaseStmt) SourceLocation;

    pub const getSubStmt = ZigClangCaseStmt_getSubStmt;
    extern fn zig_clang_case_stmt_get_sub_stmt(*const CaseStmt) *const Stmt;
};

pub const CastExpr = opaque {
    pub const getCastKind = ZigClangCastExpr_getCastKind;
    extern fn zig_clang_cast_expr_get_cast_kind(*const CastExpr) CK;

    pub const getTargetFieldForToUnionCast = ZigClangCastExpr_getTargetFieldForToUnionCast;
    extern fn zig_clang_cast_expr_get_target_field_for_to_union_cast(*const CastExpr, QualType, QualType) ?*const FieldDecl;
};

pub const CharacterLiteral = opaque {
    pub const getBeginLoc = ZigClangCharacterLiteral_getBeginLoc;
    extern fn zig_clang_character_literal_get_begin_loc(*const CharacterLiteral) SourceLocation;

    pub const getKind = ZigClangCharacterLiteral_getKind;
    extern fn zig_clang_character_literal_get_kind(*const CharacterLiteral) CharacterLiteralKind;

    pub const getValue = ZigClangCharacterLiteral_getValue;
    extern fn zig_clang_character_literal_get_value(*const CharacterLiteral) c_uint;
};

pub const ChooseExpr = opaque {
    pub const getChosenSubExpr = ZigClangChooseExpr_getChosenSubExpr;
    extern fn zig_clang_choose_expr_get_chosen_sub_expr(*const ChooseExpr) *const Expr;
};

pub const CompoundAssignOperator = opaque {
    pub const getType = ZigClangCompoundAssignOperator_getType;
    extern fn zig_clang_compound_assign_operator_get_type(*const CompoundAssignOperator) QualType;

    pub const getComputationLHSType = ZigClangCompoundAssignOperator_getComputationLHSType;
    extern fn zig_clang_compound_assign_operator_get_computation_lhstype(*const CompoundAssignOperator) QualType;

    pub const getComputationResultType = ZigClangCompoundAssignOperator_getComputationResultType;
    extern fn zig_clang_compound_assign_operator_get_computation_result_type(*const CompoundAssignOperator) QualType;

    pub const getBeginLoc = ZigClangCompoundAssignOperator_getBeginLoc;
    extern fn zig_clang_compound_assign_operator_get_begin_loc(*const CompoundAssignOperator) SourceLocation;

    pub const getOpcode = ZigClangCompoundAssignOperator_getOpcode;
    extern fn zig_clang_compound_assign_operator_get_opcode(*const CompoundAssignOperator) BO;

    pub const getLHS = ZigClangCompoundAssignOperator_getLHS;
    extern fn zig_clang_compound_assign_operator_get_lhs(*const CompoundAssignOperator) *const Expr;

    pub const getRHS = ZigClangCompoundAssignOperator_getRHS;
    extern fn zig_clang_compound_assign_operator_get_rhs(*const CompoundAssignOperator) *const Expr;
};

pub const CompoundLiteralExpr = opaque {
    pub const getInitializer = ZigClangCompoundLiteralExpr_getInitializer;
    extern fn zig_clang_compound_literal_expr_get_initializer(*const CompoundLiteralExpr) *const Expr;
};

pub const CompoundStmt = opaque {
    pub const body_begin = ZigClangCompoundStmt_body_begin;
    extern fn zig_clang_compound_stmt_body_begin(*const CompoundStmt) ConstBodyIterator;

    pub const body_end = ZigClangCompoundStmt_body_end;
    extern fn zig_clang_compound_stmt_body_end(*const CompoundStmt) ConstBodyIterator;

    pub const ConstBodyIterator = [*]const *Stmt;
};

pub const ConditionalOperator = opaque {};

pub const ConstantArrayType = opaque {
    pub const getElementType = ZigClangConstantArrayType_getElementType;
    extern fn zig_clang_constant_array_type_get_element_type(*const ConstantArrayType) QualType;

    pub const getSize = ZigClangConstantArrayType_getSize;
    extern fn zig_clang_constant_array_type_get_size(*const ConstantArrayType) *const APInt;
};

pub const ConstantExpr = opaque {};

pub const ContinueStmt = opaque {};

pub const ConvertVectorExpr = opaque {
    pub const getSrcExpr = ZigClangConvertVectorExpr_getSrcExpr;
    extern fn zig_clang_convert_vector_expr_get_src_expr(*const ConvertVectorExpr) *const Expr;

    pub const getTypeSourceInfo_getType = ZigClangConvertVectorExpr_getTypeSourceInfo_getType;
    extern fn zig_clang_convert_vector_expr_get_type_source_info_get_type(*const ConvertVectorExpr) QualType;
};

pub const DecayedType = opaque {
    pub const getDecayedType = ZigClangDecayedType_getDecayedType;
    extern fn zig_clang_decayed_type_get_decayed_type(*const DecayedType) QualType;
};

pub const Decl = opaque {
    pub const getLocation = ZigClangDecl_getLocation;
    extern fn zig_clang_decl_get_location(*const Decl) SourceLocation;

    pub const castToNamedDecl = ZigClangDecl_castToNamedDecl;
    extern fn zig_clang_decl_cast_to_named_decl(decl: *const Decl) ?*const NamedDecl;

    pub const getKind = ZigClangDecl_getKind;
    extern fn zig_clang_decl_get_kind(decl: *const Decl) DeclKind;

    pub const getDeclKindName = ZigClangDecl_getDeclKindName;
    extern fn zig_clang_decl_get_decl_kind_name(decl: *const Decl) [*:0]const u8;
};

pub const DeclRefExpr = opaque {
    pub const getDecl = ZigClangDeclRefExpr_getDecl;
    extern fn zig_clang_decl_ref_expr_get_decl(*const DeclRefExpr) *const ValueDecl;

    pub const getFoundDecl = ZigClangDeclRefExpr_getFoundDecl;
    extern fn zig_clang_decl_ref_expr_get_found_decl(*const DeclRefExpr) *const NamedDecl;
};

pub const DeclStmt = opaque {
    pub const decl_begin = ZigClangDeclStmt_decl_begin;
    extern fn zig_clang_decl_stmt_decl_begin(*const DeclStmt) const_decl_iterator;

    pub const decl_end = ZigClangDeclStmt_decl_end;
    extern fn zig_clang_decl_stmt_decl_end(*const DeclStmt) const_decl_iterator;

    pub const const_decl_iterator = [*]const *Decl;
};

pub const DefaultStmt = opaque {
    pub const getSubStmt = ZigClangDefaultStmt_getSubStmt;
    extern fn zig_clang_default_stmt_get_sub_stmt(*const DefaultStmt) *const Stmt;
};

pub const DiagnosticOptions = opaque {};

pub const DiagnosticsEngine = opaque {};

pub const DoStmt = opaque {
    pub const getCond = ZigClangDoStmt_getCond;
    extern fn zig_clang_do_stmt_get_cond(*const DoStmt) *const Expr;

    pub const getBody = ZigClangDoStmt_getBody;
    extern fn zig_clang_do_stmt_get_body(*const DoStmt) *const Stmt;
};

pub const ElaboratedType = opaque {
    pub const getNamedType = ZigClangElaboratedType_getNamedType;
    extern fn zig_clang_elaborated_type_get_named_type(*const ElaboratedType) QualType;
};

pub const EnumConstantDecl = opaque {
    pub const getInitVal = ZigClangEnumConstantDecl_getInitVal;
    extern fn zig_clang_enum_constant_decl_get_init_val(*const EnumConstantDecl) *const APSInt;
};

pub const EnumDecl = opaque {
    pub const getCanonicalDecl = ZigClangEnumDecl_getCanonicalDecl;
    extern fn zig_clang_enum_decl_get_canonical_decl(*const EnumDecl) ?*const TagDecl;

    pub const getIntegerType = ZigClangEnumDecl_getIntegerType;
    extern fn zig_clang_enum_decl_get_integer_type(*const EnumDecl) QualType;

    pub const getDefinition = ZigClangEnumDecl_getDefinition;
    extern fn zig_clang_enum_decl_get_definition(*const EnumDecl) ?*const EnumDecl;

    pub const getLocation = ZigClangEnumDecl_getLocation;
    extern fn zig_clang_enum_decl_get_location(*const EnumDecl) SourceLocation;

    pub const enumerator_begin = ZigClangEnumDecl_enumerator_begin;
    extern fn zig_clang_enum_decl_enumerator_begin(*const EnumDecl) enumerator_iterator;

    pub const enumerator_end = ZigClangEnumDecl_enumerator_end;
    extern fn zig_clang_enum_decl_enumerator_end(*const EnumDecl) enumerator_iterator;

    pub const enumerator_iterator = extern struct {
        ptr: *anyopaque,

        pub const next = ZigClangEnumDecl_enumerator_iterator_next;
        extern fn zig_clang_enum_decl_enumerator_iterator_next(enumerator_iterator) enumerator_iterator;

        pub const deref = ZigClangEnumDecl_enumerator_iterator_deref;
        extern fn zig_clang_enum_decl_enumerator_iterator_deref(enumerator_iterator) *const EnumConstantDecl;

        pub const neq = ZigClangEnumDecl_enumerator_iterator_neq;
        extern fn zig_clang_enum_decl_enumerator_iterator_neq(enumerator_iterator, enumerator_iterator) bool;
    };
};

pub const EnumType = opaque {
    pub const getDecl = ZigClangEnumType_getDecl;
    extern fn zig_clang_enum_type_get_decl(*const EnumType) *const EnumDecl;
};

pub const Expr = opaque {
    pub const getStmtClass = ZigClangExpr_getStmtClass;
    extern fn zig_clang_expr_get_stmt_class(*const Expr) StmtClass;

    pub const getType = ZigClangExpr_getType;
    extern fn zig_clang_expr_get_type(*const Expr) QualType;

    pub const getBeginLoc = ZigClangExpr_getBeginLoc;
    extern fn zig_clang_expr_get_begin_loc(*const Expr) SourceLocation;

    pub const evaluateAsConstantExpr = ZigClangExpr_EvaluateAsConstantExpr;
    extern fn zig_clang_expr_evaluate_as_constant_expr(*const Expr, *ExprEvalResult, Expr_ConstantExprKind, *const ASTContext) bool;

    pub const castToStringLiteral = ZigClangExpr_castToStringLiteral;
    extern fn zig_clang_expr_cast_to_string_literal(*const Expr) ?*const StringLiteral;
};

pub const FieldDecl = opaque {
    pub const getCanonicalDecl = ZigClangFieldDecl_getCanonicalDecl;
    extern fn zig_clang_field_decl_get_canonical_decl(*const FieldDecl) ?*const FieldDecl;

    pub const getAlignedAttribute = ZigClangFieldDecl_getAlignedAttribute;
    extern fn zig_clang_field_decl_get_aligned_attribute(*const FieldDecl, *const ASTContext) c_uint;

    pub const getPackedAttribute = ZigClangFieldDecl_getPackedAttribute;
    extern fn zig_clang_field_decl_get_packed_attribute(*const FieldDecl) bool;

    pub const isAnonymousStructOrUnion = ZigClangFieldDecl_isAnonymousStructOrUnion;
    extern fn zig_clang_field_decl_is_anonymous_struct_or_union(*const FieldDecl) bool;

    pub const isBitField = ZigClangFieldDecl_isBitField;
    extern fn zig_clang_field_decl_is_bit_field(*const FieldDecl) bool;

    pub const getType = ZigClangFieldDecl_getType;
    extern fn zig_clang_field_decl_get_type(*const FieldDecl) QualType;

    pub const getLocation = ZigClangFieldDecl_getLocation;
    extern fn zig_clang_field_decl_get_location(*const FieldDecl) SourceLocation;

    pub const getParent = ZigClangFieldDecl_getParent;
    extern fn zig_clang_field_decl_get_parent(*const FieldDecl) ?*const RecordDecl;

    pub const getFieldIndex = ZigClangFieldDecl_getFieldIndex;
    extern fn zig_clang_field_decl_get_field_index(*const FieldDecl) c_uint;
};

pub const FileID = opaque {};

pub const FloatingLiteral = opaque {
    pub const getValueAsApproximateDouble = ZigClangFloatingLiteral_getValueAsApproximateDouble;
    extern fn zig_clang_floating_literal_get_value_as_approximate_double(*const FloatingLiteral) f64;

    pub const getValueAsApproximateQuadBits = ZigClangFloatingLiteral_getValueAsApproximateQuadBits;
    extern fn zig_clang_floating_literal_get_value_as_approximate_quad_bits(*const FloatingLiteral, low: *u64, high: *u64) void;

    pub const getBeginLoc = ZigClangFloatingLiteral_getBeginLoc;
    extern fn zig_clang_floating_literal_get_begin_loc(*const FloatingLiteral) SourceLocation;

    pub const getRawSemantics = ZigClangFloatingLiteral_getRawSemantics;
    extern fn zig_clang_floating_literal_get_raw_semantics(*const FloatingLiteral) APFloatBaseSemantics;
};

pub const ForStmt = opaque {
    pub const getInit = ZigClangForStmt_getInit;
    extern fn zig_clang_for_stmt_get_init(*const ForStmt) ?*const Stmt;

    pub const getCond = ZigClangForStmt_getCond;
    extern fn zig_clang_for_stmt_get_cond(*const ForStmt) ?*const Expr;

    pub const getInc = ZigClangForStmt_getInc;
    extern fn zig_clang_for_stmt_get_inc(*const ForStmt) ?*const Expr;

    pub const getBody = ZigClangForStmt_getBody;
    extern fn zig_clang_for_stmt_get_body(*const ForStmt) *const Stmt;
};

pub const FullSourceLoc = opaque {};

pub const FunctionDecl = opaque {
    pub const getType = ZigClangFunctionDecl_getType;
    extern fn zig_clang_function_decl_get_type(*const FunctionDecl) QualType;

    pub const getLocation = ZigClangFunctionDecl_getLocation;
    extern fn zig_clang_function_decl_get_location(*const FunctionDecl) SourceLocation;

    pub const hasBody = ZigClangFunctionDecl_hasBody;
    extern fn zig_clang_function_decl_has_body(*const FunctionDecl) bool;

    pub const getStorageClass = ZigClangFunctionDecl_getStorageClass;
    extern fn zig_clang_function_decl_get_storage_class(*const FunctionDecl) StorageClass;

    pub const getParamDecl = ZigClangFunctionDecl_getParamDecl;
    extern fn zig_clang_function_decl_get_param_decl(*const FunctionDecl, i: c_uint) *const ParmVarDecl;

    pub const getBody = ZigClangFunctionDecl_getBody;
    extern fn zig_clang_function_decl_get_body(*const FunctionDecl) *const Stmt;

    pub const doesDeclarationForceExternallyVisibleDefinition = ZigClangFunctionDecl_doesDeclarationForceExternallyVisibleDefinition;
    extern fn zig_clang_function_decl_does_declaration_force_externally_visible_definition(*const FunctionDecl) bool;

    pub const isThisDeclarationADefinition = ZigClangFunctionDecl_isThisDeclarationADefinition;
    extern fn zig_clang_function_decl_is_this_declaration_adefinition(*const FunctionDecl) bool;

    pub const doesThisDeclarationHaveABody = ZigClangFunctionDecl_doesThisDeclarationHaveABody;
    extern fn zig_clang_function_decl_does_this_declaration_have_abody(*const FunctionDecl) bool;

    pub const isInlineSpecified = ZigClangFunctionDecl_isInlineSpecified;
    extern fn zig_clang_function_decl_is_inline_specified(*const FunctionDecl) bool;

    pub const hasAlwaysInlineAttr = ZigClangFunctionDecl_hasAlwaysInlineAttr;
    extern fn zig_clang_function_decl_has_always_inline_attr(*const FunctionDecl) bool;

    pub const isDefined = ZigClangFunctionDecl_isDefined;
    extern fn zig_clang_function_decl_is_defined(*const FunctionDecl) bool;

    pub const getDefinition = ZigClangFunctionDecl_getDefinition;
    extern fn zig_clang_function_decl_get_definition(*const FunctionDecl) ?*const FunctionDecl;

    pub const getSectionAttribute = ZigClangFunctionDecl_getSectionAttribute;
    extern fn zig_clang_function_decl_get_section_attribute(*const FunctionDecl, len: *usize) ?[*]const u8;

    pub const getCanonicalDecl = ZigClangFunctionDecl_getCanonicalDecl;
    extern fn zig_clang_function_decl_get_canonical_decl(*const FunctionDecl) ?*const FunctionDecl;

    pub const getAlignedAttribute = ZigClangFunctionDecl_getAlignedAttribute;
    extern fn zig_clang_function_decl_get_aligned_attribute(*const FunctionDecl, *const ASTContext) c_uint;
};

pub const FunctionProtoType = opaque {
    pub const isVariadic = ZigClangFunctionProtoType_isVariadic;
    extern fn zig_clang_function_proto_type_is_variadic(*const FunctionProtoType) bool;

    pub const getNumParams = ZigClangFunctionProtoType_getNumParams;
    extern fn zig_clang_function_proto_type_get_num_params(*const FunctionProtoType) c_uint;

    pub const getParamType = ZigClangFunctionProtoType_getParamType;
    extern fn zig_clang_function_proto_type_get_param_type(*const FunctionProtoType, i: c_uint) QualType;

    pub const getReturnType = ZigClangFunctionProtoType_getReturnType;
    extern fn zig_clang_function_proto_type_get_return_type(*const FunctionProtoType) QualType;
};

pub const FunctionType = opaque {
    pub const getNoReturnAttr = ZigClangFunctionType_getNoReturnAttr;
    extern fn zig_clang_function_type_get_no_return_attr(*const FunctionType) bool;

    pub const getCallConv = ZigClangFunctionType_getCallConv;
    extern fn zig_clang_function_type_get_call_conv(*const FunctionType) CallingConv;

    pub const getReturnType = ZigClangFunctionType_getReturnType;
    extern fn zig_clang_function_type_get_return_type(*const FunctionType) QualType;
};

pub const GenericSelectionExpr = opaque {
    pub const getResultExpr = ZigClangGenericSelectionExpr_getResultExpr;
    extern fn zig_clang_generic_selection_expr_get_result_expr(*const GenericSelectionExpr) *const Expr;
};

pub const IfStmt = opaque {
    pub const getThen = ZigClangIfStmt_getThen;
    extern fn zig_clang_if_stmt_get_then(*const IfStmt) *const Stmt;

    pub const getElse = ZigClangIfStmt_getElse;
    extern fn zig_clang_if_stmt_get_else(*const IfStmt) ?*const Stmt;

    pub const getCond = ZigClangIfStmt_getCond;
    extern fn zig_clang_if_stmt_get_cond(*const IfStmt) *const Stmt;
};

pub const ImplicitCastExpr = opaque {
    pub const getBeginLoc = ZigClangImplicitCastExpr_getBeginLoc;
    extern fn zig_clang_implicit_cast_expr_get_begin_loc(*const ImplicitCastExpr) SourceLocation;

    pub const getCastKind = ZigClangImplicitCastExpr_getCastKind;
    extern fn zig_clang_implicit_cast_expr_get_cast_kind(*const ImplicitCastExpr) CK;

    pub const getSubExpr = ZigClangImplicitCastExpr_getSubExpr;
    extern fn zig_clang_implicit_cast_expr_get_sub_expr(*const ImplicitCastExpr) *const Expr;
};

pub const IncompleteArrayType = opaque {
    pub const getElementType = ZigClangIncompleteArrayType_getElementType;
    extern fn zig_clang_incomplete_array_type_get_element_type(*const IncompleteArrayType) QualType;
};

pub const IntegerLiteral = opaque {
    pub const EvaluateAsInt = ZigClangIntegerLiteral_EvaluateAsInt;
    extern fn zig_clang_integer_literal_evaluate_as_int(*const IntegerLiteral, *ExprEvalResult, *const ASTContext) bool;

    pub const getBeginLoc = ZigClangIntegerLiteral_getBeginLoc;
    extern fn zig_clang_integer_literal_get_begin_loc(*const IntegerLiteral) SourceLocation;

    pub const getSignum = ZigClangIntegerLiteral_getSignum;
    extern fn zig_clang_integer_literal_get_signum(*const IntegerLiteral, *c_int, *const ASTContext) bool;
};

/// This is just used as a namespace for a static method on clang's Lexer class; we don't directly
/// deal with Lexer objects
pub const Lexer = struct {
    pub const getLocForEndOfToken = ZigClangLexer_getLocForEndOfToken;
    extern fn zig_clang_lexer_get_loc_for_end_of_token(SourceLocation, *const SourceManager, *const ASTUnit) SourceLocation;
};

pub const MacroDefinitionRecord = opaque {
    pub const getName_getNameStart = ZigClangMacroDefinitionRecord_getName_getNameStart;
    extern fn zig_clang_macro_definition_record_get_name_get_name_start(*const MacroDefinitionRecord) [*:0]const u8;

    pub const getSourceRange_getBegin = ZigClangMacroDefinitionRecord_getSourceRange_getBegin;
    extern fn zig_clang_macro_definition_record_get_source_range_get_begin(*const MacroDefinitionRecord) SourceLocation;

    pub const getSourceRange_getEnd = ZigClangMacroDefinitionRecord_getSourceRange_getEnd;
    extern fn zig_clang_macro_definition_record_get_source_range_get_end(*const MacroDefinitionRecord) SourceLocation;
};

pub const MacroQualifiedType = opaque {
    pub const getModifiedType = ZigClangMacroQualifiedType_getModifiedType;
    extern fn zig_clang_macro_qualified_type_get_modified_type(*const MacroQualifiedType) QualType;
};

pub const TypeOfType = opaque {
    pub const getUnmodifiedType = ZigClangTypeOfType_getUnmodifiedType;
    extern fn zig_clang_type_of_type_get_unmodified_type(*const TypeOfType) QualType;
};

pub const TypeOfExprType = opaque {
    pub const getUnderlyingExpr = ZigClangTypeOfExprType_getUnderlyingExpr;
    extern fn zig_clang_type_of_expr_type_get_underlying_expr(*const TypeOfExprType) *const Expr;
};

pub const OffsetOfNode = opaque {
    pub const getKind = ZigClangOffsetOfNode_getKind;
    extern fn zig_clang_offset_of_node_get_kind(*const OffsetOfNode) OffsetOfNode_Kind;

    pub const getArrayExprIndex = ZigClangOffsetOfNode_getArrayExprIndex;
    extern fn zig_clang_offset_of_node_get_array_expr_index(*const OffsetOfNode) c_uint;

    pub const getField = ZigClangOffsetOfNode_getField;
    extern fn zig_clang_offset_of_node_get_field(*const OffsetOfNode) *FieldDecl;
};

pub const OffsetOfExpr = opaque {
    pub const getNumComponents = ZigClangOffsetOfExpr_getNumComponents;
    extern fn zig_clang_offset_of_expr_get_num_components(*const OffsetOfExpr) c_uint;

    pub const getNumExpressions = ZigClangOffsetOfExpr_getNumExpressions;
    extern fn zig_clang_offset_of_expr_get_num_expressions(*const OffsetOfExpr) c_uint;

    pub const getIndexExpr = ZigClangOffsetOfExpr_getIndexExpr;
    extern fn zig_clang_offset_of_expr_get_index_expr(*const OffsetOfExpr, idx: c_uint) *const Expr;

    pub const getComponent = ZigClangOffsetOfExpr_getComponent;
    extern fn zig_clang_offset_of_expr_get_component(*const OffsetOfExpr, idx: c_uint) *const OffsetOfNode;

    pub const getBeginLoc = ZigClangOffsetOfExpr_getBeginLoc;
    extern fn zig_clang_offset_of_expr_get_begin_loc(*const OffsetOfExpr) SourceLocation;
};

pub const MemberExpr = opaque {
    pub const getBase = ZigClangMemberExpr_getBase;
    extern fn zig_clang_member_expr_get_base(*const MemberExpr) *const Expr;

    pub const isArrow = ZigClangMemberExpr_isArrow;
    extern fn zig_clang_member_expr_is_arrow(*const MemberExpr) bool;

    pub const getMemberDecl = ZigClangMemberExpr_getMemberDecl;
    extern fn zig_clang_member_expr_get_member_decl(*const MemberExpr) *const ValueDecl;
};

pub const NamedDecl = opaque {
    pub const getName_bytes_begin = ZigClangNamedDecl_getName_bytes_begin;
    extern fn zig_clang_named_decl_get_name_bytes_begin(decl: *const NamedDecl) [*:0]const u8;
};

pub const None = opaque {};

pub const OpaqueValueExpr = opaque {
    pub const getSourceExpr = ZigClangOpaqueValueExpr_getSourceExpr;
    extern fn zig_clang_opaque_value_expr_get_source_expr(*const OpaqueValueExpr) ?*const Expr;
};

pub const PCHContainerOperations = opaque {};

pub const ParenExpr = opaque {
    pub const getSubExpr = ZigClangParenExpr_getSubExpr;
    extern fn zig_clang_paren_expr_get_sub_expr(*const ParenExpr) *const Expr;
};

pub const ParenType = opaque {
    pub const getInnerType = ZigClangParenType_getInnerType;
    extern fn zig_clang_paren_type_get_inner_type(*const ParenType) QualType;
};

pub const ParmVarDecl = opaque {
    pub const getOriginalType = ZigClangParmVarDecl_getOriginalType;
    extern fn zig_clang_parm_var_decl_get_original_type(*const ParmVarDecl) QualType;
};

pub const PointerType = opaque {};

pub const PredefinedExpr = opaque {
    pub const getFunctionName = ZigClangPredefinedExpr_getFunctionName;
    extern fn zig_clang_predefined_expr_get_function_name(*const PredefinedExpr) *const StringLiteral;
};

pub const PreprocessedEntity = opaque {
    pub const getKind = ZigClangPreprocessedEntity_getKind;
    extern fn zig_clang_preprocessed_entity_get_kind(*const PreprocessedEntity) PreprocessedEntity_EntityKind;
};

pub const PreprocessingRecord = opaque {
    pub const iterator = extern struct {
        I: c_int,
        Self: *PreprocessingRecord,

        pub const deref = ZigClangPreprocessingRecord_iterator_deref;
        extern fn zig_clang_preprocessing_record_iterator_deref(iterator) *PreprocessedEntity;
    };
};

pub const RecordDecl = opaque {
    pub const getCanonicalDecl = ZigClangRecordDecl_getCanonicalDecl;
    extern fn zig_clang_record_decl_get_canonical_decl(*const RecordDecl) ?*const TagDecl;

    pub const isUnion = ZigClangRecordDecl_isUnion;
    extern fn zig_clang_record_decl_is_union(*const RecordDecl) bool;

    pub const isStruct = ZigClangRecordDecl_isStruct;
    extern fn zig_clang_record_decl_is_struct(*const RecordDecl) bool;

    pub const isAnonymousStructOrUnion = ZigClangRecordDecl_isAnonymousStructOrUnion;
    extern fn zig_clang_record_decl_is_anonymous_struct_or_union(record_decl: ?*const RecordDecl) bool;

    pub const getPackedAttribute = ZigClangRecordDecl_getPackedAttribute;
    extern fn zig_clang_record_decl_get_packed_attribute(*const RecordDecl) bool;

    pub const getDefinition = ZigClangRecordDecl_getDefinition;
    extern fn zig_clang_record_decl_get_definition(*const RecordDecl) ?*const RecordDecl;

    pub const getLocation = ZigClangRecordDecl_getLocation;
    extern fn zig_clang_record_decl_get_location(*const RecordDecl) SourceLocation;

    pub const getASTRecordLayout = ZigClangRecordDecl_getASTRecordLayout;
    extern fn zig_clang_record_decl_get_astrecord_layout(*const RecordDecl, *const ASTContext) *const ASTRecordLayout;

    pub const field_begin = ZigClangRecordDecl_field_begin;
    extern fn zig_clang_record_decl_field_begin(*const RecordDecl) field_iterator;

    pub const field_end = ZigClangRecordDecl_field_end;
    extern fn zig_clang_record_decl_field_end(*const RecordDecl) field_iterator;

    pub const field_iterator = extern struct {
        ptr: *anyopaque,

        pub const next = ZigClangRecordDecl_field_iterator_next;
        extern fn zig_clang_record_decl_field_iterator_next(field_iterator) field_iterator;

        pub const deref = ZigClangRecordDecl_field_iterator_deref;
        extern fn zig_clang_record_decl_field_iterator_deref(field_iterator) *const FieldDecl;

        pub const neq = ZigClangRecordDecl_field_iterator_neq;
        extern fn zig_clang_record_decl_field_iterator_neq(field_iterator, field_iterator) bool;
    };
};

pub const RecordType = opaque {
    pub const getDecl = ZigClangRecordType_getDecl;
    extern fn zig_clang_record_type_get_decl(*const RecordType) *const RecordDecl;
};

pub const ReturnStmt = opaque {
    pub const getRetValue = ZigClangReturnStmt_getRetValue;
    extern fn zig_clang_return_stmt_get_ret_value(*const ReturnStmt) ?*const Expr;
};

pub const ShuffleVectorExpr = opaque {
    pub const getNumSubExprs = ZigClangShuffleVectorExpr_getNumSubExprs;
    extern fn zig_clang_shuffle_vector_expr_get_num_sub_exprs(*const ShuffleVectorExpr) c_uint;

    pub const getExpr = ZigClangShuffleVectorExpr_getExpr;
    extern fn zig_clang_shuffle_vector_expr_get_expr(*const ShuffleVectorExpr, c_uint) *const Expr;
};

pub const SourceManager = opaque {
    pub const getSpellingLoc = ZigClangSourceManager_getSpellingLoc;
    extern fn zig_clang_source_manager_get_spelling_loc(*const SourceManager, Loc: SourceLocation) SourceLocation;

    pub const getFilename = ZigClangSourceManager_getFilename;
    extern fn zig_clang_source_manager_get_filename(*const SourceManager, SpellingLoc: SourceLocation) ?[*:0]const u8;

    pub const getSpellingLineNumber = ZigClangSourceManager_getSpellingLineNumber;
    extern fn zig_clang_source_manager_get_spelling_line_number(*const SourceManager, Loc: SourceLocation) c_uint;

    pub const getSpellingColumnNumber = ZigClangSourceManager_getSpellingColumnNumber;
    extern fn zig_clang_source_manager_get_spelling_column_number(*const SourceManager, Loc: SourceLocation) c_uint;

    pub const getCharacterData = ZigClangSourceManager_getCharacterData;
    extern fn zig_clang_source_manager_get_character_data(*const SourceManager, SL: SourceLocation) [*:0]const u8;
};

pub const SourceRange = opaque {};

pub const Stmt = opaque {
    pub const getBeginLoc = ZigClangStmt_getBeginLoc;
    extern fn zig_clang_stmt_get_begin_loc(*const Stmt) SourceLocation;

    pub const getStmtClass = ZigClangStmt_getStmtClass;
    extern fn zig_clang_stmt_get_stmt_class(*const Stmt) StmtClass;

    pub const classof_Expr = ZigClangStmt_classof_Expr;
    extern fn zig_clang_stmt_classof_expr(*const Stmt) bool;
};

pub const StmtExpr = opaque {
    pub const getSubStmt = ZigClangStmtExpr_getSubStmt;
    extern fn zig_clang_stmt_expr_get_sub_stmt(*const StmtExpr) *const CompoundStmt;
};

pub const StringLiteral = opaque {
    pub const getKind = ZigClangStringLiteral_getKind;
    extern fn zig_clang_string_literal_get_kind(*const StringLiteral) CharacterLiteralKind;

    pub const getCodeUnit = ZigClangStringLiteral_getCodeUnit;
    extern fn zig_clang_string_literal_get_code_unit(*const StringLiteral, usize) u32;

    pub const getLength = ZigClangStringLiteral_getLength;
    extern fn zig_clang_string_literal_get_length(*const StringLiteral) c_uint;

    pub const getCharByteWidth = ZigClangStringLiteral_getCharByteWidth;
    extern fn zig_clang_string_literal_get_char_byte_width(*const StringLiteral) c_uint;

    pub const getString_bytes_begin_size = ZigClangStringLiteral_getString_bytes_begin_size;
    extern fn zig_clang_string_literal_get_string_bytes_begin_size(*const StringLiteral, *usize) [*]const u8;
};

pub const StringRef = opaque {};

pub const SwitchStmt = opaque {
    pub const getConditionVariableDeclStmt = ZigClangSwitchStmt_getConditionVariableDeclStmt;
    extern fn zig_clang_switch_stmt_get_condition_variable_decl_stmt(*const SwitchStmt) ?*const DeclStmt;

    pub const getCond = ZigClangSwitchStmt_getCond;
    extern fn zig_clang_switch_stmt_get_cond(*const SwitchStmt) *const Expr;

    pub const getBody = ZigClangSwitchStmt_getBody;
    extern fn zig_clang_switch_stmt_get_body(*const SwitchStmt) *const Stmt;

    pub const isAllEnumCasesCovered = ZigClangSwitchStmt_isAllEnumCasesCovered;
    extern fn zig_clang_switch_stmt_is_all_enum_cases_covered(*const SwitchStmt) bool;
};

pub const TagDecl = opaque {
    pub const isThisDeclarationADefinition = ZigClangTagDecl_isThisDeclarationADefinition;
    extern fn zig_clang_tag_decl_is_this_declaration_adefinition(*const TagDecl) bool;
};

pub const Type = opaque {
    pub const getTypeClass = ZigClangType_getTypeClass;
    extern fn zig_clang_type_get_type_class(*const Type) TypeClass;

    pub const getPointeeType = ZigClangType_getPointeeType;
    extern fn zig_clang_type_get_pointee_type(*const Type) QualType;

    pub const isVoidType = ZigClangType_isVoidType;
    extern fn zig_clang_type_is_void_type(*const Type) bool;

    pub const isConstantArrayType = ZigClangType_isConstantArrayType;
    extern fn zig_clang_type_is_constant_array_type(*const Type) bool;

    pub const isRecordType = ZigClangType_isRecordType;
    extern fn zig_clang_type_is_record_type(*const Type) bool;

    pub const isVectorType = ZigClangType_isVectorType;
    extern fn zig_clang_type_is_vector_type(*const Type) bool;

    pub const isIncompleteOrZeroLengthArrayType = ZigClangType_isIncompleteOrZeroLengthArrayType;
    extern fn zig_clang_type_is_incomplete_or_zero_length_array_type(*const Type, *const ASTContext) bool;

    pub const isArrayType = ZigClangType_isArrayType;
    extern fn zig_clang_type_is_array_type(*const Type) bool;

    pub const isBooleanType = ZigClangType_isBooleanType;
    extern fn zig_clang_type_is_boolean_type(*const Type) bool;

    pub const getTypeClassName = ZigClangType_getTypeClassName;
    extern fn zig_clang_type_get_type_class_name(*const Type) [*:0]const u8;

    pub const getAsArrayTypeUnsafe = ZigClangType_getAsArrayTypeUnsafe;
    extern fn zig_clang_type_get_as_array_type_unsafe(*const Type) *const ArrayType;

    pub const getAsRecordType = ZigClangType_getAsRecordType;
    extern fn zig_clang_type_get_as_record_type(*const Type) ?*const RecordType;

    pub const getAsUnionType = ZigClangType_getAsUnionType;
    extern fn zig_clang_type_get_as_union_type(*const Type) ?*const RecordType;
};

pub const TypedefNameDecl = opaque {
    pub const getUnderlyingType = ZigClangTypedefNameDecl_getUnderlyingType;
    extern fn zig_clang_typedef_name_decl_get_underlying_type(*const TypedefNameDecl) QualType;

    pub const getCanonicalDecl = ZigClangTypedefNameDecl_getCanonicalDecl;
    extern fn zig_clang_typedef_name_decl_get_canonical_decl(*const TypedefNameDecl) ?*const TypedefNameDecl;

    pub const getLocation = ZigClangTypedefNameDecl_getLocation;
    extern fn zig_clang_typedef_name_decl_get_location(*const TypedefNameDecl) SourceLocation;
};

pub const FileScopeAsmDecl = opaque {
    pub const getAsmString = ZigClangFileScopeAsmDecl_getAsmString;
    extern fn zig_clang_file_scope_asm_decl_get_asm_string(*const FileScopeAsmDecl) *const StringLiteral;
};

pub const TypedefType = opaque {
    pub const getDecl = ZigClangTypedefType_getDecl;
    extern fn zig_clang_typedef_type_get_decl(*const TypedefType) *const TypedefNameDecl;
};

pub const UnaryExprOrTypeTraitExpr = opaque {
    pub const getTypeOfArgument = ZigClangUnaryExprOrTypeTraitExpr_getTypeOfArgument;
    extern fn zig_clang_unary_expr_or_type_trait_expr_get_type_of_argument(*const UnaryExprOrTypeTraitExpr) QualType;

    pub const getBeginLoc = ZigClangUnaryExprOrTypeTraitExpr_getBeginLoc;
    extern fn zig_clang_unary_expr_or_type_trait_expr_get_begin_loc(*const UnaryExprOrTypeTraitExpr) SourceLocation;

    pub const getKind = ZigClangUnaryExprOrTypeTraitExpr_getKind;
    extern fn zig_clang_unary_expr_or_type_trait_expr_get_kind(*const UnaryExprOrTypeTraitExpr) UnaryExprOrTypeTrait_Kind;
};

pub const UnaryOperator = opaque {
    pub const getOpcode = ZigClangUnaryOperator_getOpcode;
    extern fn zig_clang_unary_operator_get_opcode(*const UnaryOperator) UO;

    pub const getType = ZigClangUnaryOperator_getType;
    extern fn zig_clang_unary_operator_get_type(*const UnaryOperator) QualType;

    pub const getSubExpr = ZigClangUnaryOperator_getSubExpr;
    extern fn zig_clang_unary_operator_get_sub_expr(*const UnaryOperator) *const Expr;

    pub const getBeginLoc = ZigClangUnaryOperator_getBeginLoc;
    extern fn zig_clang_unary_operator_get_begin_loc(*const UnaryOperator) SourceLocation;
};

pub const ValueDecl = opaque {
    pub const getType = ZigClangValueDecl_getType;
    extern fn zig_clang_value_decl_get_type(*const ValueDecl) QualType;
};

pub const VarDecl = opaque {
    pub const getLocation = ZigClangVarDecl_getLocation;
    extern fn zig_clang_var_decl_get_location(*const VarDecl) SourceLocation;

    pub const hasInit = ZigClangVarDecl_hasInit;
    extern fn zig_clang_var_decl_has_init(*const VarDecl) bool;

    pub const getStorageClass = ZigClangVarDecl_getStorageClass;
    extern fn zig_clang_var_decl_get_storage_class(*const VarDecl) StorageClass;

    pub const getType = ZigClangVarDecl_getType;
    extern fn zig_clang_var_decl_get_type(*const VarDecl) QualType;

    pub const getInit = ZigClangVarDecl_getInit;
    extern fn zig_clang_var_decl_get_init(*const VarDecl) ?*const Expr;

    pub const getTLSKind = ZigClangVarDecl_getTLSKind;
    extern fn zig_clang_var_decl_get_tlskind(*const VarDecl) VarDecl_TLSKind;

    pub const getCanonicalDecl = ZigClangVarDecl_getCanonicalDecl;
    extern fn zig_clang_var_decl_get_canonical_decl(*const VarDecl) ?*const VarDecl;

    pub const getSectionAttribute = ZigClangVarDecl_getSectionAttribute;
    extern fn zig_clang_var_decl_get_section_attribute(*const VarDecl, len: *usize) ?[*]const u8;

    pub const getAlignedAttribute = ZigClangVarDecl_getAlignedAttribute;
    extern fn zig_clang_var_decl_get_aligned_attribute(*const VarDecl, *const ASTContext) c_uint;

    pub const getPackedAttribute = ZigClangVarDecl_getPackedAttribute;
    extern fn zig_clang_var_decl_get_packed_attribute(*const VarDecl) bool;

    pub const getCleanupAttribute = ZigClangVarDecl_getCleanupAttribute;
    extern fn zig_clang_var_decl_get_cleanup_attribute(*const VarDecl) ?*const FunctionDecl;

    pub const getTypeSourceInfo_getType = ZigClangVarDecl_getTypeSourceInfo_getType;
    extern fn zig_clang_var_decl_get_type_source_info_get_type(*const VarDecl) QualType;

    pub const isStaticLocal = ZigClangVarDecl_isStaticLocal;
    extern fn zig_clang_var_decl_is_static_local(*const VarDecl) bool;
};

pub const VectorType = opaque {
    pub const getElementType = ZigClangVectorType_getElementType;
    extern fn zig_clang_vector_type_get_element_type(*const VectorType) QualType;

    pub const getNumElements = ZigClangVectorType_getNumElements;
    extern fn zig_clang_vector_type_get_num_elements(*const VectorType) c_uint;
};

pub const WhileStmt = opaque {
    pub const getCond = ZigClangWhileStmt_getCond;
    extern fn zig_clang_while_stmt_get_cond(*const WhileStmt) *const Expr;

    pub const getBody = ZigClangWhileStmt_getBody;
    extern fn zig_clang_while_stmt_get_body(*const WhileStmt) *const Stmt;
};

pub const InitListExpr = opaque {
    pub const getInit = ZigClangInitListExpr_getInit;
    extern fn zig_clang_init_list_expr_get_init(*const InitListExpr, i: c_uint) *const Expr;

    pub const getArrayFiller = ZigClangInitListExpr_getArrayFiller;
    extern fn zig_clang_init_list_expr_get_array_filler(*const InitListExpr) *const Expr;

    pub const hasArrayFiller = ZigClangInitListExpr_hasArrayFiller;
    extern fn zig_clang_init_list_expr_has_array_filler(*const InitListExpr) bool;

    pub const isStringLiteralInit = ZigClangInitListExpr_isStringLiteralInit;
    extern fn zig_clang_init_list_expr_is_string_literal_init(*const InitListExpr) bool;

    pub const getNumInits = ZigClangInitListExpr_getNumInits;
    extern fn zig_clang_init_list_expr_get_num_inits(*const InitListExpr) c_uint;

    pub const getInitializedFieldInUnion = ZigClangInitListExpr_getInitializedFieldInUnion;
    extern fn zig_clang_init_list_expr_get_initialized_field_in_union(*const InitListExpr) ?*FieldDecl;
};

pub const BO = enum(c_int) {
    PtrMemD,
    PtrMemI,
    Mul,
    Div,
    Rem,
    Add,
    Sub,
    Shl,
    Shr,
    Cmp,
    LT,
    GT,
    LE,
    GE,
    EQ,
    NE,
    And,
    Xor,
    Or,
    LAnd,
    LOr,
    Assign,
    MulAssign,
    DivAssign,
    RemAssign,
    AddAssign,
    SubAssign,
    ShlAssign,
    ShrAssign,
    AndAssign,
    XorAssign,
    OrAssign,
    Comma,
};

pub const UO = enum(c_int) {
    PostInc,
    PostDec,
    PreInc,
    PreDec,
    AddrOf,
    Deref,
    Plus,
    Minus,
    Not,
    LNot,
    Real,
    Imag,
    Extension,
    Coawait,
};

pub const TypeClass = enum(c_int) {
    Adjusted,
    Decayed,
    ConstantArray,
    DependentSizedArray,
    IncompleteArray,
    VariableArray,
    Atomic,
    Attributed,
    BTFTagAttributed,
    BitInt,
    BlockPointer,
    Builtin,
    Complex,
    Decltype,
    Auto,
    DeducedTemplateSpecialization,
    DependentAddressSpace,
    DependentBitInt,
    DependentName,
    DependentSizedExtVector,
    DependentTemplateSpecialization,
    DependentVector,
    Elaborated,
    FunctionNoProto,
    FunctionProto,
    InjectedClassName,
    MacroQualified,
    ConstantMatrix,
    DependentSizedMatrix,
    MemberPointer,
    ObjCObjectPointer,
    ObjCObject,
    ObjCInterface,
    ObjCTypeParam,
    PackExpansion,
    Paren,
    Pipe,
    Pointer,
    LValueReference,
    RValueReference,
    SubstTemplateTypeParmPack,
    SubstTemplateTypeParm,
    Enum,
    Record,
    TemplateSpecialization,
    TemplateTypeParm,
    TypeOfExpr,
    TypeOf,
    Typedef,
    UnaryTransform,
    UnresolvedUsing,
    Using,
    Vector,
    ExtVector,
};

const StmtClass = enum(c_int) {
    NoStmtClass,
    WhileStmtClass,
    LabelStmtClass,
    VAArgExprClass,
    UnaryOperatorClass,
    UnaryExprOrTypeTraitExprClass,
    TypoExprClass,
    TypeTraitExprClass,
    SubstNonTypeTemplateParmPackExprClass,
    SubstNonTypeTemplateParmExprClass,
    StringLiteralClass,
    StmtExprClass,
    SourceLocExprClass,
    SizeOfPackExprClass,
    ShuffleVectorExprClass,
    SYCLUniqueStableNameExprClass,
    RequiresExprClass,
    RecoveryExprClass,
    PseudoObjectExprClass,
    PredefinedExprClass,
    ParenListExprClass,
    ParenExprClass,
    PackExpansionExprClass,
    UnresolvedMemberExprClass,
    UnresolvedLookupExprClass,
    OpaqueValueExprClass,
    OffsetOfExprClass,
    ObjCSubscriptRefExprClass,
    ObjCStringLiteralClass,
    ObjCSelectorExprClass,
    ObjCProtocolExprClass,
    ObjCPropertyRefExprClass,
    ObjCMessageExprClass,
    ObjCIvarRefExprClass,
    ObjCIsaExprClass,
    ObjCIndirectCopyRestoreExprClass,
    ObjCEncodeExprClass,
    ObjCDictionaryLiteralClass,
    ObjCBoxedExprClass,
    ObjCBoolLiteralExprClass,
    ObjCAvailabilityCheckExprClass,
    ObjCArrayLiteralClass,
    OMPIteratorExprClass,
    OMPArrayShapingExprClass,
    OMPArraySectionExprClass,
    NoInitExprClass,
    MemberExprClass,
    MatrixSubscriptExprClass,
    MaterializeTemporaryExprClass,
    MSPropertySubscriptExprClass,
    MSPropertyRefExprClass,
    LambdaExprClass,
    IntegerLiteralClass,
    InitListExprClass,
    ImplicitValueInitExprClass,
    ImaginaryLiteralClass,
    GenericSelectionExprClass,
    GNUNullExprClass,
    FunctionParmPackExprClass,
    ExprWithCleanupsClass,
    ConstantExprClass,
    FloatingLiteralClass,
    FixedPointLiteralClass,
    ExtVectorElementExprClass,
    ExpressionTraitExprClass,
    DesignatedInitUpdateExprClass,
    DesignatedInitExprClass,
    DependentScopeDeclRefExprClass,
    DependentCoawaitExprClass,
    DeclRefExprClass,
    CoyieldExprClass,
    CoawaitExprClass,
    ConvertVectorExprClass,
    ConceptSpecializationExprClass,
    CompoundLiteralExprClass,
    ChooseExprClass,
    CharacterLiteralClass,
    ImplicitCastExprClass,
    ObjCBridgedCastExprClass,
    CXXStaticCastExprClass,
    CXXReinterpretCastExprClass,
    CXXDynamicCastExprClass,
    CXXConstCastExprClass,
    CXXAddrspaceCastExprClass,
    CXXFunctionalCastExprClass,
    CStyleCastExprClass,
    BuiltinBitCastExprClass,
    CallExprClass,
    UserDefinedLiteralClass,
    CXXOperatorCallExprClass,
    CXXMemberCallExprClass,
    CUDAKernelCallExprClass,
    CXXUuidofExprClass,
    CXXUnresolvedConstructExprClass,
    CXXTypeidExprClass,
    CXXThrowExprClass,
    CXXThisExprClass,
    CXXStdInitializerListExprClass,
    CXXScalarValueInitExprClass,
    CXXRewrittenBinaryOperatorClass,
    CXXPseudoDestructorExprClass,
    CXXParenListInitExprClass,
    CXXNullPtrLiteralExprClass,
    CXXNoexceptExprClass,
    CXXNewExprClass,
    CXXInheritedCtorInitExprClass,
    CXXFoldExprClass,
    CXXDependentScopeMemberExprClass,
    CXXDeleteExprClass,
    CXXDefaultInitExprClass,
    CXXDefaultArgExprClass,
    CXXConstructExprClass,
    CXXTemporaryObjectExprClass,
    CXXBoolLiteralExprClass,
    CXXBindTemporaryExprClass,
    BlockExprClass,
    BinaryOperatorClass,
    CompoundAssignOperatorClass,
    AtomicExprClass,
    AsTypeExprClass,
    ArrayTypeTraitExprClass,
    ArraySubscriptExprClass,
    ArrayInitLoopExprClass,
    ArrayInitIndexExprClass,
    AddrLabelExprClass,
    ConditionalOperatorClass,
    BinaryConditionalOperatorClass,
    AttributedStmtClass,
    SwitchStmtClass,
    DefaultStmtClass,
    CaseStmtClass,
    SEHTryStmtClass,
    SEHLeaveStmtClass,
    SEHFinallyStmtClass,
    SEHExceptStmtClass,
    ReturnStmtClass,
    ObjCForCollectionStmtClass,
    ObjCAutoreleasePoolStmtClass,
    ObjCAtTryStmtClass,
    ObjCAtThrowStmtClass,
    ObjCAtSynchronizedStmtClass,
    ObjCAtFinallyStmtClass,
    ObjCAtCatchStmtClass,
    OMPTeamsDirectiveClass,
    OMPTaskyieldDirectiveClass,
    OMPTaskwaitDirectiveClass,
    OMPTaskgroupDirectiveClass,
    OMPTaskDirectiveClass,
    OMPTargetUpdateDirectiveClass,
    OMPTargetTeamsDirectiveClass,
    OMPTargetParallelForDirectiveClass,
    OMPTargetParallelDirectiveClass,
    OMPTargetExitDataDirectiveClass,
    OMPTargetEnterDataDirectiveClass,
    OMPTargetDirectiveClass,
    OMPTargetDataDirectiveClass,
    OMPSingleDirectiveClass,
    OMPSectionsDirectiveClass,
    OMPSectionDirectiveClass,
    OMPScopeDirectiveClass,
    OMPScanDirectiveClass,
    OMPParallelSectionsDirectiveClass,
    OMPParallelMasterDirectiveClass,
    OMPParallelMaskedDirectiveClass,
    OMPParallelDirectiveClass,
    OMPOrderedDirectiveClass,
    OMPMetaDirectiveClass,
    OMPMasterDirectiveClass,
    OMPMaskedDirectiveClass,
    OMPUnrollDirectiveClass,
    OMPTileDirectiveClass,
    OMPTeamsGenericLoopDirectiveClass,
    OMPTeamsDistributeSimdDirectiveClass,
    OMPTeamsDistributeParallelForSimdDirectiveClass,
    OMPTeamsDistributeParallelForDirectiveClass,
    OMPTeamsDistributeDirectiveClass,
    OMPTaskLoopSimdDirectiveClass,
    OMPTaskLoopDirectiveClass,
    OMPTargetTeamsGenericLoopDirectiveClass,
    OMPTargetTeamsDistributeSimdDirectiveClass,
    OMPTargetTeamsDistributeParallelForSimdDirectiveClass,
    OMPTargetTeamsDistributeParallelForDirectiveClass,
    OMPTargetTeamsDistributeDirectiveClass,
    OMPTargetSimdDirectiveClass,
    OMPTargetParallelGenericLoopDirectiveClass,
    OMPTargetParallelForSimdDirectiveClass,
    OMPSimdDirectiveClass,
    OMPParallelMasterTaskLoopSimdDirectiveClass,
    OMPParallelMasterTaskLoopDirectiveClass,
    OMPParallelMaskedTaskLoopSimdDirectiveClass,
    OMPParallelMaskedTaskLoopDirectiveClass,
    OMPParallelGenericLoopDirectiveClass,
    OMPParallelForSimdDirectiveClass,
    OMPParallelForDirectiveClass,
    OMPMasterTaskLoopSimdDirectiveClass,
    OMPMasterTaskLoopDirectiveClass,
    OMPMaskedTaskLoopSimdDirectiveClass,
    OMPMaskedTaskLoopDirectiveClass,
    OMPGenericLoopDirectiveClass,
    OMPForSimdDirectiveClass,
    OMPForDirectiveClass,
    OMPDistributeSimdDirectiveClass,
    OMPDistributeParallelForSimdDirectiveClass,
    OMPDistributeParallelForDirectiveClass,
    OMPDistributeDirectiveClass,
    OMPInteropDirectiveClass,
    OMPFlushDirectiveClass,
    OMPErrorDirectiveClass,
    OMPDispatchDirectiveClass,
    OMPDepobjDirectiveClass,
    OMPCriticalDirectiveClass,
    OMPCancellationPointDirectiveClass,
    OMPCancelDirectiveClass,
    OMPBarrierDirectiveClass,
    OMPAtomicDirectiveClass,
    OMPCanonicalLoopClass,
    NullStmtClass,
    MSDependentExistsStmtClass,
    IndirectGotoStmtClass,
    IfStmtClass,
    GotoStmtClass,
    ForStmtClass,
    DoStmtClass,
    DeclStmtClass,
    CoroutineBodyStmtClass,
    CoreturnStmtClass,
    ContinueStmtClass,
    CompoundStmtClass,
    CapturedStmtClass,
    CXXTryStmtClass,
    CXXForRangeStmtClass,
    CXXCatchStmtClass,
    BreakStmtClass,
    MSAsmStmtClass,
    GCCAsmStmtClass,
};

pub const CK = enum(c_int) {
    Dependent,
    BitCast,
    LValueBitCast,
    LValueToRValueBitCast,
    LValueToRValue,
    NoOp,
    BaseToDerived,
    DerivedToBase,
    UncheckedDerivedToBase,
    Dynamic,
    ToUnion,
    ArrayToPointerDecay,
    FunctionToPointerDecay,
    NullToPointer,
    NullToMemberPointer,
    BaseToDerivedMemberPointer,
    DerivedToBaseMemberPointer,
    MemberPointerToBoolean,
    ReinterpretMemberPointer,
    UserDefinedConversion,
    ConstructorConversion,
    IntegralToPointer,
    PointerToIntegral,
    PointerToBoolean,
    ToVoid,
    MatrixCast,
    VectorSplat,
    IntegralCast,
    IntegralToBoolean,
    IntegralToFloating,
    FloatingToFixedPoint,
    FixedPofloatFromInting,
    FixedPointCast,
    FixedPointToIntegral,
    IntegralToFixedPoint,
    FixedPointToBoolean,
    FloatingToIntegral,
    FloatingToBoolean,
    BooleanToSignedIntegral,
    FloatingCast,
    CPointerToObjCPointerCast,
    BlockPointerToObjCPointerCast,
    AnyPointerToBlockPointerCast,
    ObjCObjectLValueCast,
    FloatingRealToComplex,
    FloatingComplexToReal,
    FloatingComplexToBoolean,
    FloatingComplexCast,
    FloatingComplexToIntegralComplex,
    IntegralRealToComplex,
    IntegralComplexToReal,
    IntegralComplexToBoolean,
    IntegralComplexCast,
    IntegralComplexToFloatingComplex,
    ARCProduceObject,
    ARCConsumeObject,
    ARCReclaimReturnedObject,
    ARCExtendBlockObject,
    AtomicToNonAtomic,
    NonAtomicToAtomic,
    CopyAndAutoreleaseBlockObject,
    BuiltinFnToFnPtr,
    ZeroToOCLOpaqueType,
    AddressSpaceConversion,
    IntToOCLSampler,
};

pub const DeclKind = enum(c_int) {
    TranslationUnit,
    RequiresExprBody,
    LinkageSpec,
    ExternCContext,
    Export,
    Captured,
    Block,
    TopLevelStmt,
    StaticAssert,
    PragmaDetectMismatch,
    PragmaComment,
    ObjCPropertyImpl,
    OMPThreadPrivate,
    OMPRequires,
    OMPAllocate,
    ObjCMethod,
    ObjCProtocol,
    ObjCInterface,
    ObjCImplementation,
    ObjCCategoryImpl,
    ObjCCategory,
    Namespace,
    HLSLBuffer,
    OMPDeclareReduction,
    OMPDeclareMapper,
    UnresolvedUsingValue,
    UnnamedGlobalConstant,
    TemplateParamObject,
    MSGuid,
    IndirectField,
    EnumConstant,
    Function,
    CXXMethod,
    CXXDestructor,
    CXXConversion,
    CXXConstructor,
    CXXDeductionGuide,
    Var,
    VarTemplateSpecialization,
    VarTemplatePartialSpecialization,
    ParmVar,
    OMPCapturedExpr,
    ImplicitParam,
    Decomposition,
    NonTypeTemplateParm,
    MSProperty,
    Field,
    ObjCIvar,
    ObjCAtDefsField,
    Binding,
    UsingShadow,
    ConstructorUsingShadow,
    UsingPack,
    UsingDirective,
    UnresolvedUsingIfExists,
    Record,
    CXXRecord,
    ClassTemplateSpecialization,
    ClassTemplatePartialSpecialization,
    Enum,
    UnresolvedUsingTypename,
    Typedef,
    TypeAlias,
    ObjCTypeParam,
    TemplateTypeParm,
    TemplateTemplateParm,
    VarTemplate,
    TypeAliasTemplate,
    FunctionTemplate,
    ClassTemplate,
    Concept,
    BuiltinTemplate,
    ObjCProperty,
    ObjCCompatibleAlias,
    NamespaceAlias,
    Label,
    UsingEnum,
    Using,
    LifetimeExtendedTemporary,
    Import,
    ImplicitConceptSpecialization,
    FriendTemplate,
    Friend,
    FileScopeAsm,
    Empty,
    AccessSpec,
};

pub const BuiltinTypeKind = enum(c_int) {
    OCLImage1dRO,
    OCLImage1dArrayRO,
    OCLImage1dBufferRO,
    OCLImage2dRO,
    OCLImage2dArrayRO,
    OCLImage2dDepthRO,
    OCLImage2dArrayDepthRO,
    OCLImage2dMSAARO,
    OCLImage2dArrayMSAARO,
    OCLImage2dMSAADepthRO,
    OCLImage2dArrayMSAADepthRO,
    OCLImage3dRO,
    OCLImage1dWO,
    OCLImage1dArrayWO,
    OCLImage1dBufferWO,
    OCLImage2dWO,
    OCLImage2dArrayWO,
    OCLImage2dDepthWO,
    OCLImage2dArrayDepthWO,
    OCLImage2dMSAAWO,
    OCLImage2dArrayMSAAWO,
    OCLImage2dMSAADepthWO,
    OCLImage2dArrayMSAADepthWO,
    OCLImage3dWO,
    OCLImage1dRW,
    OCLImage1dArrayRW,
    OCLImage1dBufferRW,
    OCLImage2dRW,
    OCLImage2dArrayRW,
    OCLImage2dDepthRW,
    OCLImage2dArrayDepthRW,
    OCLImage2dMSAARW,
    OCLImage2dArrayMSAARW,
    OCLImage2dMSAADepthRW,
    OCLImage2dArrayMSAADepthRW,
    OCLImage3dRW,
    OCLIntelSubgroupAVCMcePayload,
    OCLIntelSubgroupAVCImePayload,
    OCLIntelSubgroupAVCRefPayload,
    OCLIntelSubgroupAVCSicPayload,
    OCLIntelSubgroupAVCMceResult,
    OCLIntelSubgroupAVCImeResult,
    OCLIntelSubgroupAVCRefResult,
    OCLIntelSubgroupAVCSicResult,
    OCLIntelSubgroupAVCImeResultSingleReferenceStreamout,
    OCLIntelSubgroupAVCImeResultDualReferenceStreamout,
    OCLIntelSubgroupAVCImeSingleReferenceStreamin,
    OCLIntelSubgroupAVCImeDualReferenceStreamin,
    SveInt8,
    SveInt16,
    SveInt32,
    SveInt64,
    SveUint8,
    SveUint16,
    SveUint32,
    SveUint64,
    SveFloat16,
    SveFloat32,
    SveFloat64,
    SveBFloat16,
    SveInt8x2,
    SveInt16x2,
    SveInt32x2,
    SveInt64x2,
    SveUint8x2,
    SveUint16x2,
    SveUint32x2,
    SveUint64x2,
    SveFloat16x2,
    SveFloat32x2,
    SveFloat64x2,
    SveBFloat16x2,
    SveInt8x3,
    SveInt16x3,
    SveInt32x3,
    SveInt64x3,
    SveUint8x3,
    SveUint16x3,
    SveUint32x3,
    SveUint64x3,
    SveFloat16x3,
    SveFloat32x3,
    SveFloat64x3,
    SveBFloat16x3,
    SveInt8x4,
    SveInt16x4,
    SveInt32x4,
    SveInt64x4,
    SveUint8x4,
    SveUint16x4,
    SveUint32x4,
    SveUint64x4,
    SveFloat16x4,
    SveFloat32x4,
    SveFloat64x4,
    SveBFloat16x4,
    SveBool,
    SveBoolx2,
    SveBoolx4,
    SveCount,
    VectorQuad,
    VectorPair,
    RvvInt8mf8,
    RvvInt8mf4,
    RvvInt8mf2,
    RvvInt8m1,
    RvvInt8m2,
    RvvInt8m4,
    RvvInt8m8,
    RvvUint8mf8,
    RvvUint8mf4,
    RvvUint8mf2,
    RvvUint8m1,
    RvvUint8m2,
    RvvUint8m4,
    RvvUint8m8,
    RvvInt16mf4,
    RvvInt16mf2,
    RvvInt16m1,
    RvvInt16m2,
    RvvInt16m4,
    RvvInt16m8,
    RvvUint16mf4,
    RvvUint16mf2,
    RvvUint16m1,
    RvvUint16m2,
    RvvUint16m4,
    RvvUint16m8,
    RvvInt32mf2,
    RvvInt32m1,
    RvvInt32m2,
    RvvInt32m4,
    RvvInt32m8,
    RvvUint32mf2,
    RvvUint32m1,
    RvvUint32m2,
    RvvUint32m4,
    RvvUint32m8,
    RvvInt64m1,
    RvvInt64m2,
    RvvInt64m4,
    RvvInt64m8,
    RvvUint64m1,
    RvvUint64m2,
    RvvUint64m4,
    RvvUint64m8,
    RvvFloat16mf4,
    RvvFloat16mf2,
    RvvFloat16m1,
    RvvFloat16m2,
    RvvFloat16m4,
    RvvFloat16m8,
    RvvBFloat16mf4,
    RvvBFloat16mf2,
    RvvBFloat16m1,
    RvvBFloat16m2,
    RvvBFloat16m4,
    RvvBFloat16m8,
    RvvFloat32mf2,
    RvvFloat32m1,
    RvvFloat32m2,
    RvvFloat32m4,
    RvvFloat32m8,
    RvvFloat64m1,
    RvvFloat64m2,
    RvvFloat64m4,
    RvvFloat64m8,
    RvvBool1,
    RvvBool2,
    RvvBool4,
    RvvBool8,
    RvvBool16,
    RvvBool32,
    RvvBool64,
    RvvInt8mf8x2,
    RvvInt8mf8x3,
    RvvInt8mf8x4,
    RvvInt8mf8x5,
    RvvInt8mf8x6,
    RvvInt8mf8x7,
    RvvInt8mf8x8,
    RvvInt8mf4x2,
    RvvInt8mf4x3,
    RvvInt8mf4x4,
    RvvInt8mf4x5,
    RvvInt8mf4x6,
    RvvInt8mf4x7,
    RvvInt8mf4x8,
    RvvInt8mf2x2,
    RvvInt8mf2x3,
    RvvInt8mf2x4,
    RvvInt8mf2x5,
    RvvInt8mf2x6,
    RvvInt8mf2x7,
    RvvInt8mf2x8,
    RvvInt8m1x2,
    RvvInt8m1x3,
    RvvInt8m1x4,
    RvvInt8m1x5,
    RvvInt8m1x6,
    RvvInt8m1x7,
    RvvInt8m1x8,
    RvvInt8m2x2,
    RvvInt8m2x3,
    RvvInt8m2x4,
    RvvInt8m4x2,
    RvvUint8mf8x2,
    RvvUint8mf8x3,
    RvvUint8mf8x4,
    RvvUint8mf8x5,
    RvvUint8mf8x6,
    RvvUint8mf8x7,
    RvvUint8mf8x8,
    RvvUint8mf4x2,
    RvvUint8mf4x3,
    RvvUint8mf4x4,
    RvvUint8mf4x5,
    RvvUint8mf4x6,
    RvvUint8mf4x7,
    RvvUint8mf4x8,
    RvvUint8mf2x2,
    RvvUint8mf2x3,
    RvvUint8mf2x4,
    RvvUint8mf2x5,
    RvvUint8mf2x6,
    RvvUint8mf2x7,
    RvvUint8mf2x8,
    RvvUint8m1x2,
    RvvUint8m1x3,
    RvvUint8m1x4,
    RvvUint8m1x5,
    RvvUint8m1x6,
    RvvUint8m1x7,
    RvvUint8m1x8,
    RvvUint8m2x2,
    RvvUint8m2x3,
    RvvUint8m2x4,
    RvvUint8m4x2,
    RvvInt16mf4x2,
    RvvInt16mf4x3,
    RvvInt16mf4x4,
    RvvInt16mf4x5,
    RvvInt16mf4x6,
    RvvInt16mf4x7,
    RvvInt16mf4x8,
    RvvInt16mf2x2,
    RvvInt16mf2x3,
    RvvInt16mf2x4,
    RvvInt16mf2x5,
    RvvInt16mf2x6,
    RvvInt16mf2x7,
    RvvInt16mf2x8,
    RvvInt16m1x2,
    RvvInt16m1x3,
    RvvInt16m1x4,
    RvvInt16m1x5,
    RvvInt16m1x6,
    RvvInt16m1x7,
    RvvInt16m1x8,
    RvvInt16m2x2,
    RvvInt16m2x3,
    RvvInt16m2x4,
    RvvInt16m4x2,
    RvvUint16mf4x2,
    RvvUint16mf4x3,
    RvvUint16mf4x4,
    RvvUint16mf4x5,
    RvvUint16mf4x6,
    RvvUint16mf4x7,
    RvvUint16mf4x8,
    RvvUint16mf2x2,
    RvvUint16mf2x3,
    RvvUint16mf2x4,
    RvvUint16mf2x5,
    RvvUint16mf2x6,
    RvvUint16mf2x7,
    RvvUint16mf2x8,
    RvvUint16m1x2,
    RvvUint16m1x3,
    RvvUint16m1x4,
    RvvUint16m1x5,
    RvvUint16m1x6,
    RvvUint16m1x7,
    RvvUint16m1x8,
    RvvUint16m2x2,
    RvvUint16m2x3,
    RvvUint16m2x4,
    RvvUint16m4x2,
    RvvInt32mf2x2,
    RvvInt32mf2x3,
    RvvInt32mf2x4,
    RvvInt32mf2x5,
    RvvInt32mf2x6,
    RvvInt32mf2x7,
    RvvInt32mf2x8,
    RvvInt32m1x2,
    RvvInt32m1x3,
    RvvInt32m1x4,
    RvvInt32m1x5,
    RvvInt32m1x6,
    RvvInt32m1x7,
    RvvInt32m1x8,
    RvvInt32m2x2,
    RvvInt32m2x3,
    RvvInt32m2x4,
    RvvInt32m4x2,
    RvvUint32mf2x2,
    RvvUint32mf2x3,
    RvvUint32mf2x4,
    RvvUint32mf2x5,
    RvvUint32mf2x6,
    RvvUint32mf2x7,
    RvvUint32mf2x8,
    RvvUint32m1x2,
    RvvUint32m1x3,
    RvvUint32m1x4,
    RvvUint32m1x5,
    RvvUint32m1x6,
    RvvUint32m1x7,
    RvvUint32m1x8,
    RvvUint32m2x2,
    RvvUint32m2x3,
    RvvUint32m2x4,
    RvvUint32m4x2,
    RvvInt64m1x2,
    RvvInt64m1x3,
    RvvInt64m1x4,
    RvvInt64m1x5,
    RvvInt64m1x6,
    RvvInt64m1x7,
    RvvInt64m1x8,
    RvvInt64m2x2,
    RvvInt64m2x3,
    RvvInt64m2x4,
    RvvInt64m4x2,
    RvvUint64m1x2,
    RvvUint64m1x3,
    RvvUint64m1x4,
    RvvUint64m1x5,
    RvvUint64m1x6,
    RvvUint64m1x7,
    RvvUint64m1x8,
    RvvUint64m2x2,
    RvvUint64m2x3,
    RvvUint64m2x4,
    RvvUint64m4x2,
    RvvFloat16mf4x2,
    RvvFloat16mf4x3,
    RvvFloat16mf4x4,
    RvvFloat16mf4x5,
    RvvFloat16mf4x6,
    RvvFloat16mf4x7,
    RvvFloat16mf4x8,
    RvvFloat16mf2x2,
    RvvFloat16mf2x3,
    RvvFloat16mf2x4,
    RvvFloat16mf2x5,
    RvvFloat16mf2x6,
    RvvFloat16mf2x7,
    RvvFloat16mf2x8,
    RvvFloat16m1x2,
    RvvFloat16m1x3,
    RvvFloat16m1x4,
    RvvFloat16m1x5,
    RvvFloat16m1x6,
    RvvFloat16m1x7,
    RvvFloat16m1x8,
    RvvFloat16m2x2,
    RvvFloat16m2x3,
    RvvFloat16m2x4,
    RvvFloat16m4x2,
    RvvFloat32mf2x2,
    RvvFloat32mf2x3,
    RvvFloat32mf2x4,
    RvvFloat32mf2x5,
    RvvFloat32mf2x6,
    RvvFloat32mf2x7,
    RvvFloat32mf2x8,
    RvvFloat32m1x2,
    RvvFloat32m1x3,
    RvvFloat32m1x4,
    RvvFloat32m1x5,
    RvvFloat32m1x6,
    RvvFloat32m1x7,
    RvvFloat32m1x8,
    RvvFloat32m2x2,
    RvvFloat32m2x3,
    RvvFloat32m2x4,
    RvvFloat32m4x2,
    RvvFloat64m1x2,
    RvvFloat64m1x3,
    RvvFloat64m1x4,
    RvvFloat64m1x5,
    RvvFloat64m1x6,
    RvvFloat64m1x7,
    RvvFloat64m1x8,
    RvvFloat64m2x2,
    RvvFloat64m2x3,
    RvvFloat64m2x4,
    RvvFloat64m4x2,
    RvvBFloat16mf4x2,
    RvvBFloat16mf4x3,
    RvvBFloat16mf4x4,
    RvvBFloat16mf4x5,
    RvvBFloat16mf4x6,
    RvvBFloat16mf4x7,
    RvvBFloat16mf4x8,
    RvvBFloat16mf2x2,
    RvvBFloat16mf2x3,
    RvvBFloat16mf2x4,
    RvvBFloat16mf2x5,
    RvvBFloat16mf2x6,
    RvvBFloat16mf2x7,
    RvvBFloat16mf2x8,
    RvvBFloat16m1x2,
    RvvBFloat16m1x3,
    RvvBFloat16m1x4,
    RvvBFloat16m1x5,
    RvvBFloat16m1x6,
    RvvBFloat16m1x7,
    RvvBFloat16m1x8,
    RvvBFloat16m2x2,
    RvvBFloat16m2x3,
    RvvBFloat16m2x4,
    RvvBFloat16m4x2,
    WasmExternRef,
    Void,
    Bool,
    Char_U,
    UChar,
    WChar_U,
    Char8,
    Char16,
    Char32,
    UShort,
    UInt,
    ULong,
    ULongLong,
    UInt128,
    Char_S,
    SChar,
    WChar_S,
    Short,
    Int,
    Long,
    LongLong,
    Int128,
    ShortAccum,
    Accum,
    LongAccum,
    UShortAccum,
    UAccum,
    ULongAccum,
    ShortFract,
    Fract,
    LongFract,
    UShortFract,
    UFract,
    ULongFract,
    SatShortAccum,
    SatAccum,
    SatLongAccum,
    SatUShortAccum,
    SatUAccum,
    SatULongAccum,
    SatShortFract,
    SatFract,
    SatLongFract,
    SatUShortFract,
    SatUFract,
    SatULongFract,
    Half,
    Float,
    Double,
    LongDouble,
    Float16,
    BFloat16,
    Float128,
    Ibm128,
    NullPtr,
    ObjCId,
    ObjCClass,
    ObjCSel,
    OCLSampler,
    OCLEvent,
    OCLClkEvent,
    OCLQueue,
    OCLReserveID,
    Dependent,
    Overload,
    BoundMember,
    PseudoObject,
    UnknownAny,
    BuiltinFn,
    ARCUnbridgedCast,
    IncompleteMatrixIdx,
    OMPArraySection,
    OMPArrayShaping,
    OMPIterator,
};

pub const CallingConv = enum(c_int) {
    C,
    X86StdCall,
    X86FastCall,
    X86ThisCall,
    X86VectorCall,
    X86Pascal,
    Win64,
    X86_64SysV,
    X86RegCall,
    AAPCS,
    AAPCS_VFP,
    IntelOclBicc,
    SpirFunction,
    OpenCLKernel,
    Swift,
    SwiftAsync,
    PreserveMost,
    PreserveAll,
    AArch64VectorCall,
    AArch64SVEPCS,
    AMDGPUKernelCall,
    M68kRTD,
};

pub const StorageClass = enum(c_int) {
    None,
    Extern,
    Static,
    PrivateExtern,
    Auto,
    Register,
};

pub const APFloat_roundingMode = enum(i8) {
    TowardZero = 0,
    NearestTiesToEven = 1,
    TowardPositive = 2,
    TowardNegative = 3,
    NearestTiesToAway = 4,
    Dynamic = 7,
    Invalid = -1,
};

pub const CharacterLiteralKind = enum(c_int) {
    Ascii,
    Wide,
    UTF8,
    UTF16,
    UTF32,
};

pub const VarDecl_TLSKind = enum(c_int) {
    None,
    Static,
    Dynamic,
};

pub const ElaboratedTypeKeyword = enum(c_int) {
    Struct,
    Interface,
    Union,
    Class,
    Enum,
    Typename,
    None,
};

pub const PreprocessedEntity_EntityKind = enum(c_int) {
    InvalidKind,
    MacroExpansionKind,
    MacroDefinitionKind,
    InclusionDirectiveKind,
};

pub const Expr_ConstantExprKind = enum(c_int) {
    Normal,
    NonClassTemplateArgument,
    ClassTemplateArgument,
    ImmediateInvocation,
};

pub const UnaryExprOrTypeTrait_Kind = enum(c_int) {
    SizeOf,
    DataSizeOf,
    AlignOf,
    PreferredAlignOf,
    VecStep,
    OpenMPRequiredSimdAlign,
};

pub const OffsetOfNode_Kind = enum(c_int) {
    Array,
    Field,
    Identifier,
    Base,
};

pub const ErrorMsg = extern struct {
    filename_ptr: ?[*]const u8,
    filename_len: usize,
    msg_ptr: [*]const u8,
    msg_len: usize,
    // valid until the ASTUnit is freed
    source: ?[*:0]const u8,
    // 0 based
    line: c_uint,
    // 0 based
    column: c_uint,
    // byte offset into source
    offset: c_uint,

    pub const delete = ZigClangErrorMsg_delete;
    extern fn zig_clang_error_msg_delete(ptr: [*]ErrorMsg, len: usize) void;
};

pub const LoadFromCommandLine = ZigClangLoadFromCommandLine;
extern fn zig_clang_load_from_command_line(
    args_begin: [*]?[*]const u8,
    args_end: [*]?[*]const u8,
    errors_ptr: *[*]ErrorMsg,
    errors_len: *usize,
    resources_path: [*:0]const u8,
) ?*ASTUnit;

pub const isLLVMUsingSeparateLibcxx = ZigClangIsLLVMUsingSeparateLibcxx;
extern fn zig_clang_is_llvmusing_separate_libcxx() bool;
