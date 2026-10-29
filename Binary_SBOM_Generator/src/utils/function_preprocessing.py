import json
import re
import sys
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
from typing import Optional
from tree_sitter import Language, Parser, Node, Tree

from .function_list import LIBC_NORMALIZATION, LIBC_FUNCTIONS, EXCLUDED_SYMBOLS
from .vectorization import (
    vectorize_key_feature,
    build_vocabulary,
    preprocess_key_feature,
    calculate_numbers,
    convert_logical_to_comparison,
    Vocabulary
)

MACRO_LIKE_CALL_RE = re.compile(r"^(?:[A-Z][A-Z0-9_]*|_[A-Z0-9_]+|__\w+)$")
DECOMPILED_FUNCTION_RE = re.compile(r"^FUN_[0-9A-Fa-f]+$")
FORMAT_PATTERN = re.compile(r"^%[-+0 #]*(\d+|\*)?(\.(\d+|\*))?[hlLzjt]*[diouxXeEfFgGaAcspn%]$")
FORMAT_ONLY_PATTERN = re.compile(r"^[\s%\-+0-9.#hlLzjtdiouxXeEfFgGaAcspn\[\]\(\)\{\}:,'\"\ntr]*$")
PATH_PATTERN = re.compile(r"^([a-zA-Z]:)?[\\/][^\s]+")


class OrgType(str, Enum):
    IF = "If"
    WHILE = "While"
    DO_WHILE = "DoWhile"
    FOR = "For"
    ELSE = "Else"
    SWITCH = "Switch"
    STRING = "String"
    ASSIGNMENT = "Assignment"
    RETURN = "Return"
    FUNCTION_CALL = "FunctionCall"
    POINTER_CALL = "PointerCall"


class ControlBlockType(str, Enum):
    CONDITION = "Condition"
    LOOP = "Loop"
    ELSE = "Else"
    STRING = "String"
    LIBC_FUNC = "LibcFunc"
    CALLEE_FUNC = "CalleeFunc"
    RECURSIVE_FUNC = "RecursiveFunc"


@dataclass
class ControlBlock:
    block_type: str
    org_type: str
    block_content: list[str] = field(default_factory=list)
    key_feature: list[str] = field(default_factory=list)
    key_feature_vector: str = ""
    key_feature_dvector: dict = field(default_factory=dict)
    block_content_vector: str = ""
    block_content_dvector: dict = field(default_factory=dict)


class CBMaker:
    def __init__(self, language: str = 'c'):
        self.language = language
        self.parser = self._init_parser()
        self.tree = None
        self.source_code = ""
        self.source_lines = []
        self.parameters = []
        self.variables = set()
        self.control_blocks = []
        self.vocabulary: Optional[Vocabulary] = None

    def _init_parser(self) -> Parser:
        try:
            if self.language == 'c':
                import tree_sitter_c
                lang = tree_sitter_c.language()
            else:
                import tree_sitter_cpp
                lang = tree_sitter_cpp.language()

            parser = Parser()
            parser.language = Language(lang)
            return parser
        except Exception as e:
            # sys.exit 대신 예외 발생 (Preprocessor에서 처리)
            raise RuntimeError(f"[!] Tree-sitter Error: {e}\n"
                    "[!] Install: uv pip install tree-sitter tree-sitter-c tree-sitter-cpp")

    def parse_file(self, file_path: str) -> Tree:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            self.source_code = f.read()
            self.source_lines = self.source_code.splitlines()

        modified_code = self.source_code

        lines = modified_code.split('\n')
        modified_lines = []

        TYPE_KEYWORDS = {
            'void', 'int', 'char', 'short', 'long', 'float', 'double',
            'unsigned', 'signed', 'static', 'inline', 'extern', 'const',
            'volatile', 'struct', 'union', 'enum', 'typedef'
        }

        CONTROL_KEYWORDS = {'if', 'for', 'while', 'switch', 'return', 'sizeof', 'case', 'do'}

        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()

            if not stripped or stripped.startswith('//') or stripped.startswith('/*'):
                modified_lines.append(line)
                i += 1
                continue

            if line[0] in (' ', '\t'):
                modified_lines.append(line)
                i += 1
                continue

            match = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', stripped)
            if match:
                first_word = match.group(1)

                if first_word in CONTROL_KEYWORDS or first_word in TYPE_KEYWORDS:
                    modified_lines.append(line)
                    i += 1
                    continue

                has_opening_brace = False
                lookahead = min(5, len(lines) - i)

                for j in range(lookahead):
                    if '{' in lines[i + j]:
                        has_opening_brace = True
                        break

                if has_opening_brace:
                    modified_lines.append('void ' + line)
                else:
                    modified_lines.append(line)
            else:
                modified_lines.append(line)

            i += 1

        modified_code = '\n'.join(modified_lines)

        # 수정된 코드로 파싱
        self.source_code = modified_code
        self.source_lines = self.source_code.splitlines()

        self.tree = self.parser.parse(bytes(modified_code, 'utf8'))
        return self.tree

    def get_node_text(self, node: Node) -> str:
        return self.source_code[node.start_byte:node.end_byte]

    @staticmethod
    def _is_macro_like_identifier(name: str) -> bool:
        if DECOMPILED_FUNCTION_RE.fullmatch(name):
            return False
        return bool(MACRO_LIKE_CALL_RE.fullmatch(name))

    def _extract_declarator_identifier(self, node: Optional[Node]) -> Optional[str]:
        if node is None:
            return None

        if node.type == 'identifier':
            return self.get_node_text(node)

        direct_declarator = node.child_by_field_name('declarator')
        if direct_declarator is not None:
            identifier = self._extract_declarator_identifier(direct_declarator)
            if identifier:
                return identifier

        if node.type in {'pointer_declarator', 'parenthesized_declarator',
                         'function_declarator', 'array_declarator'}:
            for child in node.children:
                identifier = self._extract_declarator_identifier(child)
                if identifier:
                    return identifier

        return None

    def _collect_identifiers_from_parameter_declarator(self, node: Optional[Node]) -> list[str]:
        identifier = self._extract_declarator_identifier(node)
        return [identifier] if identifier else []

    def _classify_callee(self, node: Optional[Node]) -> str:
        if node is None:
            return "unknown"

        if node.type == 'identifier':
            callee_name = self.get_node_text(node).strip()
            if self._is_macro_like_identifier(callee_name):
                return "macro_like"
            if callee_name in self.variables or callee_name in self.parameters:
                return "indirect"
            return "direct"

        if node.type in {'field_expression', 'pointer_expression',
                         'subscript_expression', 'parenthesized_expression'}:
            return "indirect"

        return "unknown"

    @staticmethod
    def normalize_string(text: str) -> str:
        return (text.replace("\\n", "")
                   .replace("\\r", "")
                   .replace("\\t", "")
                   .replace("\n", "")
                   .replace("\r", "")
                   .replace("\t", "")
                   .replace("{", "")
                   .replace("}", "")
                   .replace(" ", "")
                   .replace("\\", "")
                   .replace("'", "")
                   .lower())

    @staticmethod
    def is_noise_string(text: str) -> bool:
        if not text:
            return True
        candidate = text.strip()
        if not candidate:
            return True
        if PATH_PATTERN.match(candidate):
            return True
        if FORMAT_PATTERN.match(candidate):
            return True
        if FORMAT_ONLY_PATTERN.match(candidate) and "%" in candidate:
            return True
        return False

    @staticmethod
    def get_ascii_value(char_value: str) -> int:
        escape_map = {
            '\\0': 0, '\\n': 10, '\\r': 13, '\\t': 9,
            '\\b': 8, '\\f': 12, '\\v': 11, '\\\\': 92,
            "\\'": 39, '\\"': 34
        }

        if char_value in escape_map:
            return escape_map[char_value]
        elif len(char_value) == 1:
            return ord(char_value)
        return 0

    @staticmethod
    def process_literal_value(value: str) -> tuple[str, int | None]:
        # 단일 문자 리터럴 'a'
        if len(value) == 3 and value.startswith("'") and value.endswith("'"):
            char_value = value[1:2]
            return ("ASCII", CBMaker.get_ascii_value(char_value))

        # 이스케이프 문자 리터럴 '\n'
        elif len(value) == 4 and value.startswith("'\\") and value.endswith("'"):
            escape_seq = value[1:3]
            return ("ASCII", CBMaker.get_ascii_value(escape_seq))

        return ("LITERAL", None)

    @staticmethod
    def normalize_number(text: str) -> str:
        """숫자 정규화"""
        text = text.strip()

        # 16진수
        if text.lower().startswith('0x'):
            try:
                return str(int(text, 16))
            except ValueError:
                return text

        # 문자 리터럴 (processLiteralValue 사용)
        if text.startswith("'") and text.endswith("'"):
            lit_type, ascii_val = CBMaker.process_literal_value(text)
            if lit_type == "ASCII" and ascii_val is not None:
                return str(ascii_val)

        # 일반 숫자 (suffix 제거)
        try:
            num_text = re.sub(r'[UuLl]+$', '', text)
            return str(int(float(num_text)))
        except ValueError:
            return text

    @staticmethod
    def get_normalized_libc_name(func_name: str) -> str:
        """LibC 함수명 정규화"""
        return next(
            (norm for norm, funcs in LIBC_NORMALIZATION.items() if func_name in funcs),
            func_name
        )

    def extract_condition(self, node: Node) -> list[str]:
        """조건문 추출 및 정규화"""
        result = []

        # 연산자 매핑
        OPERATOR_MAP = {
            '==': 'equals', '!=': 'notEquals',
            '<': 'lessThan', '<=': 'lessEqualsThan',
            '>': 'greaterThan', '>=': 'greaterEqualsThan',
            '&&': 'logicalAnd', '||': 'logicalOr',
            '+': 'plus', '-': 'minus', '*': 'multiplication', '/': 'division',
            '%': 'modulo',
            '&': 'and', '|': 'or', '^': 'xor', '~': 'not',
            '<<': 'shiftLeft', '>>': 'shiftRight',
            '+=': 'assignmentPlus', '-=': 'assignmentMinus',
            '*=': 'assignmentMultiplication', '/=': 'assignmentDivision',
            '%=': 'assignmentModulo',
            '++': 'increment', '--': 'decrement',
        }

        def traverse(n: Node) -> None:
            node_type = n.type
            text = self.get_node_text(n).strip()

            match node_type:
                case 'identifier':
                    var_type = ("LVAR" if text in self.variables else
                               "PVAR" if text in self.parameters else text)
                    result.append(f"(IDENTIFIER,{var_type})")

                case 'number_literal':
                    result.append(f"(NUM,{self.normalize_number(text)})")

                case 'string_literal':
                    literal_text = text.strip('"')
                    if not self.is_noise_string(literal_text) and (normalized := self.normalize_string(literal_text)):
                        result.append(f"(LITERAL,{normalized})")

                case 'char_literal':
                    result.append(f"(NUM,{self.normalize_number(text)})")

                case 'call_expression':
                    if func_node := n.child_by_field_name('function'):
                        callee_kind = self._classify_callee(func_node)
                        if callee_kind == "direct":
                            func_name = self.get_node_text(func_node).strip()
                            if func_name in LIBC_FUNCTIONS:
                                result.append(f"(LIBCFUNC,{self.get_normalized_libc_name(func_name)})")
                            else:
                                result.append(f"(FUNCTION,{func_name})")

                        if args_node := n.child_by_field_name('arguments'):
                            for arg in args_node.children:
                                if arg.type not in {'(', ')', ','}:
                                    traverse(arg)
                        return

                case 'binary_expression':
                    if left := n.child_by_field_name('left'):
                        traverse(left)
                    if op_node := n.child_by_field_name('operator'):
                        op_text = self.get_node_text(op_node).strip()

                        # 복합 할당 연산자 확장 (a += 5 → a = a + 5)
                        if op_text in ('+=', '-=', '*=', '/=', '%='):
                            # 왼쪽 변수 다시 추가
                            if left := n.child_by_field_name('left'):
                                traverse(left)
                            # 기본 연산자로 변환
                            base_op = op_text[0]  # +, -, *, /, %
                            if base_op in OPERATOR_MAP:
                                result.append(f"(OPERATOR,{OPERATOR_MAP[base_op]})")
                        elif op := OPERATOR_MAP.get(op_text):
                            result.append(f"(OPERATOR,{op})")
                    if right := n.child_by_field_name('right'):
                        traverse(right)

                case 'unary_expression':
                    if op := n.child(0):
                        op_text = self.get_node_text(op).strip()
                        if op_text in ('!', '-'):
                            op_name = 'logicalNot' if op_text == '!' else 'minus'
                            result.append(f"(OPERATOR,{op_name})")
                    for child in n.children[1:]:
                        traverse(child)

                case 'sizeof_expression':
                    result.append(f"(NUMTYPE,NUMTYPE)")

                case 'update_expression':
                    # i++ → (IDENTIFIER,i), (NUM,1), (OPERATOR,plus)
                    # i-- → (IDENTIFIER,i), (NUM,-1), (OPERATOR,plus)
                    operator = None
                    var_node = None

                    for child in n.children:
                        if child.type in ('++', '--'):
                            operator = self.get_node_text(child)
                        elif child.type == 'identifier':
                            var_node = child

                    if operator and var_node:
                        var_text = self.get_node_text(var_node).strip()
                        var_type = ("LVAR" if var_text in self.variables else
                                   "PVAR" if var_text in self.parameters else var_text)

                        # 변수, 숫자, 연산자 순서로 추가
                        result.append(f"(IDENTIFIER,{var_type})")
                        if operator == '++':
                            result.append(f"(NUM,1)")
                        else:  # --
                            result.append(f"(NUM,-1)")
                        result.append(f"(OPERATOR,plus)")

                case 'field_expression':
                    # struct.field 또는 ptr->field
                    operator_node = n.child_by_field_name('operator')
                    argument = n.child_by_field_name('argument')
                    field = n.child_by_field_name('field')

                    if operator_node and self.get_node_text(operator_node) == '->':
                        # 포인터 필드 접근
                        if argument:
                            arg_text = self.get_node_text(argument).strip()
                            var_type = ("LVAR" if arg_text in self.variables else
                                       "PVAR" if arg_text in self.parameters else arg_text)
                            result.append(f"(POINTERVAR,{var_type})")
                    else:
                        # 일반 필드 접근 또는 . 연산자
                        if argument:
                            traverse(argument)
                        if field:
                            field_text = self.get_node_text(field).strip()
                            result.append(f"(IDENTIFIER,{field_text})")

                case 'subscript_expression':
                    # array[index] 또는 ptr[index]
                    argument = n.child_by_field_name('argument')
                    index = n.child_by_field_name('index')

                    if argument:
                        arg_text = self.get_node_text(argument).strip()
                        var_type = ("LVAR" if arg_text in self.variables else
                                   "PVAR" if arg_text in self.parameters else arg_text)
                        result.append(f"(POINTERVAR,{var_type})")
                    if index:
                        traverse(index)

                case 'pointer_expression':
                    # *ptr (dereference)
                    argument = n.child_by_field_name('argument')
                    if argument:
                        arg_text = self.get_node_text(argument).strip()
                        var_type = ("LVAR" if arg_text in self.variables else
                                   "PVAR" if arg_text in self.parameters else arg_text)
                        result.append(f"(POINTERVAR,{var_type})")

                case 'assignment_expression':
                    # a += 5 → (IDENTIFIER,a), (IDENTIFIER,a), (OPERATOR,plus), (NUM,5)
                    # tree-sitter: left(identifier) operator right(value)
                    left_node = None
                    op_text = None
                    right_node = None

                    for child in n.children:
                        if child.type == 'identifier' and left_node is None:
                            left_node = child
                        elif child.type in ('+=', '-=', '*=', '/=', '%=', '='):
                            op_text = self.get_node_text(child).strip()
                        elif child.type not in ('+=', '-=', '*=', '/=', '%=', '='):
                            right_node = child

                    if left_node and op_text:
                        var_text = self.get_node_text(left_node).strip()
                        var_type = ("LVAR" if var_text in self.variables else
                                   "PVAR" if var_text in self.parameters else var_text)

                        # 복합 할당: a += 5 → a, a, +, 5
                        if op_text in ('+=', '-=', '*=', '/=', '%='):
                            result.append(f"(IDENTIFIER,{var_type})")  # 왼쪽
                            result.append(f"(IDENTIFIER,{var_type})")  # 다시 왼쪽

                            base_op = op_text[0]
                            if base_op in OPERATOR_MAP:
                                result.append(f"(OPERATOR,{OPERATOR_MAP[base_op]})")

                            if right_node:
                                traverse(right_node)
                        else:
                            # 일반 할당: a = 5
                            result.append(f"(IDENTIFIER,{var_type})")
                            if right_node:
                                traverse(right_node)

                case 'conditional_expression':
                    return

                case _:
                    for child in n.children:
                        traverse(child)

        traverse(node)
        return result

    def extract_function_parameters(self, call_node: Node) -> list[str]:
        """함수 호출의 매개변수 추출"""
        if not (args_node := call_node.child_by_field_name('arguments')):
            return []

        return [
            ';'.join(features)
            for arg in args_node.children
            if arg.type != ',' and (features := self.extract_condition(arg))
        ]

    def collect_variables(self, node: Node) -> None:
        """함수 내 변수 수집"""
        if node.type == 'declaration' and (declarator := node.child_by_field_name('declarator')):
            identifier = self._extract_declarator_identifier(declarator)
            if identifier:
                self.variables.add(identifier)

        # 재귀적으로 자식 노드 처리
        for child in node.children:
            self.collect_variables(child)

    def process_if_statement(self, node: Node, func_name: str) -> Optional[ControlBlock]:
        """if문 처리"""
        if not (condition := node.child_by_field_name('condition')):
            return None

        consequence = node.child_by_field_name('consequence')

        return ControlBlock(
            block_type=ControlBlockType.CONDITION,
            org_type=OrgType.IF,
            block_content=self.extract_block_content(consequence) if consequence else [],
            key_feature=self.extract_condition(condition)
        )

    def process_while_statement(self, node: Node, func_name: str) -> Optional[ControlBlock]:
        """while문 처리"""
        if not (condition := node.child_by_field_name('condition')):
            return None

        # 무한 루프 체크
        cond_text = self.get_node_text(condition).strip('()')
        key_features = (["(OPERATOR,InfiniteLoop)"] if cond_text in ('1', 'true')
                       else self.extract_condition(condition))

        body = node.child_by_field_name('body')

        return ControlBlock(
            block_type=ControlBlockType.LOOP,
            org_type=OrgType.WHILE,
            block_content=self.extract_block_content(body) if body else [],
            key_feature=key_features
        )

    def process_for_statement(self, node: Node, func_name: str) -> Optional[ControlBlock]:
        """for문 처리"""
        condition = node.child_by_field_name('condition')
        body = node.child_by_field_name('body')
        update = node.child_by_field_name('update')

        # 조건 추출 (없으면 무한 루프)
        key_features = (self.extract_condition(condition) if condition
                       else ["(OPERATOR,InfiniteLoop)"])

        # 블록 내용: update + body
        block_content = []
        if update:
            block_content.extend(self.extract_condition(update))
        if body:
            block_content.extend(self.extract_block_content(body))

        return ControlBlock(
            block_type=ControlBlockType.LOOP,
            org_type=OrgType.FOR,
            block_content=block_content,
            key_feature=key_features
        )

    def process_do_statement(self, node: Node, func_name: str) -> Optional[ControlBlock]:
        """do-while문 처리"""
        if not (condition := node.child_by_field_name('condition')):
            return None

        # 무한 루프 체크
        cond_text = self.get_node_text(condition).strip('()')
        key_features = (["(OPERATOR,InfiniteLoop)"] if cond_text in ('1', 'true')
                       else self.extract_condition(condition))

        body = node.child_by_field_name('body')

        return ControlBlock(
            block_type=ControlBlockType.LOOP,
            org_type=OrgType.DO_WHILE,
            block_content=self.extract_block_content(body) if body else [],
            key_feature=key_features
        )

    def process_switch_statement(self, node: Node, func_name: str) -> list[ControlBlock]:
        """switch문 처리"""
        blocks = []
        condition = node.child_by_field_name('condition')
        body = node.child_by_field_name('body')

        if not condition or not body:
            return blocks

        switch_condition = self.extract_condition(condition)

        # case 문 처리
        for child in body.children:
            if child.type == 'case_statement':
                value = child.child_by_field_name('value')
                if value:
                    case_value = self.extract_condition(value)
                    key_features = ["(<operator>.equals,none)"] + switch_condition + case_value

                    # case 본문 추출
                    block_content = []
                    for stmt in child.children:
                        if stmt.type not in ['case', ':', 'break_statement']:
                            block_content.extend(self.extract_block_content(stmt))

                    blocks.append(ControlBlock(
                        block_type=ControlBlockType.CONDITION.value,
                        org_type=OrgType.SWITCH.value,
                        block_content=block_content,
                        key_feature=key_features
                    ))

            elif child.type == 'default':
                # default 본문 추출
                block_content = []
                for stmt in child.children:
                    if stmt.type not in ['default', ':', 'break_statement']:
                        block_content.extend(self.extract_block_content(stmt))

                blocks.append(ControlBlock(
                    block_type=ControlBlockType.ELSE.value,
                    org_type=OrgType.SWITCH.value,
                    block_content=block_content,
                    key_feature=[]
                ))

        return blocks

    def process_call_expression(self, node: Node, func_name: str) -> Optional[ControlBlock]:
        """함수 호출 처리"""
        if not (callee := node.child_by_field_name('function')):
            return None

        callee_kind = self._classify_callee(callee)
        if callee_kind != "direct":
            return None

        called_func = self.get_node_text(callee).strip()

        # 제외할 함수 체크
        if any(called_func.startswith(sym) for sym in EXCLUDED_SYMBOLS):
            return None

        # 함수 타입 결정
        if called_func == func_name:
            block_type = ControlBlockType.RECURSIVE_FUNC
        elif called_func in LIBC_FUNCTIONS:
            block_type = ControlBlockType.LIBC_FUNC
            called_func = self.get_normalized_libc_name(called_func)
        else:
            block_type = ControlBlockType.CALLEE_FUNC

        # 매개변수 개수
        args_node = node.child_by_field_name('arguments')
        param_count = sum(1 for c in (args_node.children if args_node else [])
                         if c.type not in (',', '(', ')'))

        return ControlBlock(
            block_type=block_type,
            org_type=OrgType.FUNCTION_CALL,
            block_content=self.extract_function_parameters(node),
            key_feature=[f"{called_func},{param_count}"]
        )

    def process_string_literal(self, node: Node) -> Optional[ControlBlock]:
        """문자열 리터럴 처리"""
        text = self.get_node_text(node).strip().strip('"')

        if self.is_noise_string(text):
            return None

        if not (normalized := self.normalize_string(text)):
            return None

        return ControlBlock(
            block_type=ControlBlockType.STRING,
            org_type=OrgType.STRING,
            block_content=[],
            key_feature=[normalized]
        )

    def process_conditional_expression(self, node: Node) -> Optional[ControlBlock]:
        """삼항 연산자 처리 (condition ? true_expr : false_expr)"""
        condition = node.child_by_field_name('condition')
        consequence = node.child_by_field_name('consequence')

        if not condition:
            return None

        # key_feature: 조건 부분
        key_features = self.extract_condition(condition)

        # block_content: true 부분
        block_content = []
        if consequence:
            block_content = self.extract_condition(consequence)

        return ControlBlock(
            block_type=ControlBlockType.CONDITION,
            org_type=OrgType.ASSIGNMENT,
            block_content=block_content,
            key_feature=key_features
        )

    def process_return_with_condition(self, node: Node, func_name: str) -> Optional[ControlBlock]:
        """조건을 포함한 return문 처리 (삼항 연산자 제외)"""
        COND_OPS = {'equals', 'notEquals', 'lessThan', 'greaterThan', 'logicalAnd', 'logicalOr'}

        for child in node.children:
            # 삼항 연산자는 traverse_and_extract에서 별도로 처리되므로 스킵
            if child.type == 'conditional_expression':
                continue

            # 일반 조건식인 경우
            if child.type == 'binary_expression':
                key_features = self.extract_condition(child)

                # 조건 연산자 포함 여부 체크
                if any('OPERATOR' in f and any(op in f for op in COND_OPS) for f in key_features):
                    return ControlBlock(
                        block_type=ControlBlockType.CONDITION,
                        org_type=OrgType.RETURN,
                        block_content=[],
                        key_feature=key_features
                    )

        return None

    def extract_block_content(self, node: Node) -> list[str]:
        """블록 내용 추출"""
        CONTROL_STRUCTURES = {'if_statement', 'while_statement', 'for_statement',
                             'do_statement', 'switch_statement'}
        EXPRESSIONS = {'expression_statement', 'assignment_expression',
                      'binary_expression', 'call_expression'}

        content = []

        def traverse(n: Node) -> None:
            if n.type in CONTROL_STRUCTURES:
                return

            if n.type in EXPRESSIONS:
                content.extend(self.extract_condition(n))
            else:
                for child in n.children:
                    traverse(child)

        traverse(node)
        return content

    def process_function(self, func_node: Node) -> tuple[str, list[str]]:
        """함수 처리 및 분석"""
        self.parameters = []
        self.variables = set()

        # 함수명 추출
        declarator = func_node.child_by_field_name('declarator')
        if not declarator:
            return ("", [])

        func_name_node = declarator.child_by_field_name('declarator')
        if not func_name_node:
            # 직접 declarator가 함수명인 경우
            func_name_node = declarator

        func_name = self.get_node_text(func_name_node) if func_name_node else ""

        # 매개변수 추출
        params = declarator.child_by_field_name('parameters')
        if params:
            for param in params.children:
                if param.type == 'parameter_declaration':
                    param_declarator = param.child_by_field_name('declarator')
                    self.parameters.extend(
                        self._collect_identifiers_from_parameter_declarator(param_declarator)
                    )

        # 변수 수집
        body = func_node.child_by_field_name('body')
        if body:
            self.collect_variables(body)

        # 제어 블록 추출
        self.control_blocks = []
        if body:
            self.traverse_and_extract(body, func_name)

        # 함수 호출 목록 추출
        callees = [
            block.key_feature[0].split(',')[0]
            for block in self.control_blocks
            if block.block_type == ControlBlockType.CALLEE_FUNC.value
            and block.org_type == OrgType.FUNCTION_CALL.value
        ]

        return (func_name, callees)

    def traverse_and_extract(self, node: Node, func_name: str):
        """AST 탐색 및 제어 블록 추출"""
        # 제어 구조는 처리 후 내부를 자동으로 탐색하므로 자식 재귀를 건너뛰어야 함
        skip_children = False

        # if문
        if node.type == 'if_statement':
            block = self.process_if_statement(node, func_name)
            if block:
                self.control_blocks.append(block)

            # else문 처리
            alternative = node.child_by_field_name('alternative')
            if alternative:
                if alternative.type == 'else_clause':
                    # else의 body 추출
                    else_body = alternative.children[-1] if alternative.children else None
                    if else_body:
                        block_content = self.extract_block_content(else_body)
                        self.control_blocks.append(ControlBlock(
                            block_type=ControlBlockType.ELSE.value,
                            org_type=OrgType.ELSE.value,
                            block_content=block_content,
                            key_feature=[]
                        ))
                        # else 내부도 탐색
                        self.traverse_and_extract(else_body, func_name)

            # if문의 consequence와 alternative를 직접 탐색
            consequence = node.child_by_field_name('consequence')
            if consequence:
                self.traverse_and_extract(consequence, func_name)
            skip_children = True

        # while문
        elif node.type == 'while_statement':
            block = self.process_while_statement(node, func_name)
            if block:
                self.control_blocks.append(block)
            # 루프 내부 탐색
            body = node.child_by_field_name('body')
            if body:
                self.traverse_and_extract(body, func_name)
            skip_children = True

        # for문
        elif node.type == 'for_statement':
            block = self.process_for_statement(node, func_name)
            if block:
                self.control_blocks.append(block)
            # 루프 내부 탐색
            body = node.child_by_field_name('body')
            if body:
                self.traverse_and_extract(body, func_name)
            skip_children = True

        # do-while문
        elif node.type == 'do_statement':
            block = self.process_do_statement(node, func_name)
            if block:
                self.control_blocks.append(block)
            # 루프 내부 탐색
            body = node.child_by_field_name('body')
            if body:
                self.traverse_and_extract(body, func_name)
            skip_children = True

        # switch문
        elif node.type == 'switch_statement':
            blocks = self.process_switch_statement(node, func_name)
            self.control_blocks.extend(blocks)
            # switch 내부 case들도 탐색
            body = node.child_by_field_name('body')
            if body:
                for child in body.children:
                    if child.type in ('case_statement', 'default'):
                        self.traverse_and_extract(child, func_name)
            skip_children = True

        # 함수 호출
        elif node.type == 'call_expression':
            block = self.process_call_expression(node, func_name)
            if block:
                self.control_blocks.append(block)
            # 함수 호출은 자식 탐색 필요 (중첩 호출 등)

        # 문자열 리터럴
        elif node.type == 'string_literal':
            block = self.process_string_literal(node)
            if block:
                self.control_blocks.append(block)
            # 리터럴은 자식이 없음

        # 삼항 연산자
        elif node.type == 'conditional_expression':
            block = self.process_conditional_expression(node)
            if block:
                self.control_blocks.append(block)
            # 삼항 연산자 내부도 탐색 필요

        # return with condition
        elif node.type == 'return_statement':
            block = self.process_return_with_condition(node, func_name)
            if block:
                self.control_blocks.append(block)
            # return 내부도 탐색 필요

        # 자식 노드 재귀 탐색 (제어 구조가 아닌 경우만)
        if not skip_children:
            for child in node.children:
                self.traverse_and_extract(child, func_name)

    def build_vocabulary_from_blocks(self) -> Vocabulary:
        """Condition, Loop, Else 블록에서 어휘 구축"""
        all_elements = []

        for block in self.control_blocks:
            # Condition, Loop, Else 블록만 처리
            if block.block_type not in [ControlBlockType.CONDITION.value,
                                        ControlBlockType.LOOP.value,
                                        ControlBlockType.ELSE.value]:
                continue

            # key_feature 전처리
            if block.key_feature:
                elements = preprocess_key_feature(block.key_feature)
                elements = calculate_numbers(elements)
                elements = convert_logical_to_comparison(elements)
                all_elements.append(elements)

            # block_content 전처리
            if block.block_content:
                elements = preprocess_key_feature(block.block_content)
                elements = calculate_numbers(elements)
                elements = convert_logical_to_comparison(elements)
                all_elements.append(elements)

        return build_vocabulary(all_elements)

    def vectorize_blocks(self, src_function_count: int = 0):
        """Condition, Loop, Else 블록 벡터화"""
        # 어휘 구축
        self.vocabulary = self.build_vocabulary_from_blocks()

        # 각 블록 처리
        for block in self.control_blocks:
            # Condition, Loop, Else 블록은 벡터화
            if block.block_type in [ControlBlockType.CONDITION.value,
                                   ControlBlockType.LOOP.value,
                                   ControlBlockType.ELSE.value]:
                # key_feature 벡터화
                if block.key_feature:
                    kf_result, _ = vectorize_key_feature(
                        block.key_feature,
                        self.vocabulary,
                        src_function_count
                    )
                    # 벡터를 "10100...001" 형태의 문자열로 변환
                    block.key_feature_vector = ''.join(str(int(v)) for v in kf_result.exact_vector)
                    block.key_feature_dvector = {
                        "numbers": kf_result.numbers,
                        "literal_values": kf_result.literal_values,
                        "function_values": kf_result.function_values,
                        "function_count": kf_result.function_count,
                        "numtype_count": len(kf_result.num_type_positions)
                    }

                # block_content 벡터화
                if block.block_content:
                    bc_result, _ = vectorize_key_feature(
                        block.block_content,
                        self.vocabulary,
                        src_function_count
                    )
                    # 벡터를 "10100...001" 형태의 문자열로 변환
                    block.block_content_vector = ''.join(str(int(v)) for v in bc_result.exact_vector)
                    block.block_content_dvector = {
                        "numbers": bc_result.numbers,
                        "literal_values": bc_result.literal_values,
                        "function_values": bc_result.function_values,
                        "function_count": bc_result.function_count,
                        "numtype_count": len(bc_result.num_type_positions)
                    }

            else:
                # 나머지 블록은 타입별로 처리
                if block.block_type in [ControlBlockType.LIBC_FUNC.value,
                                       ControlBlockType.CALLEE_FUNC.value,
                                       ControlBlockType.RECURSIVE_FUNC.value]:
                    # 함수 블록: key_feature = ["function_name,param_count"]
                    if block.key_feature:
                        func_info = block.key_feature[0].split(',')

                        # 함수명과 파라미터 개수 추출
                        func_name = func_info[0] if len(func_info) > 0 else ""
                        param_count = 0

                        if len(func_info) >= 2:
                            try:
                                param_count = int(func_info[1])
                            except ValueError:
                                param_count = 0

                        block.key_feature_dvector = {
                            "function_values": [func_name] if func_name else [""],
                            "param_numbers": [param_count]
                        }

                    # block_content: params로 저장
                    if block.block_content:
                        block.block_content_dvector = {"param_values": block.block_content}

                elif block.block_type == ControlBlockType.STRING.value:
                    # String 블록: key_feature = ["string_value"]
                    if block.key_feature:
                        block.key_feature_dvector = {
                            "literal_values": block.key_feature
                        }

                else:
                    # 기타 블록은 비워둠
                    pass

    def analyze_file(self, file_path: str, output_path: str) -> tuple[str, list[str]]:
        """파일 분석 및 Control Block 생성"""
        # 파일 파싱
        self.parse_file(file_path)

        # 루트 노드에서 함수 찾기
        root_node = self.tree.root_node

        # 첫 번째 함수 정의 찾기 (여러 함수가 있을 경우 확장 가능)
        function_nodes = []

        def find_functions(node: Node):
            if node.type == 'function_definition':
                function_nodes.append(node)
            for child in node.children:
                find_functions(child)

        find_functions(root_node)

        if not function_nodes:
            # 함수가 없어도 빈 JSON 생성 (출력 억제)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump([], f, indent=2, ensure_ascii=False)
            return ("", [])

        # 첫 번째 함수 처리 (메인 함수 또는 분석 대상)
        func_name, callees = self.process_function(function_nodes[0])

        # 벡터화 수행
        src_function_count = len(callees)
        self.vectorize_blocks(src_function_count)

        # JSON 출력 (block_content와 key_feature 제외)
        blocks_dict = []
        for block in self.control_blocks:
            block_dict = asdict(block)
            # block_content와 key_feature 제거
            block_dict.pop('block_content', None)
            block_dict.pop('key_feature', None)
            blocks_dict.append(block_dict)

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(blocks_dict, f, indent=2, ensure_ascii=False)

        # 출력 억제 (Preprocessor에서 관리)
        # print(f"[+] Control Block created: {output_path}")
        # print(f"[+] Block count: {len(self.control_blocks)}")

        return (func_name, callees)


def function_preprocessing(file_path):
    input_file = file_path
    output_file = f"{file_path.split('.')[0]}.json"

    # 입력 파일 확인
    if not Path(input_file).exists():
        print(f"[!] File not found: {input_file}")
        sys.exit(1)

    # 언어 판단
    language = 'cpp' if input_file.endswith('.cpp') or input_file.endswith('.cc') else 'c'

    # 분석 실행
    analyzer = CBMaker(language=language)
    func_name, callees = analyzer.analyze_file(input_file, output_file)

    print(f"\n[+] Analysis completed!")
    print(f"    Function name: {func_name}")
    print(f"    Called functions: {', '.join(callees) if callees else 'None'}")




def main():
    if len(sys.argv) < 2:
        print("\nUsage: python main_with_vectors.py <input_file.c> [output_file.json]")
        print("\nExample:")
        print("  python main_with_vectors.py test.c")
        print("  python main_with_vectors.py test.c output.json")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else "control_blocks.json"

    # 입력 파일 확인
    if not Path(input_file).exists():
        print(f"[!] File not found: {input_file}")
        sys.exit(1)

    # 언어 판단
    language = 'cpp' if input_file.endswith('.cpp') or input_file.endswith('.cc') else 'c'

    # 분석 실행
    analyzer = CBMaker(language=language)
    func_name, callees = analyzer.analyze_file(input_file, output_file)

    print(f"\n[+] Analysis completed!")
    print(f"    Function name: {func_name}")
    print(f"    Called functions: {', '.join(callees) if callees else 'None'}")


if __name__ == "__main__":
    main()
