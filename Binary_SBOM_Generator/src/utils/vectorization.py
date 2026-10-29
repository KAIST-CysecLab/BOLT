from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Tuple, Optional
import numpy as np
from .function_list import LIBC_FUNCTIONS


class BCVType(Enum):
    NUM = "BCVNum"
    NUM_TYPE = "BCVNumType"
    ELEMENT_TYPE = "BCVElementType"
    OPERATOR = "BCVOperator"
    LITERAL_VALUE = "BCVLiteralValue"
    FUNCTION_VALUE = "BCVFunctionValue"
    FUNCTION_COUNT = "BCVFunctionCount"


@dataclass
class BCVElement:
    type: BCVType
    value: any = None


@dataclass
class Vocabulary:
    element_type_to_index: Dict[str, int] = field(default_factory=dict)
    operator_to_index: Dict[str, int] = field(default_factory=dict)
    libc_func_to_index: Dict[str, int] = field(default_factory=dict)
    function_count_index: int = 0

    literal_value_to_index: Dict[str, int] = field(default_factory=dict)
    function_value_to_index: Dict[str, int] = field(default_factory=dict)
    number_to_index: Dict[int, int] = field(default_factory=dict)

    next_index: int = 0


@dataclass
class BlockContentVector:
    exact_vector: np.ndarray
    num_type_positions: List[int] = field(default_factory=list)
    numbers: List[int] = field(default_factory=list)
    literal_values: List[str] = field(default_factory=list)
    function_values: List[str] = field(default_factory=list)
    function_count: int = 0


def classify_operator(operator_value: str) -> str:
    operator_map = {
        "equals": "equOpr",
        "notEquals": "equOpr",
        "lessThan": "comOpr",
        "greaterThan": "comOpr",
        "lessEqualsThan": "comOpr",
        "greaterEqualsThan": "comOpr",
        "InfiniteLoop": "InfiniteLoop",
        "addition": "addOpr",
        "assignmentPlus": "addOpr",
        "subtraction": "subOpr",
        "assignmentMinus": "subOpr",
        "multiplication": "mulOpr",
        "assignmentMultiplication": "mulOpr",
        "division": "divOpr",
        "assignmentDivision": "divOpr",
        "modulo": "modOpr",
        "assignmentModulo": "modOpr",
        "logicalNot": "notOpr",
        "not": "notOpr",
        "logicalXor": "xorOpr",
        "xor": "xorOpr",
        "indirectFieldAccess": "accOpr",
        "fieldAccess": "accOpr",
        "indirectIndexAccess": "accOpr",
        "shiftLeft": "shiftOpr",
        "arithmeticShiftLeft": "shiftOpr",
        "shiftRight": "shiftOpr",
        "arithmeticShiftRight": "shiftOpr",
        "assignmentArithmeticShiftLeft": "shiftOpr",
        "assignmentArithmeticShiftRight": "shiftOpr",
        "logicalAnd": "logAndOrOpr",
        "logicalOr": "logAndOrOpr",
        "or": "bitAndOrOpr",
        "and": "bitAndOrOpr",
        "assignment": "assignOpr",
    }
    return operator_map.get(operator_value, "UnknownOpr")


def get_ascii_value(char_value: str) -> int:
    """ASCII 값 변환 (Utils.fs의 getAsciiValue)"""
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


def process_literal_value(value: str) -> Tuple[str, Optional[int]]:
    # 단일 문자 리터럴 'a'
    if len(value) == 3 and value.startswith("'") and value.endswith("'"):
        char_value = value[1:2]
        return ("ASCII", get_ascii_value(char_value))

    # 이스케이프 문자 리터럴 '\n'
    elif len(value) == 4 and value.startswith("'\\") and value.endswith("'"):
        escape_seq = value[1:3]
        return ("ASCII", get_ascii_value(escape_seq))

    return ("LITERAL", None)


def create_base_vocabulary() -> Vocabulary:
    element_types = ["LVAR", "PVAR"]
    operators = [
        "equOpr", "comOpr", "InfiniteLoop", "assignOpr",
        "addOpr", "subOpr", "mulOpr", "divOpr", "modOpr",
        "notOpr", "xorOpr", "accOpr", "shiftOpr",
        "logAndOrOpr", "bitAndOrOpr"
    ]

    vocab = Vocabulary()

    # Element types
    for i, et in enumerate(element_types):
        vocab.element_type_to_index[et] = i

    # Operators
    offset = len(element_types)
    for i, op in enumerate(operators):
        vocab.operator_to_index[op] = offset + i

    # LibC functions
    offset = len(element_types) + len(operators)
    libc_list = sorted(list(LIBC_FUNCTIONS))
    for i, func in enumerate(libc_list):
        vocab.libc_func_to_index[func] = offset + i

    # Function count index
    static_count = len(element_types) + len(operators) + len(libc_list)
    vocab.function_count_index = static_count

    # Dynamic start index
    vocab.next_index = static_count + 1

    return vocab


def preprocess_key_feature(key_feature: List[str]) -> List[BCVElement]:
    """key_feature를 BCVElement로 전처리"""
    elements = []
    function_names = set()
    i = 0

    while i < len(key_feature):
        item = key_feature[i].strip('()').split(',')
        if len(item) < 2:
            i += 1
            continue

        element_type = item[0].strip()
        value = item[1].strip()

        if element_type == "NUM":
            try:
                num_value = int(value)
                elements.append(BCVElement(BCVType.NUM, num_value))
            except ValueError:
                pass
            i += 1

        elif element_type == "NUMTYPE":
            elements.append(BCVElement(BCVType.NUM_TYPE, None))
            i += 1

        elif element_type in ("IDENTIFIER", "POINTERVAR"):
            if "PVAR" in value:
                elements.append(BCVElement(BCVType.ELEMENT_TYPE, "PVAR"))
            elif value == "false":
                elements.append(BCVElement(BCVType.NUM, 0))
            elif value == "true":
                elements.append(BCVElement(BCVType.NUM, 1))
            else:
                elements.append(BCVElement(BCVType.ELEMENT_TYPE, "LVAR"))
            i += 1

        elif element_type == "LITERAL":
            lit_type, ascii_val = process_literal_value(value)
            if lit_type == "ASCII" and ascii_val is not None:
                elements.append(BCVElement(BCVType.NUM, ascii_val))
            else:
                elements.append(BCVElement(BCVType.LITERAL_VALUE, value))
            i += 1

        elif element_type in ("FUNCTION", "FUNCTION_STRIPPED"):
            function_names.add(value)
            elements.append(BCVElement(BCVType.FUNCTION_VALUE, value))
            i += 1

        elif element_type == "LIBCFUNC":
            elements.append(BCVElement(BCVType.ELEMENT_TYPE, value))
            i += 1

        elif element_type == "OPERATOR":
            operator_class = classify_operator(value)

            # 특수 연산자 처리
            if value in ("preIncrement", "postIncrement"):
                elements.append(BCVElement(BCVType.OPERATOR, "addOpr"))
                elements.append(BCVElement(BCVType.NUM, 1))
            elif value in ("preDecrement", "postDecrement"):
                elements.append(BCVElement(BCVType.OPERATOR, "addOpr"))
                elements.append(BCVElement(BCVType.NUM, -1))
            elif value == "minus":
                # 다음 요소가 NUM이면 음수로 처리
                if i + 1 < len(key_feature):
                    next_item = key_feature[i + 1].strip('()').split(',')
                    if len(next_item) >= 2 and next_item[0].strip() == "NUM":
                        try:
                            num_val = int(next_item[1].strip())
                            elements.append(BCVElement(BCVType.NUM, -num_val))
                            i += 1  # skip next
                        except ValueError:
                            elements.append(BCVElement(BCVType.OPERATOR, "subOpr"))
                    else:
                        elements.append(BCVElement(BCVType.OPERATOR, "subOpr"))
                else:
                    elements.append(BCVElement(BCVType.OPERATOR, "subOpr"))
            elif value == "lessEqualsThan":
                # x <= n → x < (n+1)
                if i + 1 < len(key_feature):
                    next_item = key_feature[i + 1].strip('()').split(',')
                    if len(next_item) >= 2 and next_item[0].strip() == "NUM":
                        try:
                            num_val = int(next_item[1].strip())
                            if num_val < 2**63 - 1:  # INT64_MAX check
                                elements.append(BCVElement(BCVType.OPERATOR, "comOpr"))
                                elements.append(BCVElement(BCVType.NUM, num_val + 1))
                                i += 1
                            else:
                                elements.append(BCVElement(BCVType.OPERATOR, "comOpr"))
                        except ValueError:
                            elements.append(BCVElement(BCVType.OPERATOR, "comOpr"))
                    else:
                        elements.append(BCVElement(BCVType.OPERATOR, "comOpr"))
                else:
                    elements.append(BCVElement(BCVType.OPERATOR, "comOpr"))
            elif value == "greaterEqualsThan":
                # x >= n → x > (n-1)
                if i + 1 < len(key_feature):
                    next_item = key_feature[i + 1].strip('()').split(',')
                    if len(next_item) >= 2 and next_item[0].strip() == "NUM":
                        try:
                            num_val = int(next_item[1].strip())
                            if num_val > -2**63:  # INT64_MIN check
                                elements.append(BCVElement(BCVType.OPERATOR, "comOpr"))
                                elements.append(BCVElement(BCVType.NUM, num_val - 1))
                                i += 1
                            else:
                                elements.append(BCVElement(BCVType.OPERATOR, "comOpr"))
                        except ValueError:
                            elements.append(BCVElement(BCVType.OPERATOR, "comOpr"))
                    else:
                        elements.append(BCVElement(BCVType.OPERATOR, "comOpr"))
                else:
                    elements.append(BCVElement(BCVType.OPERATOR, "comOpr"))
            else:
                elements.append(BCVElement(BCVType.OPERATOR, operator_class))
            i += 1
        else:
            i += 1

    # function count 추가
    if function_names:
        elements.insert(0, BCVElement(BCVType.FUNCTION_COUNT, len(function_names)))

    return elements


def calculate_numbers(elements: List[BCVElement]) -> List[BCVElement]:
    result = []
    i = 0

    while i < len(elements):
        if i + 2 < len(elements):
            # 연산자 + 두 개의 숫자 패턴
            if (elements[i].type == BCVType.OPERATOR and
                elements[i+1].type == BCVType.NUM and
                elements[i+2].type == BCVType.NUM):

                op = elements[i].value
                n1 = elements[i+1].value
                n2 = elements[i+2].value

                if op == "addOpr":
                    result.append(BCVElement(BCVType.NUM, n1 + n2))
                    i += 3
                    continue
                elif op == "subOpr":
                    result.append(BCVElement(BCVType.NUM, n1 - n2))
                    i += 3
                    continue
                elif op == "mulOpr":
                    result.append(BCVElement(BCVType.NUM, n1 * n2))
                    i += 3
                    continue
                elif op == "divOpr" and n2 != 0:
                    result.append(BCVElement(BCVType.NUM, n1 // n2))
                    i += 3
                    continue
                elif op == "modOpr" and n2 != 0:
                    result.append(BCVElement(BCVType.NUM, n1 % n2))
                    i += 3
                    continue

        if i + 1 < len(elements):
            # 단항 연산자 + 숫자 패턴
            if (elements[i].type == BCVType.OPERATOR and
                elements[i].value == "notOpr" and
                elements[i+1].type == BCVType.NUM):
                result.append(BCVElement(BCVType.NUM, ~elements[i+1].value))
                i += 2
                continue

        result.append(elements[i])
        i += 1

    return result


def convert_logical_to_comparison(elements: List[BCVElement]) -> List[BCVElement]:
    """논리 표현을 비교 표현으로 변환"""
    # LVAR 하나만 있는 경우 → LVAR == 0
    if len(elements) == 1 and elements[0].type == BCVType.ELEMENT_TYPE and elements[0].value == "LVAR":
        return [
            BCVElement(BCVType.OPERATOR, "equOpr"),
            BCVElement(BCVType.ELEMENT_TYPE, "LVAR"),
            BCVElement(BCVType.NUM, 0)
        ]

    # !LVAR → LVAR == 0
    if (len(elements) == 2 and
        elements[0].type == BCVType.OPERATOR and elements[0].value == "notOpr" and
        elements[1].type == BCVType.ELEMENT_TYPE and elements[1].value == "LVAR"):
        return [
            BCVElement(BCVType.OPERATOR, "equOpr"),
            BCVElement(BCVType.ELEMENT_TYPE, "LVAR"),
            BCVElement(BCVType.NUM, 0)
        ]

    return elements


def build_vocabulary(elements_list: List[List[BCVElement]]) -> Vocabulary:
    """여러 요소 리스트로부터 어휘 구축"""
    vocab = create_base_vocabulary()

    for elements in elements_list:
        for elem in elements:
            if elem.type == BCVType.LITERAL_VALUE:
                if elem.value not in vocab.literal_value_to_index:
                    vocab.literal_value_to_index[elem.value] = vocab.next_index
                    vocab.next_index += 1

            elif elem.type == BCVType.FUNCTION_VALUE:
                if elem.value not in vocab.function_value_to_index:
                    vocab.function_value_to_index[elem.value] = vocab.next_index
                    vocab.next_index += 1

            elif elem.type == BCVType.NUM:
                if elem.value not in vocab.number_to_index:
                    vocab.number_to_index[elem.value] = vocab.next_index
                    vocab.next_index += 1

    return vocab


def vectorize(elements: List[BCVElement], vocabulary: Vocabulary, src_function_count: int = 0) -> BlockContentVector:
    """요소를 벡터로 변환"""
    vector = np.zeros(vocabulary.next_index, dtype=np.float64)
    num_type_positions = []
    numbers = []
    literal_values = []
    function_values = []
    function_count = 0
    position = 0

    for elem in elements:
        if elem.type == BCVType.NUM:
            numbers.append(elem.value)
            if elem.value in vocabulary.number_to_index:
                idx = vocabulary.number_to_index[elem.value]
                vector[idx] = 1.0  # Binary vector: 0 or 1 only

        elif elem.type == BCVType.NUM_TYPE:
            num_type_positions.append(position)

        elif elem.type == BCVType.ELEMENT_TYPE:
            # LVAR, PVAR
            if elem.value in vocabulary.element_type_to_index:
                idx = vocabulary.element_type_to_index[elem.value]
                vector[idx] = 1.0  # Binary vector: 0 or 1 only
            # LibC functions
            elif elem.value in vocabulary.libc_func_to_index:
                idx = vocabulary.libc_func_to_index[elem.value]
                vector[idx] = 1.0  # Binary vector: 0 or 1 only

        elif elem.type == BCVType.OPERATOR:
            if elem.value in vocabulary.operator_to_index:
                idx = vocabulary.operator_to_index[elem.value]
                vector[idx] = 1.0  # Binary vector: 0 or 1 only

        elif elem.type == BCVType.LITERAL_VALUE:
            literal_values.append(elem.value)
            if elem.value in vocabulary.literal_value_to_index:
                idx = vocabulary.literal_value_to_index[elem.value]
                vector[idx] = 1.0  # Binary vector: 0 or 1 only

        elif elem.type == BCVType.FUNCTION_VALUE:
            function_values.append(elem.value)
            if elem.value in vocabulary.function_value_to_index:
                idx = vocabulary.function_value_to_index[elem.value]
                vector[idx] = 1.0  # Binary vector: 0 or 1 only

        elif elem.type == BCVType.FUNCTION_COUNT:
            function_count = elem.value
            # src_function_count와 일치하면 1.0, 아니면 0.0
            vector[vocabulary.function_count_index] = 1.0 if elem.value == src_function_count else 0.0

        position += 1

    return BlockContentVector(
        exact_vector=vector,
        num_type_positions=num_type_positions,
        numbers=numbers,
        literal_values=literal_values,
        function_values=function_values,
        function_count=function_count
    )


def vectorize_key_feature(key_feature: List[str], vocabulary: Optional[Vocabulary] = None, src_function_count: int = 0) -> Tuple[BlockContentVector, Vocabulary]:
    """
    key_feature를 벡터화

    Args:
        key_feature: key_feature 리스트 (예: ["(OPERATOR,equals)", "(IDENTIFIER,LVAR)", "(NUM,0)"])
        vocabulary: 기존 어휘 (없으면 새로 생성)
        src_function_count: 소스 함수 카운트

    Returns:
        (벡터화 결과, 어휘)
    """
    # 1. 전처리
    elements = preprocess_key_feature(key_feature)

    # 2. 숫자 계산
    elements = calculate_numbers(elements)

    # 3. 논리→비교 변환
    elements = convert_logical_to_comparison(elements)

    # 4. 어휘 구축 (새로운 어휘가 필요한 경우)
    if vocabulary is None:
        vocabulary = build_vocabulary([elements])

    # 5. 벡터화
    vector_result = vectorize(elements, vocabulary, src_function_count)

    return vector_result, vocabulary


def get_static_vocabulary_info(vocabulary: Vocabulary) -> Dict:
    return {
        "element_types": vocabulary.element_type_to_index,
        "operators": vocabulary.operator_to_index,
        "libc_functions": vocabulary.libc_func_to_index,
        "function_count_index": vocabulary.function_count_index,
        "static_size": vocabulary.function_count_index + 1,
        "total_size": vocabulary.next_index
    }


def get_dynamic_elements(vector_result: BlockContentVector) -> Dict:
    return {
        "numbers": vector_result.numbers,
        "literal_values": vector_result.literal_values,
        "function_values": vector_result.function_values,
        "function_count": vector_result.function_count,
        "numtype_count": len(vector_result.num_type_positions)
    }


if __name__ == "__main__":
    test_key_feature = [
        "(IDENTIFIER,LVAR)",
        "(OPERATOR,lessThan)",
        "(NUM,10)"
    ]

    print("=== 벡터화 테스트 ===")
    print(f"입력 key_feature: {test_key_feature}")

    vector_result, vocab = vectorize_key_feature(test_key_feature)

    print(f"\n정적 벡터 크기: {len(vector_result.exact_vector)}")
    print(f"정적 벡터: {''.join(str(int(v)) for v in vector_result.exact_vector)}")

    print(f"\n동적 요소:")
    dynamic = get_dynamic_elements(vector_result)
    for key, val in dynamic.items():
        if val:
            print(f"  {key}: {val}")

    print(f"\n어휘 정보:")
    static_info = get_static_vocabulary_info(vocab)
    print(f"  정적 크기: {static_info['static_size']}")
    print(f"  전체 크기: {static_info['total_size']}")


