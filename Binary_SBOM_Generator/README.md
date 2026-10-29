# Binary SCA Tool

바이너리에 포함된 오픈소스(OSS) 컴포넌트를 탐지하는 **Binary Software Composition Analysis** 도구

OSS 소스코드로 컴포넌트 DB를 구축하고, 대상 바이너리를 디컴파일·전처리한 뒤 DB와 대조하여
바이너리가 어떤 오픈소스에 의존하는지 탐지하고 SBOM(CycloneDX)을 생성합니다.



```
OSS 소스 수집  →  컴포넌트 DB 구축  →  바이너리 전처리  →  탐지  →  (정답 채점 가능)  →  SBOM 생성
```

---

## 사전 필요 환경

- **JDK 21 이상** (Ghidra 헤드리스 디컴파일에 필요)
- **universal-ctags**
- **Python + [uv](https://github.com/astral-sh/uv)**

```bash
# universal-ctags 설치 (Debian/Ubuntu)
sudo apt-get install -y universal-ctags
```

### 외부 도구 설치 (Ghidra 등)

Ghidra 및 ctags를 한 번에 설치하려면 아래 스크립트를 사용합니다.

```bash
bash tools/external_tools_install.sh
```

### 의존성 설치

```bash
uv sync
```

> Docker 이미지로 실행하려면 레포에 포함된 `Dockerfile`을 사용하면 됩니다.

---

## 사용 방법

### 1. OSS 소스 수집

`osscollector/repolist.txt` 에 수집할 저장소 주소와 다운로드할 버전을 아래 예시 형식으로 작성합니다.

```
# <repo 주소>, <library|application>, ["버전 태그", ...]
https://github.com/madler/zlib.git, library, ["v1.3.2"]
https://gitlab.com/bzip2/bzip2.git, library, ["bzip2-1.0.8"]
https://github.com/inikep/lzbench.git, application
```

작성 후 수집을 실행합니다.

```bash
uv run python src/OSScollector.py osscollector
```

### 2. 컴포넌트 DB 구축

수집한 OSS 소스로부터 탐지에 사용할 컴포넌트 DB를 만듭니다.

```bash
uv run python src/preprocessor.py
```

### 3. 바이너리 전처리

`testset/bin` 에 있는 **모든 바이너리**를 디컴파일 및 전처리합니다. (시간이 꽤 오래 걸립니다.)

```bash
uv run python src/bin_preprocessor.py
```

### 4. 탐지

`testset/bin` 에 있는 바이너리를 컴포넌트 DB와 대조하여 의존성을 탐지합니다.

```bash
# 전체 바이너리 탐지
uv run python src/detector.py

# 특정 바이너리만 단독 탐지
uv run python src/detector.py bzip2_x64_O0
```

탐지 결과는 `output/` 디렉터리에 바이너리별로 저장됩니다.

> `uv run python src/detector.py --llm` 옵션은 내부 서버에 셋팅된 Ollama 기반 LLM 검증기를
> 사용하므로 일반 환경에서는 동작하지 않습니다. (내부 모델 테스트용이므로 무시하셔도 됩니다.)

### 5. Ground Truth 채점

`testset/ground_truth.json` 에 각 바이너리별 정답 컴포넌트(DB에 존재하는 컴포넌트 이름)를
아래 형식으로 넣으면 `report.py` 로 탐지 정답 여부를 확인할 수 있습니다.

```json
{
  "bzip2_x64_O0": ["bzip2@@bzip2"],
  "cknit_x64_O0": ["josinli@@cknit"]
}
```

```bash
# 전체 채점
uv run python src/report.py

# 특정 바이너리만 채점
uv run python src/report.py bzip2_x64_O0

# JSON 리포트로 저장
uv run python src/report.py --json report.json
```

### 6. SBOM 생성

정답 여부와 무관하게, `testset/bin` 의 테스트셋과 `output/` 의 탐지 결과를 바탕으로
CycloneDX SBOM을 생성합니다.

```bash
uv run python src/Binary_SBOM_Generation.py
```

---

## `bin-sbom` CLI (단일 바이너리)

위 4~6단계를 한 번에 수행해 CycloneDX SBOM을 **stdout으로** 내보내는 CLI입니다. bolt가
`--binary-sbom bin-sbom` 으로 호출하는 진입점이며, 단독으로도 쓸 수 있습니다.

```bash
pip install .        # 또는 uv build 로 휠 생성
bin-sbom sbom --stdout -i /usr/bin/curl --db /path/to/Binary_SBOM_Generator
```

호출마다 임시 작업 디렉터리를 만들어 대상 바이너리 하나만 스테이징한 뒤 그 안에서 위
파이프라인을 그대로 실행합니다. 진행 로그는 stderr로, SBOM만 stdout으로 나갑니다.

| 옵션 | 설명 |
|---|---|
| `-i, --input` | 대상 바이너리 경로 |
| `--db` | `database/` 와 `osscollector/repo_meta/` 를 포함하는 상위 경로 (기본값 `$BIN_SBOM_DB`) |
| `--database`, `--repo-meta` | 두 경로가 떨어져 있을 때 개별 지정 |
| `--ghidra` | Ghidra 설치 경로 (기본값 `$BIN_SBOM_GHIDRA`) |
| `--display-path` | 대상이 임시 추출본일 때, SBOM에 기록할 원래 경로 |
| `-o, --output` | stdout 대신 파일로 저장 |
| `--keep-workdir` | 디버깅용으로 임시 작업 디렉터리 보존 |

사전 구축한 DB가 없거나 불완전하면 종료 코드 3과 함께 안내 메시지를 출력합니다.
특히 `repo_meta/` 가 없으면 탐지는 되어도 컴포넌트 메타데이터를 못 붙여 SBOM이 비게 되므로,
CLI가 시작 시 `database/` 와 함께 검사합니다.

탐지기가 출력하는 `version`과 `purl`의 버전은 수집 DB의 참조 메타데이터이며, 바이너리에서
확인한 설치 버전이 아닙니다. 기존 필드는 호환성을 위해 유지하며 각 컴포넌트의 CycloneDX
`properties`에 다음 출처를 함께 기록합니다.

| 속성 | 값 |
|---|---|
| `bolt:binary:version-source` | `reference-metadata` |
| `bolt:binary:component-id` | 전체 저장소 식별자, 예: `madler@@zlib` |
| `bolt:binary:reference-ref` | 정규화 전 수집 ref, 예: `v1.3.1` |

취약점 매칭 시 이 참조 버전을 바이너리의 확정 버전으로 사용해서는 안 됩니다.
별도로 제공한 컴포넌트 JSON의 `cpe`와 `evidence`는 SBOM 생성 시 보존합니다.

이 전달 경로는 DB나 Ghidra 없이 표준 라이브러리 테스트로 확인할 수 있습니다.

```bash
python -B -m unittest discover -s tests -v
```

---

## 디렉터리 구조

```
.
├── src/                       # 소스 코드
│   ├── OSScollector.py          # 1. OSS 소스 수집
│   ├── preprocessor.py          # 2. 컴포넌트 DB 구축
│   ├── bin_preprocessor.py      # 3. 바이너리 디컴파일·전처리
│   ├── detector.py              # 4. 의존성 탐지
│   ├── report.py                # 5. Ground Truth 채점
│   ├── Binary_SBOM_Generation.py# 6. SBOM 생성
│   ├── cyclonedx_sbom_gen.py    #    CycloneDX SBOM 생성 로직
│   ├── llm_verifier.py          #    (선택) LLM 기반 오탐 검증
│   └── utils/                   #    전처리·유사도 측정 유틸
├── osscollector/
│   └── repolist.txt           # 수집 대상 저장소 목록
├── database/                  # 구축된 컴포넌트 DB / provenance
├── testset/
│   ├── bin/                   # 탐지 대상 바이너리
│   └── ground_truth.json      # 정답 데이터
├── output/                    # 탐지 결과 / SBOM 출력
├── tools/
│   ├── ghidra/                # Ghidra 헤드리스
│   └── external_tools_install.sh
└── pyproject.toml
```

---
## 참고사항
- 아직 완성된 단계가 아니므로 Stripped 바이너리 분석은 아직 성능이 좋지 않습니다.

## Contact
 고려대학교 소프트웨어보안연구실 박사과정 양희동 (heedongy@korea.ac.kr)
 
