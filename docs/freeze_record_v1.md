# Freeze record v1

Record behind the git tag `data-freeze-v1.2`. Generated 2026-10-22 11:51 CEST by `scripts/make_freeze_record.sh`.

## Frozen commit

- Commit: `14831572602304c5385cb2788bfa429378f85754` (branch `docs/freeze-v1.2`)
- The tag points to the commit that adds this file, which is this commit plus the record itself.

## Validation

| Step | Exit code |
|---|---|
| `bash scripts/rerun_analyses.sh` | 0 |
| `python scripts/rescore_sanitised.py` | 0 |
| `python scripts/analyze_condition_c.py` | 0 |

After the re-runs no tracked file changed: every `results.json`, table and figure reproduces byte for byte.

## Checksums (SHA-256, tracked files only)

Run outputs, inputs, payloads, prompts and analysis results. Verify with `shasum -a 256 -c` on the block below.

```
8f1ed9b51d77483ab88a3d4a42fe2fda96d8cdaa13b69224473e7b3b26422d3d  data/frozen/access_v1.jsonl
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  data/processed/.gitkeep
3500cc2cef27e4514114aec17867a24eff903e757ead573a33c242d1527d35d9  data/processed/benign_control_v1.csv
0a945a30ac2e7fa91ea4b2c0d402b0c6c60ba06b04e873e78da08ca081d8235a  data/processed/controls_v1.csv
9ead1d81aac9216dfb063ed7cb1e0908ed8adf12644404860bcc444cd7d2c517  data/processed/detector_output_v1.csv
77cfa1be830bad965e624d223c886c5e5e806b3313a98e4576395dd26e6a895e  data/processed/detector_sanitised_v1.csv
02b2d2c6a6801255adf1fe28cb11af849931f792455af0c138ac6ad25ec27f9a  data/processed/events_detector_v1.csv
cf8892e3bde9ee2eacb8c013708664653b84deb0afb1ed4b7df19ed9e2ffc9c0  data/processed/events_labelled.csv
fff6ac6d132460b7a3e832f893de0d574763c1370087a42b4f4b17903739aef0  data/processed/experiment_events.csv
50c2d52c4d1c70c9851e5203bc804687ba1751bb12365a4abe2bce2a62f5631e  data/processed/injected_cases_bclean_v1.csv
08240d7cd70ed34d88b5dba30c112b83ea49e2885f98c9330bd50b9a9de24722  data/processed/injected_cases_subset_v1.csv
550b1009d3915e2f9e09857835bbc26ac6f397ef6d67f1fcf98e0af1ad932a20  data/processed/injected_cases_v1.csv
2a5bf7e9aa13df7dab82e5589b2f513792a788d3caaf14b3e5c13e8a7efb71c2  data/processed/srbh/srbh_benign_v1.csv
53a857c7df120f8b1de778161b5942b233127cbf2baaeea747777ab124c4f896  data/processed/srbh/srbh_cases_clean_v1.csv
d26b4d34647058af4709fc98271382af0fb735dfb58d45f6487cdd460a793cad  data/processed/srbh/srbh_cases_v1.csv
6c132700bd097f43ed38e8553815375275a124373042787efc312c9548ed9438  data/processed/srbh/srbh_detector_output_v1.csv
a427dbadd6c34ffed8fdd0bcf7a7f7b6b10d85640d86e066836e00e7a9d476c2  data/processed/srbh/srbh_events_v1.csv
c7e6b1ea4d528df2cacfd184d1ba009ac93d07dd7613ac6bd5510618f913811f  data/processed/srbh/srbh_label_check_v1.csv
9a9246ff3de91c99583bc916bdb85766f03ae93a857a276f61f3d7e59ddaf2bd  data/processed/srbh/srbh_label_check_v1_bakhtier.csv
0ebbacc4bc39a91f9fde8154e02af1f3f3ad2a18462b4e9e6422ec2dcc146fff  data/processed/srbh/srbh_slice_v1.jsonl
fa6f5d53216f70a470a0891789d7001b88240f237b45fbf07f0f3cd03150460a  data/processed/subset_v1_case_ids.csv
4dfcd7ab5fdeedefe7cc2301c18de330b9679676fff2d8e4fc3fa42bce5ae334  data/processed/subset_v1_payloads.csv
f284ed72c21575062b17788365b55134275b61d5843aefdbcfa8cc91d346ea4d  payloads/payloads.csv
859c9a54ff0866c52834a404a0edb575ea0218c89da841c20759ccc857c54b13  prompts/v1/condition_A_system.txt
652355a18191749bc3673278c626ecf8c663ceb22fff69c6ab1ee4772ccf4427  prompts/v1/condition_A_user.txt
859c9a54ff0866c52834a404a0edb575ea0218c89da841c20759ccc857c54b13  prompts/v1/condition_B_system.txt
7b807cfb8ead1014726038a73d2bce28bb16519ec38b9bddb0a952d2ddf54d5b  prompts/v1/condition_B_user.txt
f533948515a4b595ff5004bd09bb50cce78da96d090a7aa448978b6caac18d64  prompts/v1/condition_C_system.txt
fd13688ea8eabadf1f311c809270339139359762881cf9b6cc9e59e4d292f2dc  prompts/v1/condition_C_user.txt
859c9a54ff0866c52834a404a0edb575ea0218c89da841c20759ccc857c54b13  prompts/v2/condition_A_system.txt
652355a18191749bc3673278c626ecf8c663ceb22fff69c6ab1ee4772ccf4427  prompts/v2/condition_A_user.txt
859c9a54ff0866c52834a404a0edb575ea0218c89da841c20759ccc857c54b13  prompts/v2/condition_B_system.txt
7b807cfb8ead1014726038a73d2bce28bb16519ec38b9bddb0a952d2ddf54d5b  prompts/v2/condition_B_user.txt
f533948515a4b595ff5004bd09bb50cce78da96d090a7aa448978b6caac18d64  prompts/v2/condition_C_system.txt
fd13688ea8eabadf1f311c809270339139359762881cf9b6cc9e59e4d292f2dc  prompts/v2/condition_C_user.txt
859c9a54ff0866c52834a404a0edb575ea0218c89da841c20759ccc857c54b13  prompts/v2/condition_PLACEBO_system.txt
0b64c3cf13458521c053f84c8c496202a9f6602d7634b08d48a5d6eee71ee92d  prompts/v2/condition_PLACEBO_user.txt
859c9a54ff0866c52834a404a0edb575ea0218c89da841c20759ccc857c54b13  prompts/v2/condition_VP_system.txt
13b46f02cb4bdc2ff693c8bdabc3fd7e3f65678e5b50525e47214c768bf8a7a9  prompts/v2/condition_VP_user.txt
859c9a54ff0866c52834a404a0edb575ea0218c89da841c20759ccc857c54b13  prompts/v2/condition_VS_system.txt
d2c6571b14b7a92e3dcd4888af7e9bc17b2e2a8b546e144ecd6885097acadff5  prompts/v2/condition_VS_user.txt
859c9a54ff0866c52834a404a0edb575ea0218c89da841c20759ccc857c54b13  prompts/v2/condition_V_system.txt
df33e5e6a335688ce71d872f65713c7990864f9b671017900db8123291e4684d  prompts/v2/condition_V_user.txt
38b9d8d772fd64d073e00224bda5ffcf35e5e034a8211998b2836ab9b025bfb9  results/analysis/all/results.json
0a446f5340070253002f96629516b8fa9b55d6dbb8b52aada3cf0286b01b5732  results/analysis/extension/results.json
16bfeab257dac49894abf5b487b5c7f76077e4b17688fe7858991638bf27bfb3  results/analysis/ladder/results.json
d717e02a5987c774baa6e69741ce28fe1fb38029f6d01ff6761eaad68c297fa8  results/analysis/srbh/results.json
3604b5ffe8156ab7e514b52c344c8b5b0162e26d0d71eefac33442d031a0741e  results/analysis/v1/results.json
b9481131cc2f9d3936e425c279bcefbfcd1db45b93aad1dd1f8cafaa8dc253cf  results/runs/claude_haiku_4_5_benign_v1.csv
a2db07411774d3dd1c475a4220fa8259a5f1556ef62769e76aa505d69224dc65  results/runs/claude_haiku_4_5_v1.csv
16a1682ffef08e0894934723ff7d02946b9388d5987f3db3ee3a245bb7b85b7e  results/runs/claude_haiku_4_5_v2_bclean.csv
a40daacad82e1a628f14c4dab16384bade3adfc74088ff1af3f15c9279daac1b  results/runs/claude_haiku_4_5_v2_components.csv
37e891eec517630d163d34c6dd7fdd59ab058c7e061c3d352b344531249acfa4  results/runs/claude_haiku_4_5_v2_components_benign.csv
6d7f24917335ad1d19e7a4a06a6d5f6e60f89b37d791243e208ba40bce188c24  results/runs/claude_haiku_4_5_v2_dose.csv
4a70598f1076ea6e2b002ead9ff07a0ec9a5d6919a7a69f9b8003ccb03e6daa4  results/runs/claude_haiku_4_5_v2_dwrong.csv
2bdce4ab0c0c83a5e81e9f6abb827650fd02222363ec35e2a5dbff50e61d7a4f  results/runs/claude_haiku_5_5_ext.csv
9f31a3f4a4ba1c5b745a1eef9730133aa58c788a2bcae54207ea64d9e9b9c035  results/runs/claude_haiku_5_5_ext_benign.csv
7cd90bdf1ce931526165b841c4938198dc704ad31488a8d51d3ab49b55eaa176  results/runs/claude_haiku_5_5_ext_dwrong.csv
aecb7d6ae4a613975744ad683a500d55aa1f8832c9a3fee5de18460ec5375acd  results/runs/gemini_2_5_flash_ext.csv
682b7f6f1a07a7ec6e736af8bd0ec2efb6ec8572b7b59823d0ab24cd44b82155  results/runs/gemini_2_5_flash_ext_benign.csv
e48af012303829aafcc67de5c7e08f808ca303240ea61bee765d0d871d66a0c4  results/runs/gemini_2_5_flash_ext_dwrong.csv
992385b31abdefe938beb0d2e1fe5594d2aa52beb7dd63b04f9013d8f5d98719  results/runs/gemini_3_6_flash_ext.csv
06ed18ecc298d11ba8fea341e11385d6c4919d25b9ed2d737b2d09f9b06b7c77  results/runs/gemini_3_6_flash_ext_benign.csv
4dc7fdfe6a21c59c03ba0b45ace6e880d7341476351ca406e4bff655ab3d3a3a  results/runs/gemini_3_6_flash_ext_dwrong.csv
bd68fdb82a034e8ce76724905725fc8353d1c80c6a51d324c675d7ea611368bd  results/runs/gemma4_12b.csv
db5804628b6e8176362225b4ec9b00dee8096de8da9575ebf92813024370dfec  results/runs/gemma4_12b_benign.csv
be2118d088067ee149522587a2ac5d18cf26a0ec2afdf0bdff7b6e696bcd6668  results/runs/gemma4_12b_v2_ladder.csv
2bacb415036c605eee7f5bf3f88c66a5b94002931ee526f466cdb7f8cd822764  results/runs/gemma4_e2b.csv
d44c900ba52c71e988d47d0c4f2a0faa186dd6808ff6bbc46d59007993ec7bcd  results/runs/gemma4_e2b_benign.csv
82298e631482eefde2d3687b5ea19a70a7402d15b3b827ea809064adc54f3321  results/runs/gemma4_e2b_v2_ladder.csv
f8a63922f8be822bd20cee13cfd4949e297f68b565a2a12b0a44d5c6ece5b5cc  results/runs/gemma4_e4b.csv
36209fe5101c105b75d37d55fc2dc8c1bcb4d0d9a7e60215ebe4088dc57c5311  results/runs/gemma4_e4b_benign.csv
23caa910a53ab80a922d83a620cb2780b0868089fcb7140f343bd411cf409f33  results/runs/gemma4_e4b_srbh.csv
d8b856b55cfb47007df6076fa94a2a53b4787136b35684995e8f03f24c8cf2a3  results/runs/gemma4_e4b_srbh_benign.csv
e523d1065efb3b4108efc39cdb4840fb1dff5179f85bed2e1be962c1bace8d0d  results/runs/gemma4_e4b_srbh_clean_c.csv
5020c7649c18c43adb23327267f5296fa06f0c2fff65b6482badd6e40e49a74d  results/runs/gemma4_e4b_v2_bclean.csv
6cfb11700dcde1e604a1f9d87295aabb32688f12fe7f4b764175405bc718843b  results/runs/gemma4_e4b_v2_bprime_bclean.csv
3c3aafa9c0f256bc639b9e9be6a3135a78ffb65531fe2b312ab86b0ff2f3b0d8  results/runs/gemma4_e4b_v2_components.csv
0eae630a2c27ce5f495ecac68b677375ff97a29f508c108aaf8f046fdb46ea89  results/runs/gemma4_e4b_v2_components_benign.csv
5d731eee1d9641aae17133a82c8ba1b601bf80e7a814af63718424a92caae9f8  results/runs/gemma4_e4b_v2_dose.csv
3a5d4e0bfe8e24683c88c1678cc651b9c38b8b4448cb1514dbf9a69fa448de0b  results/runs/gemma4_e4b_v2_dwrong.csv
6aad62ff2a95d6647799b9b4635ecfcec080d1506b34f99578320546adcac695  results/runs/qwen3.5_9b.csv
70d84a2b807dda831afe28d9c841180773ace7534dc0f02db31e3d56c57122b1  results/runs/qwen3.5_9b_benign.csv
7b19be9cee8c14915f1fb07845b6d176bcf122b6573a6c9596a92b5c663fefb1  results/runs/qwen3.5_9b_v2_ladder.csv
43f5c0bf4f0896bd470129367db71c83d7a061c22405e13e5aaf84d1a0271f19  results/runs/smoke_gemini_2_5_flash.csv
29e610bce5cc8e56a9eaf917f31b20eca2af8c5159c4a202bdb1ee99610fe38c  results/runs/smoke_gemini_3_6_flash.csv
d3b5f0f67913f7de96265375d891ab8d96eae8462b1525df0cfeabafd198390c  results/runs/smoke_haiku_5_5.csv
104c3fce3138e30aa5f90c559406758a9f18c1f023b504ab788e3780110d2d3c  results/runs/smoke_qwen.csv
d0f9d2757165339cc0bae2928f241a865df5e7964339dd8e70c12b037373d79e  results/runs/smoke_qwen_rerun.csv
```

## Environment

### Machine (local runs and this validation)

```
ProductName:		macOS
ProductVersion:		26.6.2
BuildVersion:		25G83
CPU: Apple M4 Pro
RAM: 24 GB
```

### Ollama and local model digests

```
ollama version is 0.35.1
NAME             ID              SIZE      MODIFIED    
qwen3.5:9b       56671c2ab938    6.6 GB    12 days ago    
gemma4:12b       6114515d63c1    8.0 GB    13 days ago    
gemma4:e2b       b37049369adf    4.6 GB    13 days ago    
granite4.2:8b    f586c02fdecd    5.3 GB    2 weeks ago    
gemma4:e4b       dc35e8d9c606    6.6 GB    2 weeks ago    
qwen3.5:4b       2a654d98e6fb    3.4 GB    2 weeks ago    
```

### Runner environment (`.venv`)

```
Python 3.9.6
annotated-types==0.7.0
anthropic==0.125.0
anyio==4.12.1
blinker==1.9.0
certifi==2026.7.22
charset-normalizer==3.5.2
click==8.1.8
distro==1.9.0
docstring_parser==0.18.0
exceptiongroup==1.3.1
Flask==3.1.3
h11==0.16.0
httpcore==1.0.9
httpx==0.28.1
idna==3.20
importlib_metadata==8.7.1
itsdangerous==2.2.0
Jinja2==3.1.6
jiter==0.16.0
MarkupSafe==3.0.4
numpy==2.0.2
pandas==2.3.3
pydantic==2.13.5
pydantic_core==2.46.5
python-dateutil==2.9.0.post0
python-dotenv==1.2.1
pytz==2026.4
requests==2.32.5
six==1.17.0
sniffio==1.3.1
typing-inspection==0.4.2
typing_extensions==4.16.0
tzdata==2026.5
urllib3==2.6.3
Werkzeug==3.1.9
zipp==3.23.1
```

### Analysis environment (`/Users/tung/venvs/tdk-detector`)

```
Python 3.14.8
certifi==2026.10.19
charset-normalizer==3.5.2
cloudpickle==3.1.2
contourpy==1.4.0
cycler==0.12.1
fonttools==4.67.0
formulaic==1.2.2
idna==3.20
interface_meta==2.0.1
joblib==1.6.0
kiwisolver==1.5.1
matplotlib==3.11.2
narwhals==2.27.1
numpy==2.5.3
packaging==26.3
pandas==2.3.3
patsy==1.0.3
pillow==12.3.0
pyparsing==3.3.3
python-dateutil==2.9.0.post0
pytz==2026.5
requests==2.34.2
scikit-learn==1.9.1
scipy==1.18.1
shap==0.54.1
six==1.17.0
slicer==0.0.8
statsmodels==0.15.0
threadpoolctl==3.7.0
tqdm==4.70.1
typing_extensions==4.16.0
tzdata==2026.5
urllib3==2.8.0
wrapt==2.5.2rc1
```

## Earlier archives (superseded)

| Tag | Commit | Zenodo DOI | Why superseded |
|---|---|---|---|
| `data-freeze-v1` | 53b584f | 10.5281/zenodo.23547265 | before the review fixes and the licences |
| `data-freeze-v1.1` | 366682b | 10.5281/zenodo.23547741 | licences, but not the Condition-C Wilson-over-events fix or the stricter freeze check |

Both stay on Zenodo as older versions. This record describes `data-freeze-v1.2`; the paper cites its version DOI. The concept DOI 10.5281/zenodo.23547264 resolves to the latest version.

## Which machine ran which runs

| Runs | Machine |
|---|---|
| All local Ollama runs: gemma4:e2b, e4b, 12b, qwen3.5:9b (A/B/C, v2 arms, ladder, B'+BCLEAN, SR-BH) | T. H. T. Nguyen's MacBook Pro (machine above) |
| Claude Haiku 4.5, Haiku 5.5, Gemini 2.5 Flash, Gemini 3.6 Flash (cloud APIs) | B. Abdullaev's MacBook Air (Apple M4), macOS 26.7.1; Python 3.14.8, anthropic 0.125.0, google-genai 2.31.0 |

The 8 result files from 8-9 Oct (Claude Haiku 4.5 v1 and gemma4 e2b/e4b/12b A/B/C, each with its benign-control file) were written by the earlier runner and store the prompt version and hash only; their settings are documented in `README.md` and `docs/threat_model.md` (pre-registration Section 8). All later rows also store the runner commit, backend version, model digest or reported model version, and the parameters actually sent.

## Not in the repository

- `models/`: detector fold models; rebuilt by `scripts/train_detector.py` (and `models/srbh/` by `scripts/make_srbh_cases.py`).
- `.env`: API keys.
- `data/external/`: the SR-BH 2020 source file (doi:10.7910/DVN/OGOIXX); the converted slice is in `data/processed/srbh/`.
- `logs/` and local notes: run logs and personal notes, not needed to reproduce the results.
- Smoke and test outputs in `results/runs/` that are untracked (e.g. `dummy_test.csv`, `resume_test.csv`).
