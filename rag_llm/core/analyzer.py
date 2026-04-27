from openai import OpenAI

from config import LLM_API_KEY, LLM_BASE_URL, LLM_MODEL, LLM_MAX_TOKENS, LLM_TEMPERATURE, NETWORK_CONTEXT


SYSTEM_PROMPT = """你是一位高级网络安全分析师，专门负责分析DNS日志和网络流量数据，识别安全威胁并生成详细的事件分析报告。

你的职责：
1. 基于提供的证据数据，准确回答有关网络安全事件的问题
2. 识别受感染的内部主机、可疑域名、C2通信等威胁指标
3. 将发现映射到MITRE ATT&CK框架
4. 提供具有因果关系的攻击叙事重构

关键规则：
- 仅基于提供的证据进行回答，必须引用具体数据（时间戳、IP地址、主机名、域名等）
- 当提供的信息不足以得出结论时，必须明确告知，不得编造或推测
- 所有IP地址、域名、主机名等安全实体必须精确匹配
- 回答应当结构化、逻辑清晰，包含证据链"""


def _build_network_context():
    ctx = NETWORK_CONTEXT
    parts = []
    parts.append(f"局域网网段范围: {', '.join(ctx['lan_ranges'])}")
    parts.append(f"公司域名: {ctx['company_domain']}")
    parts.append(f"已知DNS服务器: {', '.join(ctx['dns_servers'])}")
    return "\n".join(parts)


def _build_prompt(question, context):
    net_ctx = _build_network_context()
    prompt = f"""## 网络拓扑上下文
{net_ctx}

## 检索到的证据数据
{context}

## 分析任务
基于以上证据数据，回答以下安全问题：

{question}

请提供详细的分析报告，包括：
1. 关键发现（受感染主机、可疑域名、C2通信等）
2. 证据链（引用具体数据点）
3. ATT&CK技术映射
4. 攻击路径重构
5. 防御建议"""
    return prompt


class Analyzer:
    def __init__(self, api_key=None, base_url=None, model=None,
                 temperature=None, max_tokens=None):
        self.api_key = api_key or LLM_API_KEY
        self.base_url = base_url or LLM_BASE_URL
        self.model = model or LLM_MODEL
        self.temperature = temperature if temperature is not None else LLM_TEMPERATURE
        self.max_tokens = max_tokens if max_tokens is not None else LLM_MAX_TOKENS
        self.client = None

    def _get_client(self):
        if self.client is None:
            self.client = OpenAI(
                api_key=self.api_key,
                base_url=self.base_url,
            )
        return self.client

    def analyze(self, question, context, stream=False):
        client = self._get_client()
        prompt = _build_prompt(question, context)
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        if stream:
            return self._stream_analyze(client, messages)
        response = client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
        )
        return response.choices[0].message.content

    def _stream_analyze(self, client, messages):
        stream = client.chat.completions.create(
            model=self.model,
            messages=messages,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            stream=True,
        )
        for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                yield chunk.choices[0].delta.content

    def quick_analyze(self, question, context):
        return self.analyze(question, context, stream=False)
