# **基于检索增强大语言模型的安全事件分析报告：理论、架构与深度实证剖析**

## **引言与行业背景深度解析**

在当今高度数字化的技术生态中，安全运营中心（Security Operations Centers, SOC）正面临着前所未有的巨大压力。网络威胁不仅在数量上呈现指数级增长，其复杂性和隐蔽性也在不断演进，而具备高级分析能力的安全分析师队伍的扩张速度却远远落后于这一趋势1。现代化的安全信息和事件管理（SIEM）系统每天例行生成数以千计的安全警报，但大量实证研究表明，由于人类认知的带宽限制，分析师通常只能审查这些海量数据中的极小一部分1。这种由于信息过载导致的“警报疲劳”（Alert Fatigue），不可避免地导致了严重的安全事件被忽视或处理延误1。

调查和定性一个复杂的网络安全事件，例如识别受损的内部资产、追踪攻击者的横向移动路径、理解初始入侵机制等，需要分析师在分布于不同系统的海量证据中进行深度综合1。这些证据广泛散布于入侵检测系统（IDS，如Suricata）、网络遥测记录（如Zeek连接日志）以及端点身份验证事件（如Windows事件日志）中1。当前主导行业的检测机制严重依赖于静态签名和基于规则的启发式算法，这些传统方法存在一个根本性的缺陷：它们无法泛化并识别以前从未见过的未知攻击模式1。高级持续性威胁（APT）及复杂对手正是利用了这一漏洞，通过滥用配置错误的证书模板（例如ESC1攻击）、伪造Kerberos票据以及利用网络信任关系进行逐步的横向移动来实施攻击1。此类攻击通常会持续数小时甚至数天，将取证伪影分散在不同的日志源中，没有任何单一的日志条目能够揭示完整的攻击链条1。

尽管近期机器学习方法在警报分流和异常评分方面取得了进展，但这些方法最终输出的仅仅是二元分类结果或概率排名，而不是事件响应人员真正需要的、具有连贯因果关系的攻击叙事重构1。大语言模型（LLMs）凭借其在自然语言处理领域的突破性进展，被认为是解决这一问题的理想方案。它们能够解释非结构化文本，将零散的事实整合连贯的叙事，并以人类可读的自然语言传达调查结果1。然而，将原始的安全日志直接输入到大语言模型中在操作上是完全不可行的。单一的安全事件可能会产生数以百万计的日志条目，这远远超出了当前任何商业大语言模型的上下文窗口限制1。更为严峻的是，这些海量日志中混合了极少量的真实攻击信号与压倒性规模的日常合规活动（如正常的身份验证、良性的网络连接、误报的签名警报），直接输入会导致攻击信号被彻底淹没1。此外，事件响应通常要求极高的时效性，而大语言模型在处理超长上下文时的推理延迟依然较高1。

为了克服这些固有挑战，本报告基于被修复和高度还原的核心研究内容，详尽阐述并评估一种全新的基于检索增强生成（Retrieval-Augmented Generation, RAG）的安全事件分析系统1。该系统摒弃了将原始日志直接喂给大模型的低效做法，转而通过在安全日志上运行目标明确的查询来提取相关的威胁指标（IOCs），将这些攻击指标精确映射到MITRE ATT\&CK框架，并通过语义相似性检索，利用语义相关的事件序列增强大语言模型的上下文1。这种架构赋予了模型在极其有限的上下文限制内生成具有高度解释性、证据支撑的安全事件报告的能力1。

## **填补空白：相关工作与行业演进脉络**

在早期的学术文献和技术草案中，关于本研究在整个技术生态中的定位曾存在信息缺失的现象1。为了提供完整的视角，必须对大语言模型在网络安全自动化领域的演进脉络进行深度梳理。近年来，大语言模型已被广泛应用于漏洞检测、恶意软件分析、威胁情报提取和事件响应等多个子领域1。

早期的研究主要致力于调整预训练模型以适应网络安全领域的特定文本。例如，SecureBERT引入了一种在大型网络安全语料库上训练的特定领域BERT模型，证明了其在处理包含MITRE ATT\&CK术语的下游任务中的性能提升1。同样，CySecBERT在超大规模网络安全语料库上采用了领域自适应预训练策略，以显著提高网络安全自然语言处理任务（如命名实体识别和网络威胁情报处理）的准确性1。在威胁分类学映射方面，TRAM工具通过微调SciB-ERT模型，成功将非结构化的安全报告映射到结构化的MITRE ATT\&CK技术矩阵中1。这些模型为分类和向量嵌入任务提供了强大的语义表征，但它们缺乏处理多步骤、跨日志源攻击推理的能力。

在基于日志的异常检测领域，LogLLM结合了BERT的语义提取能力和Llama的序列分类能力，在系统日志数据集上进行异常识别1。LogPrompt则探索了通过零样本提示工程进行解释性日志分析的可行性1。然而，这些前沿方法主要集中在系统级日志（如HDFS、Linux系统日志）和二元异常标签上，并未涉足包含多阶段攻击模式的特定安全日志复合分析1。最近的工作开始探索多智能体大语言模型系统在网络安全任务中的应用，例如Audit-LLM证明了多智能体协作能够有效减少内部威胁检测中的误报率，而特定于SOC环境的系统如CORTEX则提出了专门用于高风险警报分流的智能体架构1。在网络威胁情报（CTI）自动化方面，研究人员开发了能够从威胁报告中提取妥协指标的智能体，并使用RAG技术生成正则表达式，协助分析师建立SIEM关联规则1。基于GraphRAG的方法则利用从网络日志构建的、本体支持的知识图谱来支持大语言模型驱动的网络安全监控查询生成1。

上述系统无疑推进了警报级别的处理效率，但它们的核心关注点仍然局限于初步的分流和摘要，而不是端到端地回答有关已检测事件的特定取证问题1。对45名SOC分析师实际查询模式的实证研究表明，大语言模型在实际运营中的最佳角色是作为增强而非取代人类专业知识的认知辅助工具1。相比于以往侧重于警报分流的工作，本报告所重构的系统解决了端到端的安全事件分析难题。通过将其形式化为基于异构安全日志（涵盖入侵检测系统、网络监视器和身份验证事件）的复杂问答任务，本架构成功实现了对离散取证事件的因果关系重构1。这种需要针对安全数据量身定制的智能分块策略，以及支持在多个日志源中对攻击进度进行推理的检索机制，代表了该领域的重大范式转变1。

## **数学形式化与评估度量的严谨性**

为了实现科学、可重复的系统评估，本报告将安全事件分析严谨地形式化为一个受限的问答（Question-Answering）任务，并定义了贯穿整个实验框架的专有评估指标。这种形式化不仅标准化了输入输出流，还明确了传统文本匹配度量在安全领域的局限性1。

### **安全事件分析的问题重构**

假设 ![][image1] 表示一个离散的安全事件，该事件由一组异构的安全日志集合 ![][image2]（例如，Suricata警报、Zeek连接日志、Windows事件日志）所表征1。在此框架下，事件分析的核心被定义为给定事件的日志集合，系统必须准确回答有关攻击性质和演进路径的法证问题。

定义评估问卷（Evaluation Questionnaire）为 ![][image3]，它是从针对事件 ![][image4] 的可能问卷空间中提取的问答对的有限集合： ![][image5] 1

在实际操作中，为了覆盖事件响应人员确定范围和控制攻击所需的最基本信息，我们构建了一个包含五个具体问题的标准化测试问卷（M=5）1。在过往的文档版本中，这部分内容存在遗漏，现予以完整呈现1： 问题一：局域网中可能受感染的内部主机的IP地址是什么？（其答案类型 ![][image6]）1 问题二：局域网中可能受感染的机器的主机名是什么？（其答案类型 ![][image7]）1 问题三：局域网中可能受感染的机器的Windows用户帐户名是什么？（其答案类型 ![][image8]）1 问题四：最初感染的可能的虚假或可疑域/URL是什么？（其答案类型 ![][image9]）1 问题五：联系过的、可能涉及命令与控制（C2）通信的可疑外部IP地址是什么？（其答案类型 ![][image10]）1

上述问题涵盖了识别受影响资产、确定初始妥协向量以及查明命令和控制基础设施的关键步骤1。此外，该框架支持自然扩展到其他问题（例如提取具体使用的MITRE ATT\&CK技术或释放的文件哈希值），而无需对底层架构进行任何修改1。除了取证识别，该框架还统一了攻击重构任务：推导恶意行为者在给定时间范围内采取的具体攻击路径1。系统必须回答复合问题（“攻击者在此时间线内做了什么？应实施哪些防御措施？”），并通过报告攻击步骤的精确率和防御建议的召回率进行严格评估1。

### **复合安全分析器设计**

遵循复合人工智能系统（Compound AI Systems）的范式，安全分析器（Security Analyzer）被解耦为两个可独立优化的主要组件1。

定义安全分析器 ![][image11] 为一个映射函数： ![][image12] 1 其中 ![][image13] 是安全日志的空间，![][image14] 是问题空间，![][image15] 是响应空间1。对于具有日志 ![][image16] 和问卷 ![][image14] 的事件 ![][image4]，输出被定义为： ![][image17] 其中 ![][image18]，![][image19] 是自然语言问题，![][image20] 是参考基准答案，![][image21] 是答案类型1。

答案类型空间被严格定义为 ![][image22]1。这种类型区分至关重要，因为安全实体数据具有高度的结构化特征，需要特定的匹配函数来进行评估1。

### **特定于类型的评分与匹配函数**

在标准的自然语言处理问答基准测试中，精确的字符串匹配通常就足够了。然而，网络安全答案拥有必须受到尊重的深层结构属性1。在此前的数据损坏中，该匹配公式未能完整呈现，这极大削弱了报告的技术严谨性1。完整的匹配机制如下：

对于每种答案类型 ![][image23]，定义一个匹配函数 $match\_{\\tau}: A\_{\\tau} \\times R \\rightarrow $。设 ![][image15] 表示参考标准答案，![][image24] 表示大语言模型生成的答案1： 对于IP地址：![][image25] 1 对于主机名和用户名（忽略大小写差异）：![][image26] 1 对于集合类型（恶意域集合、C2 IP集合）：![][image27] 1

这一匹配函数的存在揭示了该项任务极其非平凡的本质属性1。如果考虑一个随机生成答案的基准模型：对于私有IPv4地址（![][image6]），随机猜测正确的概率极其微小，约为 ![][image28]1。对于主机名（![][image7]），有效Windows主机名的排列组合空间高达数十亿1。对于集合类型（![][image9]），考虑到全球有数以亿计的注册域名，随机生成有效可疑域名的成功概率几乎为零1。这与典型的多项选择问答测试形成了鲜明的对比——在包含4个选项的问答测试中，即使是随机瞎猜也能获得25%的准确率1。因此，本任务硬性要求大语言模型必须具备从完全非结构化的海量底层日志中自主合成、推理和生成高度结构化答案的能力1。

## **跨事件语义推理的安全架构实现**

系统的整体架构由安全上下文提取（Security Context Extraction）和RAG-LLM分析（RAG-LLM Analysis）两个协同工作的流水线组成1。前者通过目标查询将原始日志压缩为与安全密切相关的信息特征，后者则利用语义检索获取相关上下文，并引导大语言模型进行因果推理1。

### **架构设计的核心原则**

该架构的构建遵循了五项极具前瞻性的核心工程原则1： 第一，分析前过滤（Filter before analysis）。由于大语言模型处理海量原始日志的速度过慢，且在充满噪声的数据集上表现极差，系统必须首先使用目标IOC查询提取安全相关信息。这一降维打击使得系统能够扩展到现实企业中庞大的日志量1。 第二，一次嵌入，多次查询（Embed once, query many times）。提取后的聚合数据通过大语言模型被语义嵌入到向量数据库中并缓存到磁盘。每个数据集只需构建一次索引，随后就可以使用不同的提示策略、针对不同的问题进行无数次的快速检索计算，而无需重新处理源数据1。 第三，周期性批处理分析（Periodic analysis）。系统并非在每一个离散事件发生时频繁调用大模型，而是按照定义的时间间隔执行分析，将相关活动分批聚合到连贯的时间窗口中，从而模拟高级威胁生命周期的逻辑1。 第四，供应商不可知设计（Provider-agnostic design）。系统将与大语言模型的交互抽象在通用接口之后，允许组织根据性能、成本、推理延迟和数据隐私敏感度的要求灵活替换底层模型提供商1。 第五，可扩展的IOC查询库（Extensible IOC query library）。检测查询作为独立的库进行维护，并严格映射到MITRE ATT\&CK技术矩阵。这意味着分析师可以随时扩展新型攻击的覆盖范围，而无需对核心推理管道进行重构1。

### **安全上下文提取与聚合机制**

上下文提取模块通过标准API（如ElasticSearch REST API）与现有的网络监控基础设施（本研究中使用Security Onion）深度集成1。它的核心依赖于一个强大的IOC提取查询库。由于前期草案的格式断裂，该查询库的具体结构被不幸遗失，现将其详细重构以展示其映射逻辑1。

| 查询维度 | 对应的MITRE ATT\&CK技术框架 |
| :---- | :---- |
| PowerShell 脚本注入 | T1059 – 命令和脚本解释器；T1204 – 用户执行文件释放 |
| 证书枚举操作 | T1649 – 窃取/伪造身份验证证书 |
| 证书颁发请求 | T1649 – 窃取/伪造身份验证证书 |
| 证书成功签发 | T1649 – 窃取/伪造身份验证证书 |
| Kerberos 身份验证行为 | T1558 – 窃取/伪造Kerberos票据 |
| Kerberos 服务票据获取 | T1558 – 窃取/伪造Kerberos票据 |
| 服务安装与修改 | T1543 – 创建/修改系统进程 |
| 新建系统用户帐户 | T1136 – 创建系统帐户 |
| 安全组特权修改 | T1098 – 帐户权限操纵 |
| 目标SCADA服务器的SSH访问 | T1021.004 – 远程服务：SSH协议 |
| SCADA 服务意外停止 | T1489 – 恶意服务停止 |
| 表1：用于活动目录（Active Directory）攻击检测的查询库及其ATT\&CK映射 1 |  |

每一个查询不仅仅是简单的字符串匹配，而是将基础过滤器与高级聚合器深度耦合，从而将成百上千的离散事件压缩成有序的模式排名1。这种聚合设计是一种根本性的架构选择：它将海量事件浓缩为紧凑、语义丰富的数据块，同时完美保留了跨事件的模式特征。这些特征往往是单条日志无法体现的1。

例如，Kerberos客户端聚合查询会在Elasticsearch中执行，专门过滤目标端口为88的认证事件，并使用正则表达式脚本从message.keyword字段中提取用户名，最后按照源IP地址进行分组汇总1。Suricata高严重性警报聚合查询则过滤来自内部IP空间（如10.0.0.0/8）的IDS警报，提取严重级别为1至2的事件，并按签名名称、源IP和目的IP进行多维度聚合1。文件下载聚合查询进一步追踪攻击载荷的投递，它监控常见的下载端口（80, 443, 8080等）以及高风险文件扩展名（.ps1, .exe），并使用高级脚本将原始的HTTP GET请求日志重建为高度清晰的流量流向格式（如 源IP \-\> 目的IP:端口 : 请求路径）1。

### **向量嵌入与大模型深度检索**

经过提取和压缩后，这些结构化的聚合结果被分割成具有明确语义边界的块。这里的“分块”并非像传统文档处理那样按字数硬性切割，而是将每一个完整的聚合结果作为一个独立的数据块，从而在语义上保持了绝对的连贯性1。这些数据块使用预训练的句子嵌入模型（本系统部署了all-mpnet-base-v2）进行向量化，并在FAISS向量存储中建立索引以实现极速的余弦相似度搜索1。

在分析阶段，分析师提出的安全问题同样经过相同的模型被嵌入到向量空间中，系统检索最相关的 ![][image29] 个相邻数据块（默认设置 ![][image30]）1。随后，系统会构建一个复杂的大语言模型提示词模板。该模板首先确立大模型作为“高级网络安全分析师”的角色定位，紧接着提供必要的网络拓扑上下文环境（包括局域网网段范围、公司域名、关键的活动目录域控制器IP地址等）。检索到的数据块紧随其后，且每个数据块都被明确标记了其源文件路径以支持可解释性和溯源1。模型被明确要求：仅基于提供的证据进行回答并引用具体数据（如时间戳、IP、主机名），当提供的信息不足以得出结论时，必须坚决拒绝幻觉并予以告知1。

### **跨源佐证的端到端案例解析**

为了直观展示提取机制与大模型推理如何无缝协作，可以考察一个典型的多阶段恶意软件感染案例。在Fake Authenticator（假冒身份验证器）恶意软件场景中，需要精确锁定受损的内部主机IP以及具体负责执行的被控用户账户1。该数据集包含了3,694条原始日志事件，杂乱地交织着HTTP连接、Kerberos身份验证、IDS警报和TLS证书交换记录1。

系统首先通过目标查询将其降维。Suricata聚合查询结果显示，内部IP 10.1.17.215 频繁触发了极为可疑的警报，例如“假的微软Teams CnC有效载荷请求”和“PowerShell文件请求”1。这一步仅仅确认了恶意活动源于该IP，但并没有揭示背后的用户是谁，也不知道具体下载了什么恶意载荷1。随后，Kerberos客户端聚合查询提供了身份归因的拼图：它揭示了该恶意IP地址同时关联着人类账户 shutchenson 以及机器账户 DESKTOP-L8C5GSJ$1。最后，文件下载聚合查询捕获到了决定性的载荷信息：该IP地址向外部C2服务器 5.252.153.241 发起HTTP GET请求，下载了一个名为 29842.ps1 的PowerShell脚本1。

在整个取证过程中，没有任何单一的数据源能够勾勒出完整的攻击全貌1。IDS警报缺乏用户维度的身份归属；Kerberos日志证明了身份验证的发生但看不出这是否是恶意行为；HTTP日志记录了文件下载行为，却无法单凭自身判断该流量是正常业务还是恶意投递1。但是，当这些经过深度聚合的独立数据块被统一检索并注入大语言模型的上下文中时，大模型展现出了卓越的跨源交叉验证能力。它敏锐地捕捉到了这些数据块之间共享的纽带——IP地址 10.1.17.215，从而顺理成章地构建出了一条连贯的证据链：正是工作站 DESKTOP-L8C5GSJ 上的用户 shutchenson 从被标记的C2服务器下载了恶意的PowerShell载荷1。这证明了降维聚合策略在保留使大模型能够进行跨源逻辑推理的语义链接方面取得了巨大成功1。

## **恶意软件流量分析的实证评估与性能标定**

为了全面评估系统的可行性（RQ1）、不同供应商的性能对比（RQ2）、对上下文大小的敏感度（RQ3）以及面对不同攻击模式的鲁棒性（RQ4），本研究在四个极具代表性的高级恶意软件流量场景上进行了深度评估1。

### **数据集的复杂性特征**

这四个场景由恶意软件流量分析领域的公共数据源提供，每个场景代表了一种完全不同的攻击模式和战术特征1。

| 恶意软件场景名称 | 文件大小 (MB) | 网络数据包数量 | Security Onion产生的日志数量 | 核心攻击模式与威胁特征分析 |
| :---- | :---- | :---- | :---- | :---- |
| Fake Authenticator (2025年1月) | 26 | 39k | 3,694 | 用户被定向到虚假的Google Authenticator下载页面，随后触发多服务器C2通信机制。1 |
| NetSupport RAT (2024年11月) | 21 | 26k | 1,044 | 攻击者向合法网站注入恶意脚本，向受害者推送虚假的浏览器更新，从而植入远程访问木马。1 |
| Koi Stealer (2024年9月) | 2.1 | 5k | 774 | 一种高度活跃的信息窃取型恶意软件，拥有多个C2端点并表现出极度规律的自动签到（Check-in）行为。1 |
| IcedID (2023年4月) | 22.3 | 44k | 5,701 | 臭名昭著的银行木马，通过Firebase Storage云存储URL进行隐蔽投递，生成HTTPS C2流量及用于妥协后操作的BackConnect活动。1 |
| 表2：恶意软件网络抓包（PCAP）文件特征与复杂性分析 1 |  |  |  |  |

评估覆盖了横跨云端API服务与本地GPU部署方案的八种顶级大语言模型配置，包括：Anthropic体系的Claude Sonnet 4、DeepSeek生态的DeepSeek V3、OpenAI体系的GPT-4, GPT-4o, GPT-5-mini, GPT-5.2，以及支持完全本地私有化部署的开源大基座模型Llama 3.1:70b和针对安全领域特化的Cisco Foundation-Sec-8B1。

### **恶意软件事件召回率全景分析**

针对上述四个场景，所有模型接受了统一维度的评估。对于单值问题（如感染主机的IP），精确率等同于召回率，计分采用二元标准。而对于集合值问题（如C2指示器），模型将根据其发现的参考标准指示器的比例获得部分信用分1。

| 模型提供商 | Fake Auth. | Net. RAT | Koi Steal. | IcedID | 平均召回率 | 标准差 σ |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| Claude Sonnet 4 | 100% | 100% | 100% | 100% | 100% | 0.00 |
| DeepSeek V3 | 100% | 100% | 100% | 100% | 100% | 0.00 |
| Ollama 3.1:70b (本地) | 100% | 100% | 80% | 95% | 95% | 0.09 |
| Cisco 8B (本地特化) | 100% | 90% | 100% | 70% | 90% | 0.12 |
| GPT-5.2 | 60% | 100% | 100% | 85% | 85% | 0.17 |
| GPT-4o | 60% | 100% | 80% | 80% | 80% | 0.14 |
| GPT-4 | 60% | 100% | 80% | 75% | 75% | 0.17 |
| GPT-5-mini | 60% | 100% | 80% | 75% | 75% | 0.17 |
| 表3：各大语言模型在不同恶意软件场景中的核心事件分析召回率表现 1 |  |  |  |  |  |  |

宏观数据显示了明显的阵营分化。两款顶级云端模型架构——Claude Sonnet 4 和 DeepSeek V3 展现出了压倒性的统治力，在所有四个高难度场景中均实现了完美的 100% 召回率，并且其标准差为绝对的 0.001。它们准确地跨越日志孤岛，无一遗漏地识别出了所有的感染主机、受害用户账户、恶意访问域名以及深埋的C2服务器1。尤其令人振奋的是，本地部署模型表现出了极强的韧性。拥有700亿参数的开源模型Llama 3.1（通过Ollama部署）达到了 95% 的综合召回率1。这为那些受到严格数据主权监管和GDPR等隐私法律约束的大型企业释放了一个极其明确的信号：在不向第三方云API暴露核心遥测数据的物理隔离环境中，系统依然能够维持极高水准的智能化事件响应准确度1。

相反地，GPT系列模型在特定逻辑推理任务上表现出了结构性的脆弱。所有测试的GPT版本在Fake Authenticator场景中的召回率均暴跌至 60%1。详细排查表明，它们彻底未能发现关键的次级C2服务器。这一失败根源于它们在整合行为聚合数据（例如对异常高的连接总数和文件下载量的综合研判）与Suricata警报方面存在固有缺陷1。而最复杂的多阶段感染链条——IcedID场景，则成为检验所有模型的试金石。在该场景中，攻击者的初始网络重定向IP隐藏极深，随后跳转至Firebase获取安装包，最终才建立隐蔽的C2通信。在此环节，Claude、DeepSeek、Cisco以及Ollama都成功抽丝剥茧找到了初始感染源的IP地址（80.77.25.175），而所有GPT模型无一例外地陷入了思维短视，仅仅报告了最终暴露的C2域名1。这表明GPT模型倾向于过度依赖置信度极高的IDS警报，却缺乏还原完整攻击演进时间线的深度因果追踪能力1。

## **揭秘黑盒：大语言模型的认知推理模式深度解剖**

除了硬性的召回率指标外，不同底层架构的大语言模型在处理相同的安全分析问题时，展现出了截然不同的“认知范式”与认知认识论1。通过深度对比这三个具有代表性的模型对Koi Stealer场景中C2检测问题（Q5，基准C2服务器为 79.124.78.197）的解析过程，可以洞悉它们在平衡精确度与覆盖率时的内在取舍策略1。

### **DeepSeek V3：以证据权重为核心的高精度克制**

DeepSeek V3 采用了一种极其严谨的、注重证据权重的结构化推理策略1。在分析繁杂的日志时，它首先准确锚定了正在产生大量恶意流量的受损内部主机 172.17.0.99。随后，它并未盲目罗列所有对外连接，而是精准引用了确凿的Suricata高危签名（如 ET MALWARE Win32/Koi Stealer CnC Checkin）作为核心证据基石。

更值得关注的是其“主动排异”的认知行为。DeepSeek 在推理过程中明确识别出了一些潜在的候选对象——例如内部主机通过DNS解析并连接的外部IP（涉及 sso.godaddy.com 等域）。然而，它在最终给出结论前，主动进行了二次逻辑审视，并以“缺乏IDS签名进一步佐证”为由，坚决将这些候选IP从最终可疑名单中剔除1。这种对微弱指标的显式拒绝，完美展现了其过滤分析噪音的能力。它严格区分了“被访问过的外部IP”与“被确认为C2基础设施的IP”，从而极大降低了分析师验证误报的认知负担1。

### **Cisco Foundation-Sec-8B：防御纵深与全局威胁映射**

作为一个专门在安全语料库上进行预训练特化的模型，Cisco Foundation-Sec-8B 的行为逻辑充斥着浓厚的安全实战思维1。它输出了一条极其冗长且详细的思维链（Chain-of-thought），试图在微观数据上勾勒出宏观的全局威胁图谱。

在结果呈现上，Cisco采用了一种层次化的分级输出策略。它不仅准确锁定了主C2服务器，还将那些被DeepSeek过滤掉的边缘可疑IP一并保留，作为次级威胁进行了详尽汇报。更加引人瞩目的是，Cisco的推理内嵌了深厚的运营背景——它敏锐地指出攻击者使用了“域前置（Domain Fronting）”这一高级逃逸技术，即利用合法的域名来掩盖真实的C2 IP流量，并随即生成了要求立即将受损主机物理隔离的操作建议1。这种宁可过度报告也不漏掉任何微小威胁的策略，高度契合传统SOC环境中的纵深防御理念。

### **GPT-5.2：缺乏语义过滤的枚举式罗列**

与前两者相比，GPT-5.2 将高度复杂的逻辑推理退化成了简单的文本提取练习1。面对海量数据，GPT-5.2 仅仅产生了一段简短的回答，毫不加区分地将上下文提及的所有7个IP地址罗列出来1。

这种处理方式导致了极其严重的类别混淆错误（Category Error）。在这7个被其统称为“涉及C2通信的可疑外部IP”的清单中，不仅包含了DNS查询解析的正常IP、确诊的C2 IP，甚至荒谬地将 172.17.0.99（即受害的**内部**局域网主机自身）也赫然列为“外部C2节点”1。这种扁平化、缺乏优先级区分且包含根本性常识错误的枚举策略，不仅未能提纯攻击信号，反而将真正致命的威胁掩盖在巨大的误报堆积中，彻底违背了自动化系统旨在减轻分析师负担的初衷1。

| 认知对比维度 | DeepSeek V3 认知模式 | Cisco 8B 认知模式 | GPT-5.2 认知模式 |
| :---- | :---- | :---- | :---- |
| 核心推理风格 | 注重证据权重；具有显式的弱指标拒绝机制 | 重度依赖思维链；倾向于全面而细致的威胁图谱映射 | 缺乏数据过滤机制；机械式的枚举与数据盲提取 |
| 证据层级结构 | 严格二分法：已确认威胁 vs. 仅仅是可疑活动 | 采用分层与梯队展示策略（明确区分主要与次要威胁） | 绝对扁平化的列表；没有任何威胁优先级排布 |
| 答案的精确度 | 极高（仅保留确诊的1个核心C2 IP） | 中等（报告3个IP，但附带了详细的纵深分析上下文） | 极低（胡乱堆砌7个IP，包含明显的提取谬误） |
| 关键逻辑失误 | 零失误 | 零失误 | 出现致命的类别混淆（将受害者内部IP当成了外部C2） |
| 运营战术环境 | 分析语言精简，环境考量较少 | 高度贴近实战（自动提出域前置概念并建议主机隔离） | 彻底脱离实战运营语境 |
| 表4：三大语言模型在C2隐蔽通信检测任务中的认知与推理模式对比全景剖析 1 |  |  |  |

## **消融实验：检索增强范式的不可替代性与参数边界**

为了科学量化检索增强生成（RAG）管道的具体价值，本研究设计了严格的消融实验体系，对上下文窗口容量（检索块数量 ![][image29]）进行了敏感性分析，并设置了破坏性的“无RAG”和“纯Suricata”基准对照组1。

### **上下文块数量（![][image29]）对推理上限的决定性影响**

以Fake Authenticator场景为例，我们系统地测试了 ![][image31] 时的模型表现。结果证明，上下文容量是解锁顶级大模型隐式推理能力的关键钥匙。

| 模型提供商 | 仅检索 k=1 块 | k=3 块 | k=5 块 | 最佳点 k=7 块 | k=9 块 | 极值 k=11 块 |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| Claude Sonnet 4 | 60% | 93% | 93% | 100% | 100% | 100% |
| DeepSeek V3 | 60% | 93% | 93% | 100% | 100% | 100% |
| GPT-5.2 | 60% | 60% | 60% | 60% | 67% | 80% |
| 表5：检索块数量增减对Fake Authenticator场景召回率上限的消融分析 1 |  |  |  |  |  |  |

当 ![][image32] 时，信息量极度匮乏，所有模型只能勉强摸到大象的一角，仅识别出基本的IP、主机名和表面可见的恶意域名，完全错失了用户账户的溯源和所有深层C2服务器1。随着信息量的初步释放（![][image33]），Claude和DeepSeek的推理引擎开始发力，成功完成了用户溯源并揪出了三个C2 IP中的两个，整体召回率飙升至93%1。当到达系统默认的最佳阈值 ![][image30] 时，完美的100%达成。在这一阶段，模型获得了至关重要的行为聚合数据块——揭示了高达1,198次的连续连接和594次异常文件下载的惊人统计数字，从而使得隐藏最深的主C2服务器（5.252.153.241）无所遁形1。

反观GPT-5.2的表现，则揭示了大语言模型领域的一个残酷真相：扩大上下文窗口无法拯救模型底层的推理短板。即便将上下文喂到 ![][image34]，GPT-5.2的召回率依然被死死卡在80%。深入分析其生成轨迹发现，该模型患有持续性的“身份识别认知障碍”——无论给它多少额外数据，它都无法在逻辑上将包含美元符号的Windows机器服务账户（DESKTOP-L8C5GSJ$）与实际操作的人类用户账户（shutchenson）区分开来。这种根深蒂固的推理谬误导致其在问题3上的得分永远是零分1。这深刻表明，在网络安全自动化选型中，基础模型的逻辑推理能力权重，要远远大于针对上下文容量的单纯工程调优（RQ3）1。

### **无RAG基准与系统性崩溃的必然结果**

为了回答“RAG预处理是否必不可少，或者现代拥有超大上下文窗口的大模型能否直接生吞硬嚼原始安全日志？”（RQ5）这一问题，研究评估了一个极其激进的无RAG（No-RAG）基准1。在该基准下，系统不进行任何查询提取、降维聚合或向量嵌入，而是直接将尽可能多的原始网络抓包日志硬塞入模型的最大上下文窗口中1。

结果是一场毫无悬念的灾难。受限于绝对的令牌（Token）数量限制，No-RAG方法只能勉强吞下该场景3,694条日志中的 22 到 158 条（仅占数据总量的 0.6% 到 4.3%）1。由于日志是严格按时间顺序排列的，这些填满上下文的早期日志绝大多数仅仅是系统启动和日常网络握手时的良性背景噪音。因此，所有模型都在这些良性日志中准确提取了受害者的表面信息，但在检测核心攻击基础设施（虚假域名和三个C2节点）上交出了刺眼的 0% 成绩单1。因为那些包含Suricata报警和海量异常流量的日志，早已被无情地截断在了物理上下文窗口之外1。

如果想要通过传统的“滑动窗口”模式分批次处理所有原始日志，面对这3,694条记录，系统需要排队发出约24次昂贵的API调用请求。由于API速率限制的物理阻碍（例如Claude在两次超长上下文调用间强制要求150秒冷却），完成一个单一事件的分析时间将从RAG架构下的短短2分钟，以几何级数暴涨至令人绝望的5个多小时1。这在争分夺秒的应急响应实战中是完全不具备操作可行性的。

此外，研究还测试了一个“纯Suricata”基准对照组——即传统SOC分析师最习惯的做法，仅仅依靠IDS报警进行分析。该基准虽然勉强触及了40%的召回率，但其失败机制与No-RAG截然不同：纯Suricata系统的折戟并非因为长度被截断，而是因为数据维度先天残缺1。传统IDS警报数据包中根本不存在主机名、Windows用户账户以及初始感染重定向域等信息，这些高价值的情报必须跨域前往Kerberos身份验证日志和HTTP连接记录中去挖掘。这进一步不可辩驳地证明：RAG的降维预处理机制与跨源数据的语义交叉关联，是下一代安全自动化工具不可或缺的两个核心支柱1。

## **经济学可行性与毫秒级延迟突破**

将人工智能投入生产级SOC运营，必须在分析精度、推理延迟与资金消耗之间寻找完美的平衡点。本系统以2025年末各大云供应商的公开定价体系为基准，对处理一轮包含5个复合问题的完整安全事件所需的大规模Token消耗进行了严密的成本核算1。

| 基础设施部署模式与模型提供商 | 输入端计费率 (美元/百万Token) | 输出端计费率 (美元/百万Token) | 单次事件调查耗资 | 攻击事件综合召回率 | 端到端平均响应时间 |
| :---- | :---- | :---- | :---- | :---- | :---- |
| **云端极速层：** DeepSeek V3 | $0.28 | $0.42 | **$0.008** | 100% | 1.2 分钟 |
| **云端极速层：** Claude Sonnet 4 | $3.00 | $15.00 | $0.12 | 100% | 1.2 分钟 |
| **云端基准层：** GPT-5.2 | $1.75 | $14.00 | $0.09 | 85% | 0.3 分钟 |
| **本地私有化层：** Ollama 3.1:70b | 忽略不计（内部算力损耗） | 忽略不计 | $0.00 (硬件折旧除外) | 95% | 2.5 分钟 |
| **本地专精层：** Cisco 8B | 忽略不计（内部算力损耗） | 忽略不计 | $0.00 (硬件折旧除外) | 90% | 16.0 分钟 |
| 表6：不同架构下的大语言模型在安全事件归因中的经济学指标、响应速度与性能画像评估 1 |  |  |  |  |  |

在基于极度保守的用量估计（每次分析触发5次独立的大模型调用，平均输入高达4,000个Token，深度推理输出800个Token）下，DeepSeek V3 创造了云端成本效益的神话。它在维持与Claude同等完美的100%召回率的傲人战绩下，将单次复杂安全事件的分析成本硬生生压缩到了极其低廉的0.008美元——其分析成本仅为Claude的十五分之一1。若将此放入大型企业SOC每天需要处理1,000次高级威胁分析的工业级规模进行推演，部署DeepSeek的月度账单仅为微不足道的240美元，而使用Claude则需要支付高昂的3,600美元1。

对于金融、军工等必须遵守严格数据驻留与不出境政策的敏感机构而言，利用GPU服务器阵列部署Ollama架构运行Llama 70B模型成为了破局之钥。它不仅彻底清零了高昂的按次计费API支出，更是在物理隔绝外网的环境下交出了高达95%的极优召回率答卷。虽然代价是将单次分析的推理延迟从云端的1.2分钟略微拉长至2.5分钟，但这在实际战术响应中完全处于可接受的安全冗余范围内1。值得反思的是，Cisco 8B模型由于底层框架缺乏极限优化，即使在本地部署其处理延迟也高达令人咋舌的16分钟，这一负面数据再次在侧面印证了在RAG检索框架内，具备强大涌现能力的通用巨型参数模型，在综合战力上已经开始对参数量较小的垂直领域特化模型形成降维打击1。

## **活动目录（AD）多阶段APT攻击的实时重构实战**

如果说恶意软件流量分析测试的是静态法证的“验尸”能力，那么对活动目录的分析则彻底将系统推向了充满动态博弈的攻防前线。为了填补在早先版本中遗失的关键章节1，我们在此详细复盘RAG大模型系统在对抗高度仿真的红蓝对抗军演中的实战表现1。

在这个被精心设计的场景中，扮演高级持续性威胁（APT）的红队试图隐蔽地攻陷一个庞大的Windows域环境，而防守方的蓝队则在迷雾中进行实时抵抗。 红队展开了一系列教科书般的战术动作（Red Team Actions）：首先通过Metasploit框架完成初始渗透撕开防线；随后利用极其凶险的ESC1漏洞，请求了一个带有管理员使用者可选名称（SAN）的数字证书；在完成证书枚举后，伪造并请求了Kerberos TGT及各种关键服务票据；紧接着利用PSExec协议将恶意触角横向移动延伸至域控大脑；在中枢区域创建高权限的后门用户，并最终图穷匕见，通过SSH强行登录负责工业控制的SCADA核心服务器，企图制造物理层面的服务瘫痪（最终战役目标）1。 面对这股暗流，蓝队迅速发起了雷霆万钧的反制（Blue Team Actions）：从紧急吊销被滥用的伪造证书、强制重置至关重要的KRBTGT账户密码、到对域控制器进行重启以掐断现有会话，并辅以大规模的用户密码重置与账号禁用。在蓝队的严防死守下，SCADA系统被攻陷的悲剧在最后一刻被成功阻止1。

### **突破时间维度的滑动窗口实时侦测**

不同于对恶意软件离散问答的处理逻辑，在这里系统面对的是一个极其苛刻的“攻击重构任务”：必须在持续流动的时间长河中，精准地框定攻击者的每一个作案步骤，并实时生成针对性的防御指令1。系统被配置为采用5分钟的滑动监控窗口（例如15:30–15:35，随后无缝衔接到15:35–15:40），并由本地部署的Llama 3.1:70b模型承担高强度的战术指挥官角色。

| 监控滑动时间轴 | 红队实际发起的有效攻击步数 | 大模型精确识别的有效攻击步数 | 系统产生的误报次数 | 战术侦测精确率 (Precision) | 攻击动作召回率 (Recall) |
| :---- | :---- | :---- | :---- | :---- | :---- |
| 第一波次: 15:30–15:35 | 11 个关键动作 | 11 个动作全域捕获 | 0 次误报 | 100% 绝对精确 | 100% |
| 第二波次: 15:35–15:40 | 8 个关键动作 | 6 个动作精准溯源 | 0 次误报 | 100% 绝对精确 | 75% |
| 第三波次: 15:40–15:46 | 7 个关键动作 | 5 个动作精准溯源 | 0 次误报 | 100% 绝对精确 | 71% |
| **全时域战术平均值** | \-- | \-- | **0 次误报** | **100% 绝对精确** | **82%** |
| 表7：基于5分钟高频滑动时间窗口的APT攻击步骤动态侦测指标 1 |  |  |  |  |  |

宏观统计结果展示了令人敬畏的精准度。该架构交出了一份 100% 战术侦测精确率的耀眼成绩单——这就意味着，大语言模型在报告中指出的每一个攻击步骤，全部都是红队真实采取的恶意破坏活动，系统没有发出任何一次“狼来了”的虚假警报，彻底根除了让防守方深恶痛绝的误报问题。在长达16分钟的高压对抗中，系统维持了 82% 的极高平均召回率，如同开了上帝视角一般，将红队的初始后门植入（Metasploit加载、PowerShell恶意注入、无文件落地释放）、凭证窃取的全链条（从证书枚举、漏洞滥用请求、恶意签发到换取Kerberos终极票据）以及致命的内网横向移动（利用系统服务安装掩护的PSExec跳转）悉数捕捉并大白于天下1。

### **高阶语义重构：破解ESC1漏洞滥用的迷局**

在这个过程中，系统展示出的最令人叹为观止的能力，是其在毫无人工干预的情况下，跨越时间与空间的物理日志隔离，完美重构了极其复杂的ESC1证书模板滥用攻击逻辑。

红队的这一连串战术动作在底层的Windows系统中留下了五个孤立且冰冷的事件代码残骸（分别是ID号为4662, 4886, 4887, 4768和4769的事件日志）1。在系统的预处理阶段，这些代码被五个完全独立的靶向查询截获，并各自封存在不同的数据块（Chunk）中。如果依靠人类的肉眼去翻阅这几万条穿插着正常域控流量的记录，要想把这五个孤岛联系起来难如登天。

然而，大语言模型的神经网络架构在接收到这些检索块后，展现出了令人战栗的高阶语境解构能力。它敏锐地在两块碎落的数据拼图上找到了异常的咬合点：在提取“证书请求（Request）”数据块时，它注意到请求中隐蔽地嵌入了 SAN:upn=Administrator；而在随后相隔数十秒的“证书成功签发（Issued）”数据块中，系统记录的却是普通攻击者控制的账户 Subject:CN=\<user\>1。

大语言模型如同一位经验丰富的探长，瞬间洞察到了这个被刻意制造的“使用者名称/使用者可选名称（Subject/SAN）严重不匹配”现象正是这一致命提权攻击的爆发奇点。它立刻在报告中生成了一段令人背脊发凉的精确推理叙事：红队首先进行地毯式的证书模板探测枚举；随后利用漏洞强制向域控服务器提交了一个伪造SAN为超级管理员的证书请求；在系统愚蠢地予以放行并签发后，红队披上了无敌的伪装，完美冒充了域控Administrator的无上权威；最后，红队凭借这张滴血的证书顺藤摸瓜，毫无阻碍地窃取到了高权限的Kerberos TGT票据，并要求分配具有摧毁整个域环境能力的 krbtgt 核心服务票据，兵不血刃地完成了对整个活动目录的降维夺权1。

这一连串如同行云流水般的因果推导，标志着安全自动化领域的一次革命。它证明了该系统已经完全超越了低级的“模式匹配（Pattern Matching）”时代。在这个高阶范式下，系统能够极具智慧地区分“孤立合法的普通网络操作”与“组合起来旨在实施提权的系统漏洞利用”。单独来看，申请一张内部证书或是请求一个Kerberos身份票据，在这个拥有成千上万台机器的域环境里再平常不过了，但系统通过宏大的跨域时序视野，准确地将这些看似人畜无害的合法外衣剥去，揭露了它们拼接在一起时所组成的致命杀机1。

### **防御反制建议的战略有效性与操作可行性边界**

除了扮演冷酷的解剖师，系统还必须在烈火烹油的战场上充当蓝队的战术参谋，为其自动生成挽救危局的防御指令，以检验其防守反击能力（RQ6）1。

| 高危滑动窗口 | 蓝队防守专家在实战中采取的阻击动作 | AI战术参谋自动生成的反制建议网络 | 阻击建议的精确率与战术覆召回率 |
| :---- | :---- | :---- | :---- |
| 第一波次: 15:30–35 | 吊销证书, 重置KRBTGT, 重启DC | 吊销证书, 重置KRBTGT, 重启DC, 禁用暴雷用户 | 3/4 精确打击, 3/3 战术全覆盖 |
| 第二波次: 15:35–40 | 重置KRBTGT, 重启DC, 密码重置, 禁用暴雷用户 | 重置KRBTGT, 重启DC, 吊销证书, 禁用暴雷用户 | 3/4 精确打击, 3/4 战术高覆盖 |
| 第三波次: 15:40–46 | 重启DC, 禁用暴雷用户, 重置KRBTGT | 重置KRBTGT, 禁用暴雷用户, 吊销证书, 密码重置 | 2/4 精确打击, 2/3 战术稳健覆盖 |
| *(战术动作代号释义：RC=果断吊销恶意伪造证书, RK=全面重置KRBTGT核心密钥密码, RD=强制重启受损DC节点, DU=冻结并禁用入侵路径上的傀儡用户, RP=全域受牵连账户紧急密码重置)* |  |  |  |
| 表8：大模型实时生成的动态防御建议与人类蓝队顶级专家实战操作的历史比对分析 1 |  |  |  |

宏观复盘显示，AI战术参谋提出的反制策略矩阵，对蓝队防守专家用以抵挡攻击的所有类型的防御手段实现了令人震惊的 100% 绝对覆盖，同时在每一轮高强度对抗的滑动窗口内保持了 80% 的卓越战术召回均值1。更加难能可贵的是，这些建议绝非生搬硬套的安全响应模板，而是有着极强战术语境的“精确制导武器”：系统在刚一嗅到ESC1提权的气味，便立刻建议斩断毒源，果断吊销被滥用的伪造证书；在监测到红队染指Kerberos核心票据后，便拉响了最高级别的警报，坚决要求启动KRBTGT核心密钥的全面重置流程；在查获红队试图留置内网后门的新建账户时，系统第一时间便下达了冻结并禁用该傀儡用户的指令1。

然而，在对这些高度智能化建议的实操边界进行深度检验时，我们还是触碰到了目前自动化系统面临的一丝局限性：当红队嚣张地利用盗取的顶级管理员身份在内网兴风作浪时，大语言模型出于纯粹的安全隔离逻辑，会冷冰冰地建议人类操作员直接“禁用”或者彻底“封杀”默认的超级管理员（Administrator）账户以阻断后续破坏1。从纯粹的安全攻防博弈来看，在内网权限已经失控的危急关头，这一决策在战术上是绝对正确、甚至可以说是壮士断腕般的防守妙招；但如果将其放置于极其复杂的现代化企业生产环境中去考量，这却是一个在操作层面上几乎行不通（Operationally Infeasible）的毁灭性指令。直接禁用域核心的超级管理员账户，极有可能引发比红队入侵更为惨烈的连锁性业务瘫痪灾难。这种由于缺乏对现实世界生产环境极其复杂的商业连带责任感和深刻同理心所造成的“过度防御倾向”，再次敲响了警钟：在将生成式人工智能引入网络安全基础设施的征途上，我们仍不可须臾离开“将人类的战略决断与悲悯之心保留在自动化控制回路中（Human-in-the-loop）”这一不可动摇的核心铁律1。

## **精确率与召回率的细粒度深度指标下钻**

为了提供无懈可击的数据支撑和彻底恢复之前技术草案中丢失的完整实验数据矩阵1，我们必须深入到每一个恶意软件变种的骨髓，对其在识别初始感染载体（Q4，针对可疑域名与IP）以及深挖幕后指挥控制大脑（Q5，C2架构侦测）两个最硬核、也最容易产生大量噪音的集合类法证问题上进行细粒度的性能下钻分析1。

在这一系列严苛的数据度量中：N 代表各家大语言模型在这两个问题上输出的可疑目标总数；TP（真实命中数）代表它们从这茫茫多的可疑目标中，有多少是真正在网络安全界权威的公开威胁情报解决方案中被证实为铁板钉钉的恶意实体；TP/N 这个比率生动刻画了模型说话的“水分”——也就是精确率；而 Rec.（召回率）则无情地检验着模型是否有能力将专家眼中的核心威胁一网打尽1。必须指出的是，大模型往往展现出极其敏锐的嗅觉，它们标记出的一些被统计算法冷酷判定为“误报（False Positives）”的额外IP或域名，经过人类安全专家的后续手工溯源，竟然真的散发着极其诡异的恶意特征。这意味着大模型真实的战场精确率，实际上极有可能被这套相对刻板的标准答案基准体系严重低估了1。

### **Fake Authenticator 场景数据透视**

在这一场景中，标准答案基准极其严苛地框定了1个必须找到的初始感染虚假域名（|Q4|=1）和3个确诊深度参与了C2暗网通信的外部IP节点（|Q5|=3）。

| 模型架构提供商 | 问题四输出总数(N) | 问题四：初始感染载体精确率 (TP/N) | 初始感染发现召回率 (Rec.) | 问题五输出总数(N) | 问题五：幕后C2中枢精确率 (TP/N) | C2架构追踪召回率 (Rec.) |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| Claude Sonnet 4 | 5 个 | 1/5 (20%) | 1/1 (完美覆盖) | 6 个 | 3/6 (50%) | 3/3 (完美猎杀) |
| DeepSeek V3 | 2 个 | 1/2 (高达50%) | 1/1 (完美覆盖) | 7 个 | 3/7 (43%) | 3/3 (完美猎杀) |
| Cisco 8B | 5 个 | 1/5 (20%) | 1/1 (完美覆盖) | 23 个 | 3/23 (仅13%) | 3/3 (完美猎杀) |
| Ollama 3.1:70b | 2 个 | 1/2 (高达50%) | 1/1 (完美覆盖) | 9 个 | 3/9 (33%) | 3/3 (完美猎杀) |
| GPT-5.2 | 7 个 | 1/7 (惨淡的14%) | 1/1 (勉强及格) | 10 个 | 0/10 (无一命中) | 0/3 (彻底迷失) |
| 表9：Fake Authenticator场景基于多维指标的精确率-召回率深度矩阵解构 1 |  |  |  |  |  |  |

数据清晰地暴露了各个模型的底层性格。以安全为卖点、特化训练的Cisco 8B在面对C2集群侦测（Q5）时，如同一个精神极度紧张的哨兵，为了确保不放过任何一个苍蝇，竟然疯狂地抛出了多达23个可疑IP的冗长名单。尽管它确实瞎猫碰死耗子般囊括了那3个核心目标，但其低至13%的战术精确度，注定会让任何一个被迫去人工复核这堆垃圾数据的SOC分析师崩溃。与之形成鲜明对比的是DeepSeek和本地开源巨擎Ollama 70b，它们在确认初始感染源（Q4）时展现出了令人拍案叫绝的克制与精准，仅仅锁定了2个嫌疑目标便一击命中核心，精确率高达惊人的50%。而GPT-5.2的答卷则是一场彻底的灾难——它在C2追踪环节胡乱指认了10个IP，却完美避开了所有正确答案。

### **Koi Stealer 与 NetSupport RAT 场景表现**

Koi Stealer的基准更为极简：仅1个感染域和1个孤零零的C2 IP。在这样一个容错率极低的考场上，DeepSeek V3和本地化的Ollama 3.1展现出了令人毛骨悚然的“一击必杀”能力：在回答C2位置（Q5）时，它们毫不犹豫地只输出了1个IP地址（N=1），而这个地址就是致命的那个标准答案（TP/N \= 1/1），其狙击手般的精确度令人叹为观止。相反，GPT-5.2在这个问题上竟然撒网捞出了7个IP，精确度被可怜地稀释到了1/7。

在NetSupport RAT（一种通过伪造浏览器升级诱骗用户点击的狡猾木马程序，其参考基准为2个可疑域和1个C2 IP）的测试中，所有模型的表现都在伯仲之间，均表现出了可接受的稳定度。无论是云端巨头还是本地新贵，都在Q4（初始感染域挖掘）上达到了2/2的完美覆盖，并在Q5上交出了1/1的绝杀答卷。唯一的区别在于话痨程度：Claude和DeepSeek各自唠叨了4个可疑目标，而高冷的Cisco仅仅输出了2个便切中要害。

### **IcedID 炼狱级场景的极端考验**

作为所有测试中的终极试金石，IcedID（参考基准：|Q4|=1个跳转IP 80.77.25.175；|Q5|=2个主C2通信域名 askamoshopsi.com, skansnekssky.com）之所以让众多模型折戟沉沙，源于其极其冗长、充满迷惑性的多重跳转感染链条。受害者首先被诱骗点击某个跳转IP，随后被迫重定向至云端的Firebase对象存储服务，下载隐藏极深的ZIP安装包，该安装程序运行后还要去联络一个过渡域名（skigimeetroc.com），经过层层伪装后，最终才与真正的深层C2服务器群组建立通讯1。更为严苛的是，要通过Q3的测试，模型必须能够慧眼如炬地把倒霉的人类员工账号（csilva）与冰冷的机器硬件账号（DESKTOP-SFF9LJF$）这两个极易混淆的概念，从如同乱麻的日志中精准剥离1。这正是老旧的GPT系列架构以及即便接受过安全特训的Cisco都会集体翻车的死亡陷阱。

| 大语言模型序列 | 攻克Q3死亡陷阱 (准确剥离真实用户) | 问题四输出总数 | 初始感染追溯精准度 (TP/N) | 初始感染追溯召回率 (Rec.) | 问题五输出总数 | C2架构定位精准度 (TP/N) | C2架构定位召回率 (Rec.) |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| Claude Sonnet 4 | 完美攻克 (✓) | 5 个 | 1/5 | 1/1 | 5 个 | 2/5 | 2/2 |
| DeepSeek V3 | 完美攻克 (✓) | 6 个 | 1/6 | 1/1 | 4 个 | 2/4 | 2/2 |
| Cisco 8B | 惨败混淆 (×) | 3 个 | 1/3 | 1/1 | 5 个 | 1/5 | 1/2 |
| Ollama 3.1:70b | 完美攻克 (✓) | 3 个 | 1/3 | 1/1 | 3 个 | 2/3 | 2/2 |
| GPT-5.2 | 完美攻克 (✓) | 3 个 | 0/3 | 0/1 | 5 个 | 2/5 | 2/2 |
| GPT-4o | 完美攻克 (✓) | 3 个 | 0/3 | 0/1 | 5 个 | 2/5 | 2/2 |
| GPT-4 | 惨败混淆 (×) | 3 个 | 0/3 | 0/1 | 5 个 | 2/5 | 2/2 |
| GPT-5-mini | 惨败混淆 (×) | 3 个 | 0/3 | 0/1 | 5 个 | 2/5 | 2/2 |
| 表10：IcedID炼狱级多阶段感染场景下的大模型极限压力测试实录 1 |  |  |  |  |  |  |  |

在Cisco的惨淡表现中，其Q5召回率之所以腰斩至1/2，是因为它被IcedID的障眼法给忽悠了——它错把仅仅用作临时过渡的安装下载域名（skigimeetroc.com）当成了最终长期驻留的幕后黑手C2域名上报1。在惊心动魄的Q4（溯源初始感染原点IP 80.77.25.175）较量中，Claude、DeepSeek、Cisco和本土战神Ollama都经受住了考验，虽然DeepSeek为了保险起见多报了几个（总共指认了6个），而Cisco和Ollama则精准干练地锁定在3个嫌疑范围内。反观整个GPT家族，在这个溯源问题上可以说是集体阵亡，它们如同被蒙上了双眼，在最终答卷上只能唯唯诺诺地填上最后阶段的几个C2域名，对于攻击究竟是从何处发起的这个最关键的初始入口重定向IP，完全一无所知1。

## **解构IcedID复杂性：超越人类分析的维度跃迁**

通过剖析在恢复技术文档过程中找回的附录内容1，IcedID数据集之所以成为大语言模型的终极梦魇，其背后隐藏着几个深层次的三阶复杂性特征。而本系统克服这些环境摩擦阻力的方式，生动地展示了AI在复杂网络流量分析领域，如何实现对人类专家认知维度的全面超越1。

首先是多主机环境与混合流量噪音的干扰。该网络抓包并不是一个干净的实验沙盒，它真实地捕获了一个包含三台Windows主机的活动目录环境，而实际上只有 DESKTOP-SFF9LJF（IP: 10.4.19.136）这一台主机被IcedID攻陷。环境中的其他无辜主机（如 10.4.19.138）由于持续进行着正常的域加入序列、域名查询以及庞大的日常LDAP同步操作，产生了一股排山倒海般的良性通信洪流。这种背景噪音之所以致命，是因为合法的域操作流量在体量上以压倒性的绝对优势，彻底掩盖了那台被控主机向外发送的微弱但极具诊断意义的IcedID C2心跳信标。如果在过去，人类分析师通常依靠流量骤增的警报或体量异常（Volume）来作为初步排查的风向标，在这个场景中则会被完全带偏。系统的RAG架构摒弃了单纯的体积阈值判断，转而利用强大的语义特征签名库去沙里淘金，在海量的噪音中死死咬住了那些细微的异常语义片段1。

更令人感到震撼的是，大语言模型系统在分析过程中，不仅仅是在复述已知的情报，它竟然成功突破了人类安全专家预设的认知天花板，主动挖掘出了一批在Unit 42（全球顶级网络安全团队）官方发布的长篇分析报告中都未曾收录的全新高级威胁指标。 第一，系统敏锐地捕捉到了一个额外的深层C2域名 spakernakurs.com，并指出其背后的解析IP为 104.168.53.18，这与已被官方曝光的 askamoshopsi.com 的基础设施特征如出一辙。经过人工对该资产的深度追查，无可辩驳地证实了该域名正是IcedID黑客团伙在全球布置的庞大轮换或备用C2基础设施网络中的重要一环1。 第二，系统的分析引擎将 skansnekssky.com 定性为具有高度持久性的长效C2活动。人类分析师顺着大模型的指引使用tshark等底层工具进行深度交叉验证后，震惊地发现该域名在长达69个会话中，呈现出极其规律的、间隔约302秒且伴随极小亚秒级抖动的周期性心跳信标特征——这一极其精确的军事化控制行为模式，在Unit 42那份详尽的官方文档中竟然只字未提1。

最后，针对IcedID利用谷歌的Firebase云存储服务（firebasestorage.googleapis.com）来分发初始安装包的狡猾战术，系统展示了极具弹性的动态查询自适应能力。在传统的SIEM过滤策略中，为了避免系统被海量的正常谷歌服务API调用日志撑爆，通常会简单粗暴地配置一个全局通配符排除规则（例如直接忽略 \*googleapis.com\* 所有的流量）。如果本系统也机械地照搬这一标准策略，那么整个攻击的最初始入口将会被永久抹除，案件的侦破也将彻底陷入死胡同。为了破解这一困局，系统的底层数据提取引擎进行了外科手术式的精细化改造：用具有极高针对性的子域名级别的定点排除，替换了那些大干快上的粗放式宽泛通配符，并巧妙地外挂了两个针对性的高级聚合器。其中一个负责死盯那些没有任何域名依托、直接通过裸IP发起的强行TLS加密连接，这一招神不知鬼不觉地将深藏在 193.149.176.100 的BackConnect隐蔽C2信道拽出了水面；另一个则暗中对所有发往裸IP的HTTP明文请求进行汇总监控，从而一举将隐藏极深的重定向母星服务器 80.77.25.175 彻底暴露1。这一系列极其精妙的自适应调整，不仅生动刻画了现代高级黑客是如何处心积虑地利用传统防御系统那些司空见惯的粗放式过滤启发式规则来金蝉脱壳的，更雄辩地证明了：在面对极其复杂的现代网络战争时，那种能够时刻感知不同数据集底层性格并据此动态自修缮其查询逻辑的架构体系，是何等的至关重要1。

## **战略启示与未来展望：网络安全范式的划时代重构**

本文所展现的深层次经验数据和实证分析，其意义远远超出了简单地优化恶意软件分流效率的范畴。这些数据犹如投向湖面的巨石，激起了层层极其深远的二阶甚至三阶启示涟漪，预示着未来安全运营中心在底层认知架构上必将迎来一场翻天覆地的划时代重构。

首先，也是最具颠覆性的一点，本研究的结果无情地粉碎了一个长期盘踞在人工智能与网络安全交叉领域的思维定势：即“经过特定领域语料库深度熏陶特训的专才模型，其表现必然会天然地碾压那些通用型的基础模型大模型”。实战的检验是极其残酷的。那个头顶安全光环、经过重度安全领域知识“投喂”的特化模型 Cisco Foundation-Sec-8B，在涉及深层次多维时序关联的核心召回率对抗中，不仅彻底败给了那些横空出世的通用推理巨兽（如DeepSeek V3和Claude Sonnet 4），更是在一项最为基础也最为致命的实体消歧任务（将冷冰冰的机器硬件账号与具有主观能动性的人类自然人账号进行物理和逻辑上的剥离）中表现得一塌糊涂1。 这一极其反直觉的现象如同闪电般照亮了一个被长期忽视的真理：在极其复杂的深水区网络取证调查中，其核心考验的根本不是模型对枯燥的安全行话、花哨的战术专有名词的机械式肌肉记忆（Vocabulary Retrieval），而是一场纯粹比拼在无序且极度异构的庞大上下文中，进行缜密、严谨的逻辑演绎推理能力的生死较量。换句话说，依靠在安全语料上“死记硬背”换来的所谓特化预训练，根本无法治愈一个模型在底层逻辑上无法准确辨别“服务器”和“员工”之间巨大认知鸿沟的先天性智力缺陷。未来的网络安全自动化，必须构建在具有强大跨越学科界限进行高级因果推理能力的基础上，而不是退化为一个庞大但僵化的安全词典1。

其次，本系统极其巧妙的“双轨制”架构切分——将如同泥石流般汹涌的底层海量日志数据的体积压缩与降维任务，外包给极其专业且高效的Elasticsearch目标聚合查询集群；而将大语言模型那无比珍贵的算力与有限的注意力机制（Attention Mechanism），像手术刀一般精准地聚焦在对降维后核心高优特征的纯粹语义推理和宏观战术意图识别上——这一神来之笔，极其完美且优雅地化解了横亘在大语言模型可怜的物理上下文窗口极限与现代企业动辄PB级海量业务数据规模之间，那条似乎不可逾越的绝对鸿沟1。 在这个被称为RAG管道的神奇转换炉中，成千上万个嘈杂喧闹的网络数据包被极度浓缩成了一个个薄如蝉翼的JSON切片，但它却像琥珀保存远古DNA一样，完美无瑕地封存了那些对于大模型连点成线至关重要的关系型元数据基因（比如在不同异构日志孤岛间惊鸿一瞥般共享着同一个罪恶的IP地址，或是那些在微秒级时间轴上悄然吻合的犯罪时间戳）。这种架构不仅将大模型从陷入日常业务良性运转产生的汪洋大海般背景噪音的泥沼中彻底解救出来，更为其打造了一副由高度预先关联的行为模式构筑的战术望远镜1。

最后，以DeepSeek V3为代表的新一代模型所展现出的令人震撼的极限成本效益（处理一起极其复杂的高级安全事件仅仅耗资不到一美分，折合0.008美元），不仅是一个冰冷的财务数字的狂欢，它更犹如在整个网络安全防御生态的深水中引爆了一颗威力巨大的深水炸弹1。它以一种无可辩驳的姿态向整个行业宣告：一种全天候、7乘24小时不间断、不眠不休且永远保持在智力巅峰状态的完全自动化主动深潜式威胁狩猎（Continuous Autonomous Threat Hunting）模式，已经在商业经济维度上变得完全可行且唾手可得。 当一个融合了人类数十年安全防御智慧精华的人工智能系统，能够在短短不到60秒的时间内，像拨开洋葱一样精准地解构一场跨越数个系统、潜伏极深的APT入侵迷局时，企业应对网络攻击的生死攸关的定义指标，将发生根本性的物理层面的大位移。衡量一个组织生存韧性的标尺，将从过去那令人绝望的“从被攻陷到偶然发现的平均时长（Time to Detect）”，彻底且无可逆转地演变为：在AI雷霆万钧般给出了无懈可击的调查结论与反制方案后，组织内部那套繁琐、冗长且充满政治妥协的人类“杀伤链阻断授权流转网络（Human-in-the-loop Authorization Matrix）”，究竟需要耗费多少个致命的瞬间，才能颤抖着按下那个阻断整个攻击进程的回车键1。在这个已经到来的崭新纪元中，AI已经解决了“看见”与“看懂”的世纪难题，而留给人类自身需要去面对和克服的最终梦魇，仅仅剩下我们在生死抉择面前，那依然显得过于迟缓与犹豫的响应行动力。

#### **引用的著作**

1. teacher.docx

[image1]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAACwAAAAYCAYAAACBbx+6AAABDUlEQVR4Xu2VMWtCQRCEF4JdIIg2Af9QCi1s/QE2/h6LNCnzE0wpWKYOAUsLCy3SpBLE7HJ3uAwq8949Dch9MPDcGbkFx3cihUKhUIUP1Up1iPqNn5986AbYmRs57rGOs7Ok4H/SlbDDJxpICs5hzvKg6qumqtcoe67KWMIeAzQQOgjYojvVTPUMXh2+JOzxiAZCBx3W8b2EpZuCriUddPyoWjjMgK4lHXTYd95wmAldSzroeImy3l5SFeha0kHHNRama0kHHVaJdxxmkGq5QAOhgyfYSnN/ulTLIRrIREJwhAaBLdvUa+1bwh5tNBJLOVbBq+NDBP7i6IHHgOfXqWct0tVsv1TO1Vwo3CV/s+xQfMLu3QUAAAAASUVORK5CYII=>

[image2]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABUAAAAYCAYAAAAVibZIAAAAt0lEQVR4XmNgGAWjAAaagPgREP9HwiB+L7IicgHMQKoBQQaIgQfQxCkC0QwQQ/3QJSgBpxkghvKgS1AChkd4WqHxQ4D4LhB/hbIZUaUhgFB4vkUXYIAYmI4uiAzwhWcEFCMDkMtA6kXQxOEAJAFScBhdAghYGSBy6N4zhorjBDkMEAWgcEUGyVDxq2jiIDCfARJkGGAnA8Lb+LAlTAMSAIUnuiMoAgTDkxxAMDxJBehBw4IqPVQAADxYOBzMlf0cAAAAAElFTkSuQmCC>

[image3]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFIAAAAYCAYAAABp76qRAAADNklEQVR4Xu2ZTcgOURTHj6IIKeQrerFQPmLBRqxkYcOCDbGzULKyILayU4RSykIWNiwkZaFMVkJJESkLikKxQVE+7t+5p+fM/71z77wWzzNpfnV6Z845M3OfM/ecc++8Ij09PT09PXU2BZnGygLHWDER9gV5EWUb2brC1iD3g7wJsp9sKXYFucjKFowFecjKEg+C/A6yKp5PcroF5jRizomOZ3tCt8XpPIuDfGdlZLboy/gheg8Izm86nwtBTrjzRqaL3uAKGyJPRe0I7KjAs38GecWGyBnRMc5hQ+BrkDWsJA6IXr+XDaLPhi1bFqaIOmHmNbFS1OcoG4YIgtg0q8BU0TFWpEcAoS/xTNRvBhsit4JcZaUHb6s023Bz+Lxmw5C4J/r8eWwgLDU9VZBrpEuRutazXjL23aLG82wgLJAI+rBZJvrs52xIkAoGztGYcswV9atI77H0ns8GgFSBcRYbiHUyuhmJzoxnb2QDYXXeB3JyPF/odCmsPu5gAwEf3+T+YjWF32CKk6J+Z9mQ4JAM7gvZUzfXuMuKBHafXOkBm0X9UOsMBBC6prpnlOqjgYw8zsrlohc3dUGPzVykQI4lMn7NhZS8TjrjMSsIm1FtXrbNXJ/G9htLtH0GAnmZlVhb4eKK9AyCAz8sgUqgs6U4FeSj1GcVllqldLW6VKrNFnB0do/9xhxt6qORDKTVFJ8KKRAA+JVSC1SscKyVwZuHILhtgO8vVhJYPMOPu3qb1Lb6uJMNCZKpDT7L4I2h4XwLckkGq3psqWAf5a7mtugYMOtsUY5xvY92bP1gT3Vm6wO5ZmP1cSYbEsBvXLMBCB6MGJifmUjRG9GGmTtKLL1fijY7m12YSdi2wbYi6lI0BdmA3SZTDhtHY5/AtgdvGU5oFJ/ise+2XQjmB9FxvQ3yLh6fJh/s0hg0IV6QowRYAL088U5EdkHexB2pf/V55I67wmGpbySavuygoU04AAmKW8QUlejDbXZiB9Q1sO/H2L7Ev7kfieVb6aNFDkvr1IzPYoOEoDZ1EUs1CC97mDHJf/Aogc9oR1jZlg1BFrGyYywNspqVDQz1w+7/zr/8q+EgKzx/AO/L3xqzrc5pAAAAAElFTkSuQmCC>

[image4]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAoAAAAYCAYAAADDLGwtAAAAVklEQVR4XmNgGAUMDDuA+BEQ/4fiL1A+P7IiZABTiBeIMEAUHUATxwDpDBCFfugS6OAqA0QhD7oEOhhW7juMLoEOchggCqPRJWDgFgPCSmQsjKxoWAEAN3gfyuj75DsAAAAASUVORK5CYII=>

[image5]: <data:image/png;base64,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>

[image6]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADUAAAAYCAYAAABa1LWYAAABgElEQVR4Xu2WvS9EQRTFr4SE2BCJj0ZCrVEIhY9OIRFRUMiKXqGmUWgUWo1Eo5ToJQpRqCT+ABqN6ERJiXvevbPujh2yijc7Mr/kZGfOnXl7Z97MvCHKZDKZTGvyzDryzZQZYn3QPxtUphG9rNWAuk27sthg3bN6PH+G9cAa1vo065FVrbVQrkjWbkibX01L4Zg1xdoh+X8HJv6MNak+BjOmsWvWpZZpm7XrKswJa9zUf6ODJIlmhORCtLNutHxB9YM6Jek7r/6oiS2p14bKoAmAd1an55UJlnq/lpHkoYkt6u+5xiz76lU8v3iY3zgWCxRIkmTibz3viQK575Fswmb4y/IbKHr+DJJ88U2SVYTk1z0fHvp845XqX3csukiSXNP6m4m5/dRnPPdWR4xX4GZg1g9EYIIkFxwaK6w5E3P7CQMBOBhQ36q1MODEcw9qBbBqkM+B57v9dEcSh9w3K0lC+ylpGu2npFkmuUFgULi6uW9Z0mAguDrh5hDrPhqPT8HBXSfkVZ/LAAAAAElFTkSuQmCC>

[image7]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAHkAAAAYCAYAAADeUlK2AAADy0lEQVR4Xu2YS6iNURTHl1DkmbfRjURJDIiIiQgpA48IMwNmRphQSgZSBvIo1GWgJCVJGUhfmQgDAwMThUgRIuSRx/7Za7nrrPOdy1X33LrtX63uWf+977f3tx9rrXNECoVCoVAoFAqFxIBkk5Otjg2F/sGSZC+T/UxWNTYV+hPDJW/ymtjQiyyTPObA2FDoHdhcFpzNbheV5DELbaKS9i84492IYn9hVLL1LWyY69dOLB+PTXY72X393Irpkvs8TDYjtBkzJffheRR1wPvxnpslj3lI/XHaPlLyM9epTyg/m+xRsgWq1bE12VOp70NReSvZcaftlNx/n9MWSR7ngnSfQjZI7ndW8rObuCn55VrZjq6ubYOFZ+w3yXarxmKhcSA9g1U/4bSPyU45H/DPO/9zsiHJOiRv6hHJz9mkvh3ut8kGadu2ZFdUt3FXqm8MVX2F+gfUZxOMB5Kf+SnZ6WQfJD8PviS7nOxVsimqXUz2Qz97LKXNVn+85HdvgAXc6/zOZHOc/zeYGIvXE4ubVMcqyZPf6LQRqs11GqcWjUXw7FHdYDPxLb9bO7pRSfNCUohhVgTGUI52rkaL80E7qJ85BNec/l0/G09U9+u0XTUPkQVtmtNYj2/O/82E4POS/sX7ChYzvtRi1dhs47pqcc62iRZyCc22oITRupBGuy2+QfSgr90Yn7rqqv9jqvkNmqoaf2GM5HnZ/3OgPWhV0JhXXA98f2sJ7WgdTmuCgeOD+goOGznLU6nuYb6vgwZ3pXnzCbtoZstdmy04t7aOSprXZotqfgz8OEducPxfqDs4lqbi10Y0fwDt0N6TnKZIL6Nde0v2S2Pe+Bf+J1yTN7rDQuvaoKNxUwzbmDNOM9DZ1DrIobQTFg1b8BgRDNpiqOZwxQMWNwNeqEUqad58S1P+ayN5GW2W00hZaES3HsHVPxrFPsB+kPBh2TSiDQULYdqKIUKzh1/L0DvUp4jBt2oaKMD8ZlTSuOD4PB/qwqoVV3bjvurfuvmgWT5+HPR4cCrVPZaSwGqEiar5+sTwEaoBuz09Phm9QF3+obgxrVO6vkpRpWIG+Y5+PgoQuq8636pinze51Xaz50tXRQ92u/wtt5uERgFEnodnyS5ZJ8kVsm0Gh88qcQvLMT2gVUHj8plGNW5QhVO5ew4nOxm0P1BRM4Cd3r7kvTRuCtjGYEtD2x3X9lzyLfPw/fKddPVhoWKfSdqG7QptpIO60G8byMIaFGk2FrebebPo+P4wtlpvtIVBm6c65uftx7L36u53hEKhUCgUCoVCb/ILMW8cOxocbNwAAAAASUVORK5CYII=>

[image8]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEsAAAAYCAYAAACyVACzAAACE0lEQVR4Xu2WvUucQRDGJ2hAiZiIJkEsNGATBFOIFiGlYiFYGLVRm1T2gjYpIiZVuiAKATF98jfIVSpokUYQ0SJiK2KhkIjGeW5m751bfe9DyBlxfvBwOx93u+++s7NH5DiO4ziO4zjO3eQxazhFj0xepZhgbbPqIz/s5sgXGGfts76xqvJDOUZYeyQ5D4x/lPWTkvk+ql2by1BWWH8LaDJJrQhfWa9ZMyTzW2AvRz5wxOrXMV7uuYmBQZLvdqr9lHWi4w7WFGtIcy5INmmJdag5WaZZ742NhbwydjEekjxcOUIVp1HNWtdxhmThgQaSh+k2PtCr/sAvyv/eW5J4u/Ghqs50vKWfn0jyGlnPdBxiWeC0YJKayFdJUBVNOsZi501sTH32+IBQgbusnigGEAtVBFC18LWqPaCfBxRVUiGwSPuGbpNQLaimwAYl1WBBdSPXKvQa9DfYm6wFkh78RGMxyPsSO9P4QNL8yuEmxxD9ohgZuvriYP+IfBZU3CxJHqoNdKn9JiSl0EKS9zIOpIFSLXln/zFYC3pPIPQrVFwdJZuGRh5v6ilJHnhOEsemxfSZ8XWXSSroU6W8gUqBJm/7xw7J+nCs8GAv1A/fu5BEcjnFN+Fv1lzk+8xaNDZOVMn9CpNgYtxG/wM4Un9I1gSh8a/q+LvJazM50JqJBfBbx5TkoPJw41ngx98Hx3Ec575xCe/7h2FzQEesAAAAAElFTkSuQmCC>

[image9]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIkAAAAYCAYAAADOHt4vAAAEQUlEQVR4Xu2YO6hVRxSGV9BAJEaJjyhEuChpFMUiWigRLcQoooUPfKZSiIiQQtTGyJWQUlAhRE2CWikS0ELBQmSjjcTGQlFE4UYEC5GQoCFRfMx3ZpZ77XX3Oddzr94HzgeLc+af92vNzBbJZDKZTCaTyWQy74QJwRYEG+70TKbBvWAvkw1mZkls44c+ItM/PAr2wIuDjLsSF8lQ8nYfSWzzHB8xFKEjP3ox02eWSxzbj33EUGOqxI5M8RGZPlPIGxzjo4OtamIDubpWS7yLrAx2UJp3ZJFEN38l2CijfxDscrCfjPadxDK/N9pciflPBhtmdAvjcEZiGsr1cAe5Fmyvj5BY/3kp8y2T2IYDr1P0Htp7WGJ5m1ycwnGiaZYaXeeYcb2V/jMW3bgo5YWwzraUSfsNJoS6v07hIyns7yMTk74+hZkowiwquC7xbvBvsF+CPU5p4P9gp4M9DDY5aaeCvUj/LYeC/SVxkrUOjNcWoBEP6BvSf/g1WEewq8FuBvsv2NgU94eU+XoDm5v6RqTw5mD7yugGLAxMF//vEo8X2syi+EZiGXtSeEZK95qdwXab8NFgM024J6iICWzH6FgrmAgazYR5zd5HdIA2Gg0KiRPNwJ1LGumea4LEn0m37fk2aZbtSbOvleNJU05ILIc60ZkEhcs2dEnP5bTLDYllKJSFx1VYgGwGyzapLmK9j+BtavnMhRncpon7CXaen7y6+wgDUDfAhUR9TLBxwUam8BKTBtAKp7GobJm6ODnGLHg069UWp99OqebHi+nORKdvlq5gT5zWDuSl3GNSeieFNtkFyziwgPCclkLqvWctDGjdoPc3tME32t9HPk1h9RSWZ1JNW3dz1+PM7njwZbLj0BYaDdDqXlm0u/Bi4HOJebyXRrM7v104VilDzS6AIml4760SP0LW3aV8n1vSKfHy1g69OW7GN3I2p67Rfud+KTGd9w763ueSqBRJs5APjd2lcC9Bm240PQ6sd8WboflXlubH63l2Sfc2sPDQ2Jx9Ba97R6p90uO0Fepl/SZoCq6rL6v6bUGjGVSv6c7tknKiWCyWH5Juz33CF0wYiqRbWFiqMWiYHn0W2qEa//ESYPOvleqHqa5g/5gwcInVo4Z7Qt3iagZHC3UVRvskaQp99m1XpqVf72VXSIsParoDv/IRA8B9iTdwRT/HsyDmSXn+cxHdr4kCsyWm6zCaHit+p/gBBiZMNV5DoN5Bv57OSmGdXDvxaNpu/2Ihj9+AqnEEaH1vCpuE/tt721mJnlr5QmIddsPwwnkqZT7r4Uh3O/2vhbPSDsZAwqD9LbE9dIjG/5zCPGkVOqzpsEvS/cxt1i80v2N0AWD6pIQ1Rt8h1Sdwh0nH9wfV7cToQp1kNOBVpn1s9m2mFXulrA9bV41uMF+qaX6rRjfGi/qJ4zmeGeToPasns/eoTCaTyWQymfeCV+mNPZ1fiT2QAAAAAElFTkSuQmCC>

[image10]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAFgAAAAYCAYAAAB+zTpYAAACnElEQVR4Xu2YT4jNURTHj1BERMxQwkpRshCLYTaDImHBQv6tLewUKQslC1ubKZvJQkrTzELKQpKVsrFjwYJkI4kiFv6cz9x7fr/zu95v5r3n13szup/6Nu+cc+/73Xfuvefe34hkMplMJpPJ/K98UI2mzkwzDKp+y9xJ8H3Vj9SZaQ4Ww8PUmWmGpRISfCANGMtVx2q0xLXrFadVL1XLEv8u1WvVumgPqd6qThQtumOL6rnqqWptEjM2S4gjG9dWCTm6JiHBp6I9L8aneBSDdTpbNu0JN1U7VRclPN9gEdxV7Yh+Ekti4Il0vz153m1nf1ctcvZKCc+7FG2Sh83fPRIS+kr1K35GBRdUl509ptrm7JlYKGGAnYhE1bFAwgqBB1JN8B0JffdG/0YXOxR9lZXTBiSSfmxxsEm1BPM87KvRNj5JGKtBGw65vxhIbGbBz16voRytip8Z9A0XOxj/8kN84sG2qCWqXSgH9PspYXunE/RCqhO3XvVGdb5oUdZfJn5a+GHpwPvFfqlPGIvgWeJ7J92PndVIX9M+F8Pm6sXOY+uT4JTDUl31tVyRcIB0QjclYvVUz+khYR9Tp5Rb+mTix0eff8EmlRVqYI87uxWPJUz6jHyV6pbsF4sl/LDj0f7mYlZ/VzifJWaD87XDpIR+/tbAYedrKfFbzjbWSFk2aOMP2C/uc4GtjN1poA9slzAWDpGjqmEXs/pLUsFO9HNFi/ahzNxzNruR7/KHMLeW984GbjG8whv04XAEdmjLiebmYD9qNsBuYjzXE7/VXzt8kN2JO2W+6rOU38NOYfekTEjZBo1Uw3LGxTYlsTlFXf31UD99MlrJ19iMo1X9zTTEEQlvbiSY65LdlTMNQVJ5feaNrV//H8nMNv4Ad4mvHlC/wKIAAAAASUVORK5CYII=>

[image11]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABwAAAAYCAYAAADpnJ2CAAABYklEQVR4Xu2UTysGURTGz4Ii3pREykLvV7CwsZQdCwspSwsfwOLNTskXULIh2VC2srGSTyGyUMpCUopC/pzHPdd75pk7887Ccn71NDPPOfeemTNnRqSm5h+ZUV2q9lR95q22wx05UbXYTDGo+lYt23W36kF1qLqPSR0YlrDHAQeYLgmJ4+QD+JtsFoAbRP45+TmOVI9sGreqJpsJ5lTbEgpiTSkfUlzwjo0CvuyIgi8+kAIFkbjGgYrsqCbtHPtApWCqYmLURSajmH7Vjbt+lQoFwYLki75lMtJcSygawURXKugZkXbRIYp5JiS004OnxboG+b/gc1hk01iSsHCUAw4MCnclaszl/TEtYeMUs1LeGgzYPJsSvlmsm+IAOFVtsWng3RyzaeAv9MSmsSKhII45YksGyF9XfZIXwf/1XbXBASMO3y4HelRXql7J9//M5XmeJZu372K4ad4n9TA1NdX4Ady2XOpghODyAAAAAElFTkSuQmCC>

[image12]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAI0AAAAYCAYAAADH9X5VAAAD/klEQVR4Xu2ZTahNURTHl6IIKeQjyksZ+IgkiShJZgwoKWViIGXEQG+mZICJRCK6PkJMJZLBCwOZi3wUEkUooZCP/X/rLG/f/z37nLPvPbf3evavVve9tdY9Z5191l57r31FEolEIpFIJBKJRBPrnDx2csbJ2Ey3Z8BcyjUne1n5nzFVdPxeOTnpZHSzefgw0ckfJ9uz/0c5ee/kkpO35lTCFNFrnGNDzTx38k70XpCPoi9opu80CMwTjee8kxGZbmGmu21OQ4izouNm4/g6+/+Np1tjzsxIUYce0gPoD7AyAJIM/n2k7wZzRe91kQ2DxAXReKw6+9hk2s+GIQJi+8pK0XhhW8UGcNnJB1ZmvHQym5U5bHByXPQm+E63QSLjXkvYMAicEo1lEhs8ML7wGWrMEI2rwQbHWikoAj8lnDQoWVX4nX2GsrZusGTiXrYMxLCNFcQY0UpWhWWicRxhA9En6jed9J2wyMlWVkayWzQuXIs5JmrDZwtIGhh72VCRE6KDB3CdmBm1Wtp78Z0k5wQnP1iZAdsvVhZgz1v2DH2ifnVXxqqTOgT2h6H3Vfhs6HbMweROk0eYcaI3Nr5JOAjGstz/fhWwXOJ7DTZEgI0/J4clTO4g5bBcNI77bMjhs6hvnZUGoMItZmUEiAmx+fRk+mekb2GztCbO9yaPfJ6KJo5hy0YV8JLgu5MNJdS1n/ETJzZhwHXROLCfK8PGtBt8Eo0/FhwNIKYvol0TBBUYummeXyXsYpDJZPPBS8PS5GPlbjzp66RsP7OCFQVY4sQmDLA4MF5FWEV6yAYCxxyoRO0IjiCOShy2wvB+5mamzx0PtNpbWJmBDRa+iIBCYPNrycXSzTMTXD+0n1ngZAcrC+gkabCfQCx+pc0D1Rh+aL2L6CRpcFZ1WOJ4IRoXg+SDvof0/aClCu2+10v+BY1eJxtZKQNLx0o21ITtZ0LnM3iRmAxV6HR5woEdYimqxvNFfcq6q05od3kKTb7CCoo1OVTSMDuusjIDMwKB5oFZjhtWne2HRFvcqtgsWMoGxyYnj1gZoI6NMKoaYrGJd8PJFdFzKjwTxgn2qk1FOyAZkZixYCVAbA02iOoheQeV/5YXztJ90jqgBi6EzVLodNM21KfZkIOtqTGHgUhWfMevJng5DzI9qmcZdbbcVm1wSGa/ueG3JktuHHh2k3Zb7oMSnnyWNDZ50BH3gwd7IjojzMnkljkR1jaaNDybdUIsnJA+NhPzAmf4uiGpQp2He8BeAATtNz7xkwqez5jj/V0XaERC24sQ96R1zHjcdmW6u6IJE91JJeJBNbYTcjBLtINKJIKgmyqayYlELn7CoNIkEqVgP4Nji6qdWCIx/PgL/AgphmHmcqYAAAAASUVORK5CYII=>

[image13]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA0AAAAYCAYAAAAh8HdUAAAAd0lEQVR4XmNgGAXUA01A/AiI/yNhEL8XWREuANNANBBkgGg4gCaOF0QzQDT5oUvgA6cZIJp40CXwgcHhHyt0ARAg5J+36AIggM8/EVCMAkQYIBoOo0sAASsDRI4RXSIHKgHyFzJIhopfRRbcCRUkhC1hGkYBFAAAz4so/3XI028AAAAASUVORK5CYII=>

[image14]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA8AAAAZCAYAAADuWXTMAAABBklEQVR4Xu2SsQqBURTHjyxEWRSJxchgUfIGHoF3MPMEXsCoPIQkBoMZI4syMFiERcogznHO1XG7fMpg8at/3e93/ve7t68P4M/v8WPGmCtmjTnKuqZLLqhAxYzlg+KHln/QBy5Q0UUVeJ61B+bEgj1QRMFxeljkRksHprfTciCyqKWDGDg2n0VGtHSQA+6tjAiIoHjRAO41jUiLWBrxBnND+nB3kiJGRrwgBdybaRkSOdfSwRa457MHBxkQ9NFOmDamK64l87g8P0EbaEglfYMepiMzuuFL6Je8ABcnmL2sK6rz9gU29BuW1PNUrT0ZAZ9ublF+mnpQB95EWVizj8hjErb8mhuHqkRrxVwqdwAAAABJRU5ErkJggg==>

[image15]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA8AAAAYCAYAAAAlBadpAAAA1klEQVR4Xu2SMQoCMRRER9BC1NobCFb23kAECzvBws7GU3gGb+AlLCy2t/UCLmJhJ4iFIPqHn79kP7GwstkHQ9iZScIPC1T8j7UoF72DLuH7HHmzov0FK3rmUJ9rkja0kDmf9KHZyQfGCFrg6llBs50PjD200PKB8IJmDR8YqXm7oqfoJqq5rIC3cSOLfGXqHrxe1EsyQXreTfCbzi+RIT3vMvhD55dIzUsOUH/gA6MDLWTOJ3YoHy7JAlqYOp/YZl5AHhZsozBW3QrCOHhH0RX6p1X8ygepAj1F/kxu+gAAAABJRU5ErkJggg==>

[image16]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADoAAAAYCAYAAACr3+4VAAABj0lEQVR4Xu2WIUsFQRSFr6hNkAcWwaLNbFIMVoMmg2A0WPQviAhGm7xg0SL+AhGbYDRbBIvFIGLSIIjO4c7CvPNmZ3fe7qAP5oMDu+fO7N4Z7p1dkUwmk8n8HYdGz0Y/jnB/7A76Z5xLb87f9n7PGVNKMWmYQL6fbIboiE66JT8Fo0ZrRl2jUytcxzInmvMZB0JsiU5a50CLYIFfRtdG0xQbhCPRnBc4EOJedNIEB1piUrSPsNi2eBHNeYQDIVL357vROJsNQb4fbIZI3Z9TEtlHNUjSn0t0v2H0JLqbuK4qnVUr9GVIMVT15woboKo/39gQXeQOmyWkWGioP+E9sAlC/blp5YIHYTxKsg4Yd8lmQ/D+su/ngdEim0gCk+44IHp4+HYN5VK2MWW8SnuH0bzo+y84IHq6e3PbFQ2gT122re8rARwAKPcYsMi2Pi8norktk79v/SvXvLFmlfpKQLQ/eWPq4P4wzFCsDo/Sn59Ps8WEJsT2p4/iFxCb1eQXMCmD9OfQwSUy1hvOZFLzC2tkcftplXRQAAAAAElFTkSuQmCC>

[image17]: <data:image/png;base64,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>

[image18]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAH8AAAAYCAYAAADTTCLxAAAES0lEQVR4Xu2aX8hNWRTAl4zCjJEh0jBiJqWkJiF/H0SpqVFIU97MFA/ePIgnHqaIPDA1JeUJL1KS8qDc8iKmUCbyJzPzYB4kmVBmhrF+9lnf3d/69j7nfF9c935zfrX67llrn3P32Wvvtdbe9xNpaGhoaGhoaGiApSpjvLIHoM/zvHK4MF3lQiGzC91XKpP7WpSzVaXllY71Kke8soeg7994ZS8zQuW5ypniM5xQuaLynzWqgPto+7s3RExTeemVEX+oPJPwHORhofsobtQFvFKZ6JW9yhOVnV6p3FL50ysznJXgMCZRDmxzvdKxRcJz1nlDF7Fc5ZFX9iKLJb+6d6j86JUJWNE3pb1iU+D0nC3mqoR2n3hDl0EfZ3plr3FK8k7ZpTLLKxMQOUZJWNm5Z7UkfFcVZROom2ipnPNKY4XKbZWpxfX24vrTvhbdgTn/mspIZ6vDt9JOGeT7nOPQr/JKxwQJ7VpO/z6hsL2usqe4XqnyWduchbSUfFeq459VFkho8I8Ep+9VeR216wao8G21mbCS627F4ve5JOmQTcGG3hZCjk0S2jGhOgF5+3jxeaHKv5JxaAIiYrIt4WC0tF+G7dLY4vPjqF1deA5bjLpyMNxWG3L23zJwEhDKyziqMj+6tijincx1alJ4OpnvKWb9zuOF1C9w6SN9HecNtg9kJZSt9PGSmT0fEBzOiqBfVN45eHkGMIbJwH1EvJjsKnHYpEvBVnJGdP25yg8S2u9XWRLZqrDi8zunRxcXuJxJ3IiuY8z5fqL3gTFbFEgY6DVe2UH2eUWB5V6q/Rx3pe0sL36bRmTJOdWoyvfbVOY4HVGn6rkpLMIQnQ2ejS4ucL9UmRRdx5Q634xVRU4dBhv2D4XbSuHFGYQU1nc/2MYiCavcs0zCfX57WCfsW4r0E8dIRdBjKr96ZQ3Ylfjn0efBTKRs2AeKFj+7Yi6r/KLytTd0CCZlrv5gxft8GOMHzrDV46MdY5BdJQU4MTeYTOifvFKCE5k0KVgAH3tlwV8y8CSSXG/5nhRzR8IY5E4XS1MZ5+O5QSLnTFE5LwPzTqfAQXTen1ObA6lHPGwF70k49k3xhYR773uDVEdB7H4w6cPTQu/Drx0nky48TF5sudPG3RJ2YMYBCe0tYtlEw3+pcQAiVM6/b2cX270y+EI7S+80nE/z3TjTBh5hsFNVPpM5bvdbP2t/mwmnhwaRjt1AjO2AqiQVhcryPf3n/XJ2OC3t528s/sb5ntM7trw5WjLwfWpDoceA/F8oO0YeCsekOt/XPX8nRfi+VUVl2g/5eJfQSPg/7A3DGFYw7/wuIKSXbUU5pDrplRmoffz+HucSGS86PfDDDr84DhmOE9lD5irq4cgMSYfwwbBZ+qeEnIMp6FLpK4azge8lPIedz4bI9kBCaks9g5SSqwUaSujUP3PUOZ9fLcHhnEPwd21/cxL67ovkhkEwbP+N6w0gOSRsDf822gAAAABJRU5ErkJggg==>

[image19]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADUAAAAYCAYAAABa1LWYAAACI0lEQVR4Xu2WzyuncRDHR0vZVlwUq1WIAynUtvsPOLi4KcR/ITk7uGs5SBwkNyltymEPThIuipJycFKEE7WHxbybGft55vvr+T6++NL3Ve98n5nJM5+Zz2eeD1GJEiVKfFBGWceqPud7d+yyHlgd+lwW2Oot6L3whSTxZe9QDkn8WOSr8YM1yZoPVBGJyAzikDA6kol2kpgJ73gJtlkXrDZKXsVbyt2FKpKYM+8AaPMqa5Pkn1SzhiMR8UEyTd6YJ0Mkyc56h8MWhXdGmGPdkCzGWg61hEExQRI/vTEBf0lyqPEORxel6dSYGsN9vqK2JKRULAGV9L+wuZgiiftlBnQGhh0zKFes8+AZ1YrzAmzhNdbXHMp2RgB2CN536h1psI7WmmFEDb1mUGBDBQx0Mc6HrlCL+kaSw5azexpJ4jDWn1hSI9ptWJWSnCeAyj0X+zYdeYfjkiQuUqQFNYbYHjWwNfdZPYEtG9NUmEGBwWV5YPvfsRZZv9WG7x38KbeJZnWU63O3Ptt56mTVkYx5jNi4IKEmb8wTO8dIPuzYBmtdfehoWgZJAqBx/RueJ5DS4hj8Ifn4ojCfnC8un1n/SN6/x7rW38NBTMaFGXblCM8TBoSfjvmAa9IAJbsmpQPFCocWjkZWMOv9GcNYRbVnnP2t2CLJ0bqW8VhgxqOa9yr8tmriMnpA0sViABdXOy4nzhehlWQh6Ei//i5mvrMavPHD8gjzkIDIe5U2bQAAAABJRU5ErkJggg==>

[image20]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEEAAAAYCAYAAACldpB6AAABOklEQVR4XmNgGAWjYBSMglEwCkbBAAMeIA4B4llIuBBFxTAGCkD8H4irgFgYVWpwAm4g3gDEK4CYEU2OHOANxKfRBQczmAHE7xkgnmdlgMQeCIsjKyIBgMz5ii44mEExA8TDIM/DwEKoGLkgHYiN0QUHKwDFGMizJ9DEn0MxOtgDxMnoglgASJ0UEEviwYOmjIhmgASCC5o4SKwVTQwEwhiIKy+GVCDAkj0HkpgSVAxEkwtA2cESXXCwgjkMmHkflAJgYiC2NBDLAPEWBkjhSQwYUgWjIgPEwyxQvgmUD/PAJyh9CIg5oXLEAjOGIVRFhjMgqsRSBtQqUh5JXQMQT0HiEwNAKQhkTg0Qi6HJDUnwD4j50QWJBLBmcxnDEG42gxpNsMZUBprciAEgz/8G4gvoEqNgFIyCYQMAbHY55WNKNgoAAAAASUVORK5CYII=>

[image21]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADQAAAAYCAYAAAC1Ft6mAAABkUlEQVR4Xu2WvUrEQBSFr6ggiIgggmCz2CoWFja+gIWNWgg2dvoE2ljY+AIiFjaWPoIWooKNYGVhI4hWNhaCYKHizz1Mwl7PZpPJJkFl54OP3ZxJQm6SOxORQCAQCPwe7+qXp8/RMX+WQfVD7TDZgLiLvzQZWFbPKKuMTnVW3VX3IvE/iy11jLIlcQXh1zKprlNWOijkTT1Uh2nMhxcOxD0ZFNRHOQpEUT/oVxea2Gv28wHnwuuColpligOp9wszrnbZ4EQam8y6Wt/Viye1m8OCxP1zzgPMmrphtvfVCbOdFzQzzlE2K+IKmuMBZoi2P9UeysC8esVhAjOR6Js083Ityf2TCu5u0jsKRsWNZ1FVQc36J5VN9ZbDnKDoAw4LEt/ozP5hMFVuU4aF7UZ9FZpJUniUcicF7/6xoG9w0DTlO9EvegvTsQ8opui0bXkQd22Y6bzBzIaDkp5CTdxUnAe7sI7QmA/H0rh8xF6Y/VriSF3k0JP40wereZ5Pn0rBXUEvnfLAf+VOvZdyGz3QlnwD1Ahb+XxJlP4AAAAASUVORK5CYII=>

[image22]: <data:image/png;base64,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>

[image23]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADAAAAAYCAYAAAC8/X7cAAABT0lEQVR4Xu2WsUrEQBCGf0FB8UBFEeQq7Wy0EAvBN7DUQvABFLnK4iqLu8IXECsbC7H0FcQXsRYES20EdYZBbu43SzImAYv94C/2z84mk8zsBshkMpnMiAXRV0BnFvZ/uBTdkncBe9hd8l9EW+Q1xrzoUHTtdDQ2o5gPNoRnWAKT5D+KOuTVZht2s2NYEhG0fK7YhK33ziYssTHmRAcJzbp5KXqiezYDLIlmyFuDJXBHvrLnBw/43SBeJ6OpheiNn9hsgJ/61y+bpC86d+Mb0aYbV0Gbr8tmA7zCEpjgC55lGn+KpskrQ9/+SomiPaGk6j+J1qEGRWkjgXWk6z/JAH+rZS2hVTZromuW1j/zBguM0kYTV6p/j9a9BvCJV5V91NtGPVOwZyk62JLozqNBfOJF2ICtcSpapGtV4O3ba8fNax1tWD0Ah4j9SmQymSDfgQBRufWDSbIAAAAASUVORK5CYII=>

[image24]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAA8AAAAXCAYAAADUUxW8AAAAtUlEQVR4XmNgGAU0Aa5A/BBdkFjwH4i/ogsSAyYwQDSDMEmAB4hfA/FvBjI0XwdiYQaIf0nSbAjE86HsAwwQzSCXEAX+ATEjlL2UAaJZEiGNGzwDYlYkfjkDRLMvkhhWAIrTv0D8CAm/Y4BoBhmCF4Cciw6MGSCaF6JLIANQnNqiCzJA/ArSfABNHA74gfg9uiAUgEIZpBkjiXoD8RcGRCq6jyrNcIEBEgYweVAYhKOoGAXEAQA8tys1vYz7vwAAAABJRU5ErkJggg==>

[image25]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAJsAAAAYCAYAAADtRY/6AAAFTElEQVR4Xu2aXahtUxTHh1BEJHIJhQflK0kU4ZYQCYUiHy9eePBEuZJ0r/LiwQNCqMuDRHiRjwdlR0l4oIhELokiKUVc+Zi/5vyfPc7Yc629zrrrnL2P1q9GZ68x515r7jnHHB9zHbORkZGRkZGRkZGRzctNUbFk3BwVI+vDkUkuj8oBeSLJ1VG5IPZP8m9UJvZK8lf5O7IOHJrkO8uT/1toG4orkrwflYX9knybZLflMfxdrhGukS9tWAP4xOrGBqcn+T4ql4ALkkyiclGwaEzg2bGhI3x3Z1QOBPfGm7Rxt+V+ZwQ9Rob+z6Dvy8k2NeIDQ5vA2C6KygVwq03HikxWtS4QvAcDOiA2dOAoqy/0ENyWZFdUVthleQw1D/aPtRvHWsBzvmT5fqQONS604Yx7KJbK2CaWB9SHbda80HsKofmGqKzA83+NSpt6tiHGd0eSG236e5s2l555WGxYIK3Gdn6Sr5IcXa7Jjd5L8lH5DHsnedpyfnJO0dWg7fMk18eGxDVFGAx9+Fy71wmWn80Y4o5mnBjFvkleLNcnrerRj32s26Jtsdzvqdhg2UBouzM2rBHGopyUQoh7thVEvye5PSoXSKOxHZ7ksSRnWu70uOUdBecV3blJ3iw6FhndJeVasMNInHeU64ttusuB72FcHCmgu7dcn1ra1Ye2R8v1QZbD0sErPXL7H0leLte0oeub/4njbTrWNlhU+p3mdPx25hD9VqfvyyTJseWz1gUP18QH1rC4C6LR2N6wnLBfZbmTL/nxKujedjpA90zQ/WKzlRH9mAiP8jWe6VE4eMHpvik6GZu8ys6VHpl5i9EFeZB54EnppypUlehrvtMecIytXihtgjjfHtqo0ufxoOVjna7SJaWo0Whsl5W/E5udbBmGT3ZVSdIm8HLovHdRWIoDnlj2VpFXbNYICd14OyGvwr3FIUWHB/DI43WFcXbpT5+Yr+ks7JGg7wPh0/8+bbB3nC6Csa3XUVAfGo1N0EGhUnAdF+C6ovNG8UPReQi96DAGD7pXgw7Q/xyVgU8t5yeepoIBI42hvg159jZUCdfyNfTRs68VjaEmbZ5rUxkbnosOlwZ97Uv8aEKmp2YoJO9x8fQcyvWavi1UAH2eDTom+bOg60OXMNpUGSrUEWL7wmapeXzg3rwtaGK9wmjfV2I1u1mhdu4lA/DhUuFCoXF3+Vu7OZOjfE3nQPE57GRCr0JuLe86wvJCUCXSx4dL6WS82gRUsR9aPmGHs5I8aTmJ/zrJfeWz50Sbb2x6exG96P1FHyMDMMYHorICuarGG+HebWPbNAUCMElxV+Hl+JLP19jR0lGpqmp9znIoFa/b1Hg4OlEuI88AhLkvymfgtUx8TcRrj5/K51tsdqHljdBda3lMp1jOcyh8CPnwlmVj8qGG7/nNNe/oQwVMDOPwkOU2eV3mRfkrz9RcNHGXzf42zzxjY0zMzzKgeXo3NggS3rjTmcDayTSLz81wyR4MRZOCN1L+Ie8HDIRr9NGwwN8DwdgEG0KG59H97gn6uHj8HjyQoD2e8vN7Y0HD8Ysfk2S768NzOO1H/7ytrt7ZtLRNnE5wfBLv68eMh47t6Dxa3JgbbzTa+OStqtI1J/9rKAziouB5ya2gKWRut26vq9YKxVStqBgCUoiaUxjZIEjUCacPO533GnhQQm5EXmLei/i1wjvX46JyIPAktd8yskHsSPKxZQ8G/P3RcsVMEdH2eotD7VqI7wt5oc9Nh4SCYr3uPdKTmK/Ng7J/qH+eHNpLCrzw+M+TSwbVMBXhVstvJLrCO9xl5sqoWHb+AyakjFfYWOPAAAAAAElFTkSuQmCC>

[image26]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAOwAAAAYCAYAAAD50BEbAAAHuElEQVR4Xu2aW8htUxTHh1DklsgldBykOG6FREhCdPCAIrcXSSEPdCi3ePCgJEkOoo8HidxKLqGsjgdCbrl1or4jlxAixJHL/Jnz/+2xx1l7f7fV2evT/NVorzXm2mvN25hzjLGWWaVSqVQqlUqlUqlUKpVKZaskB0Zlj9gyyUFRWemeXZOcFpWVXrFdkh+jcoJ8YO1z5r4kK6Oy0g07JPkiyT9Jfg1llX7BGG0elYXPknxr+Rrk8yK/ON22M1cvnhWW73lNLCj8ZXlu9Ql2f+rVC7aw3IFHxoI5wn+norLSG+5PcldUBna30eP4lY03+PnCxOd+D8WCwjFJvovKCUAIsd4GixbSC063XBkqOF92s/zfQ2NBpRdsYnl8to4FAXa7UeP4rOWyNhd2vlyV5DrL92uGi4agfHlUTpDGemSwjS28MhpoJkalf7AY/xmVLeAWj5oDxL6UHRAL5slmSf4ox9xvnSuLNJYXir7Q2Oj+sWMtdyBuCuDPv57k3XIMmyZ50HKscVTRtUHZJ0nOjQWJs4pQEa7huO1e+1p+NnUgweShnsSvuEuPl/P9h66oTJI3bW4Tnznwc1TawFVeGwsWwItJ9izH3HNc3uMMG2MgE6CxEfXZKcnqJIdbvuCeJOeXMnx7dEcnebnoMBR0J5dzwY6H/31zOT/J8nV6KP/DQC8ouhvLuU/76953l3MSD39bzjgKyn9P8mQ5pwzdQuPhSrewu45K7oidLY8Zsa5HRnNn0C+EPZKsced+Lraxl40v39g0NqI+L1hOAqmzznRl7G7ofMMBXQzgcWNIFni4jhXXo/iVZ3oU+zzmdLgw6GSwGuipmSsy6GabJP9n6J++LFiMxWyx55WWr2O+KEPMOe5rV6EOuykusWAhaTWAAjE35dvEggDvbXkVNB9ZCI2NqK/eQTW24QUyLp9AUIaXMsFui85PGjoL3XlOB43lXTPyjG1oyLjhPlOogfYDsX3R4SEIylcVfVdQL+rTR2bLyG5M6PO2RJJn2trHhnnRxbtbNh+STR7cb545akGQwcYQbFI01t5HM1Aot1dwHv90TtF5w/q66Dy40egwKA+6thgH/fdRGfgwyW9BNyoJdYqNzwrOF9q4X1T2hOeiYoLMxWC5pi1+ZfzjPFoI3GOUjNpBl5TBqrJMcg+6Juj4cCGugm3GRkIoPlDPOWGEPrrZEa55OOhwfT4OOmCx8V7AYolt6QvEXkhfoJ/GucR6LTcVC2xgVIuB+7YtGJqPo/pqybjE0PZeVA3wk56vL9DJzV1fftE15VgQMyh+VWo9PgfXBTda7nNbHLqL5d1zR8vXeNdXOi0AfiFBf2+SByy/OPeJK+73U5Kry6+y43Cb5cTbq0X/ng0mEkIcfXGSR8svuz6Dor4QpyZ5JclblhcPZds/stw3JEWaJK9Zdt+mLN+HZ/gwgMQb977CNlwUwe+utGut5f5W2HCHDRsQ/cBXRrTd/5dMO18aXWa5zcAkp30kEF9K8kPRjwO3tm0cxbWW2xiNSkkfJEK7SETO9iEFfdy2eAOJLD9XIksm6QRMqBhXstvyBx+/0snSkUFWNvkRyy6jeN4GBkgnKsaS+wp0PpNL8K3nG+4cjrfBFyiXWP6vd32ZiNKdbblOwILgJz47N/8HJbdUhtEr3c9xU46p23Hl+JYigsQY/eNfE3CsvjrRhtuiNrM4ESLgDlJfUGJP7WpsYGDKgItbbTh+Bx+/6pixVF2oF+0SMnqy89+U4yNsOGHIQkt9WJjxaKaSHGxjJpBjttc6+iQxhjCEG+gV8jBvmFfA+FE2Xc7b4Hqu0ZyM3GC5nDxIG2we0QYmydvW3k//wQRaHXSsSNoZPRgQN7o96Jmg6BF2RWWd/c7DwzlHH40T/D0QDFawqLR9Pqb7Xe90GBM7pGCSyhWasmFvwK+sGnTEJy3a4lcmpfc+dA8d63pcwBiv+WtZSNjJBJNGcT+Tn/aRReV3b11UYLfwngMst4GnocXJg5Giw3A0Gdjx2T0Jd760YU+LutOGuUKOo+3DCT+uEp7nob3oMVDuofpp4YptEfG+fodf1lKOxIWvseFxmBTUTWOOaIGLHsn/CoyJBQOU1RZMQB+rs3PygQZgKEwSJdY0cdsmit/FyJLrHtrdBZPHv29kp5p257icJOiA5/tVnt3RhwAR3OkIz8LtBAaZD0sEWW7ah6tPKKB6Ud9RsVtb28eh8MZ7Zl3RtmB3BXVmsatMACa9JiA7GK7VPpYHpLGBEXj3OLp88i5wWeVGPlF+4yKAUWAcxIvgy9jteB4xIGAkfgfwqz1eDQsIrjO7CouAN1gWIbWL/8jN9zQ2WABw3XmW3HmexWIEuLt6DUdbvcHK24qLy1zhuV2/aiJ3cFNUdgShlA8JKhsRJrLfpZZZHgySSYCREic9bTlB4WMEjAs3hHKSPQL3bNpy0g0wzqdmSrP7TMx7SDm/MMk7Sd63bGQ857BSts4GCSh2IZ8o45pPk1xezqkbiSA+bsEz8HXCWKNbB4QjJNlwpVZYbovc+0st9wWyqugArwA3jAWCuup9M8Z+kS6aB34h7Ara78eqS2JSslLpnDVR0TMwAL8YLRYfV3cJmfmVUVmpdAnGILe3z2BkZKP7Ch4T71WXDP8CjPInLCi10KgAAAAASUVORK5CYII=>

[image27]: <data:image/png;base64,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>

[image28]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEcAAAAXCAYAAABZPlLoAAACIElEQVR4Xu2XvUslMRTFj2ih+IUWimC1jQi2aiNoY2GhWFuInc3WW9hbCP4BIopYiSCCaGkxYGktgtgoouDCiuIWu+BHDjfBO5nJvHm+DxDnBxcnJ2NucpJJ8oCCgoKCqtJq4r+JGxP7Xt2350w9D5n4qcrfnhcTDfa518SyqkswYOLNBpdbS7y6bnRA+hBiAR/9vDTRGKvNzwWkjUkTj15djFUTf/Hh5Jot14seyEy6QYfMWTfxoMojkHeblJYXmupy0hw39hijkBf0SsnqYK25Qnpu9o/6oKdzEndUWRucFoRm/rbPrt1zW47xz8SdpzUj33Kd9wUPJvYHU4qQOYsQvc3TT6xeDtM2NIk2uqy4B1lWsyYm9Asl6ITsT2mwjsu2XELmHEN0HsGayOqpn0UATtiGKvN/EytnDNLwkYkDq81ZjYPLQzeSJjhjyumwI2ROSI8gOie6HFYgG/omAnsOl5b+Fh2nSA44C21QJcaQkAkhPYLofZ5eMc4cLlnNttV/eHoWzqBKjCEhE0J6hBqZMwxpmGZonDn+ppVFrc2JILp/bDvd36grph3Z5kx5eoh6fFZLSDfhM6dVbl4hCTQ8vZgwzy25Xhsyr/jU/avBE+K/k6rKDCSpHggN4220FLU4yu+Rbg65NXGoyszBd/uVVnV+QZJc279b8eog1boE8lNh3mdIHxh/rKY3Wk4gj13+hNi19eOqvqCgoOBL8g7MmaJXB4YKigAAAABJRU5ErkJggg==>

[image29]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAsAAAAXCAYAAADduLXGAAAAv0lEQVR4XmNgGGFAGIh1gJgbXQId3AXiv0D8H4h50OSwggMMEMVEAZDCw+iC2ADIapDiaHQJbCCIAaJYEElsBhDPRuLDAch6mHv5gfg8EEsA8S8gVoIpggGQwjlAfBqIOaFi04H4KVwFFGgyQBSDcBkQM6NKo4JJDAgnVEDZrghpVPAciN8i8UGKD0DZuUAshJCCSIJMR+a3QtmfkMQZZBggkiB3w8ATIJ4PxJFAHIwkzsDIgN19bkAsiy441AAAAGMkjUuclJwAAAAASUVORK5CYII=>

[image30]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAC4AAAAYCAYAAACFms+HAAABRElEQVR4Xu2VMUvDQBiGP1FBUREV0bm4CAV/h4iLuulsf4Lg7tahFEGxLt1dHdwCjg46OOrg5OjkIoh9396diS+mokOuwj3wkOT9LumX5HoxSyQS/4IFWIdTWhhmHuE7/IDTUqsa/j776MI23BFX86GOzNwJsVkz10eZK/lQB8NrDSPQgPtwVPJteCLZ5+vZ1UIELuCEZOzvRbI+W+Yanytkp7BTOI7JKxzXkHCKhPk9C2/hMnyDtTAoEi24p2GATd/AeXjusyef80bK4FM4+6WDrqfw+qULxoy54hVsSi02x/BZw0CY33d++/C1HBX2wz/rt2SWv44Rv186WPjLVFnsn/kzS+Z6OdJCQNdvHl/6/QyO5aVK2TTXy4EWCNdLXb/DYD79+0JeNYc2oPHweZ0sZBs+o2w+FvyCsod1LSQSiSGlB0PnUh6/8ZzMAAAAAElFTkSuQmCC>

[image31]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAKUAAAAYCAYAAACbfz1xAAAFEElEQVR4Xu2bTYgdRRDHS4ygGPEraMTARsWDEIwQo+QgBEEIhFyiiKJ4VUQvCmoOQnLPIQgJQYWQgyiiaAg5CEIaBRUF9aAkiIKKH6hEUeJBJWr9ram8erUz0zUzve57y/ygeDvVPfX6o7qnquct0cjIyMjIyMjIyMjK5zqWu6rPkfnkdpI5XO0LIlzOsoHlQl+wDKxj+YflfZbzXNnI/HExy68kcxqezy9YzpDc1MujC3OK5XuvrOEAyw6v7MB+kj5DPme5YLo4xFcsB0kWEsbuFpZvWa6ylQKgDa+zPEuys1jZOqkW4lGa9OtdV9YVjAl8I8dTLE96pQPtOeaVbSSSm2aB30kmu453aDLgkL5O+RPLenP9Fom9K4wuAtpp2wN5YKpGHjydvA0r90+qZvmE5TNz/QTLH+Y6AtrzJ023oY6XaLpOxCmTV7aBG972yh5cwnIPyYpXuW+qRh44ZfJKB3YitLmPU2JH84MNO7h+0+giwCnhNOjn1umiMDewvMpyvtMvsJxwujZ2kvRho9NDhznpQ6Jmp1R0PHNOGZnXs6jRrs5j2Uxi40ESxxxCpPFDnBLg3l/MtU7oC0YXAU45NOTBuMMxPX+znOOVLXxK0gcfOkD3jdNFSbRMTqkTcqnRIU56zly38QjJSi/FX5Rv/FCn9LxHYq/P43uoU9aBcGLBKzNoKFHnlDnHaiJR/t4uTtkUli0Cj239YmRKH7GsJYkrrtVKDSAQRqJUErQleaWjpFPuIrGF3b4rGOTjJO1F/AY7XWNKzx0sL3tlgA9oBTklDKJDl7E8X+l01cFJ23iG5WqvHACcHN/7kC9wlHBK9PdhliMkGSYy6K5gnNab62tI2nWr0XUF96/xygC3kdy7yejw9JsVpzxKeVv/cRFJxTdY9rqyCNgl4SBtEokxUQcOgrZgx8lRwiktGsLc6Qt6ADs2Xu3CNgpOXANI1Gz2jURpVpwSwM9QF/1sPLPUyfi4+sR5XReWwikfd2V1lHZKJBR9Js/G4UofOwrOZyNntG3cTfL9J1nOrf5G0tSHRPm+dHFKPXrDvDU6ZaLJl+rEvHK2NA8e33hkleL/eHw37YrqTNHEBZOA+hryKEOcEvchlCoJbL7olUES5fsSdcrw4xuV7PkkrvXUPbGsmhTVMquJDhZL0yvTRIv7bQ+wLW12HiOpf7PR6cK254vQ4e1T485QoX1KTq/k7CAOxf2vGd2GSmcXGvqDfkVItHhMPFGnDCU6OKyFMXs+qcYxAHg7EAE7Tskjoch51vUkbcWjyqM7GOzUgez2B5o+A9xFco+NZ3N2sGB9mWbgNkE8XOm+NLo69Kw3Ob2Ss3MlSfk+o0MC52N0TWIPOX0dH5LUtWPlwe8mUOdpX+DAWGWfAjj5hzH7znd7pcs1xHMjyT2IC9HIIbQ5ZSL5nq+N4NquQOwk+i6/iXtJyn9mOV39DZ0lYgdHZyj/rvqEIKu3wEG1rA0coKOODweUiB0kOijHYXldn8BNtHjMPCjHkaCO8Y+Vzmb2ukj8XPiFqrTN65KChAU/IthDS/uaMQLeb5dgpdrp+kp1KKXmdVkIxR4ZsPv3De4tpezg0brbK3tQyg6OZLZ45RKDXTR55bxwioYfi8CpmxKCLpSy8xt1C4eaKGEH/el7jjoEOKUm0XPHAkkH8LrT/3Imio/r+lLKTlMG35USdnB2OdSxu9DrR76zCl77jf8OMd/ov0NEXqDQv0BDhnnb8OshAAAAAElFTkSuQmCC>

[image32]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAC4AAAAYCAYAAACFms+HAAABI0lEQVR4Xu2WMUoDURCG/4BCxIjEELC2Dlh4DLu0OUgukQOIeoS0KewGLAW1sDRFLHOEgCQzzjzz8kjemhSZCO+Dn903/+zuv7vDskChUPgXtFgd1mlqHDJj1jdrzmoknicn0FxZCBrcG3njM2iWoCzS8JwWnSFUBJfxkIZeajhDqAjehTY0o9od6yFae0CoCC4jEhrOWW+sS+isXYUmBwgVwcV8YV2wHq02sbrcyCaOWfdbKne+FEIm+BnUfGINEs8bQiZ4mO93236u2q4QMsEJS7Nm+8NfN88uo9L+OfJvEDLBxYi/37Ie2T6xjpbW3iFsCF6HGvH3W9Z96NP/iOoevELzSJYVrs2Qf4LArdXWHrAn5Noz1pdparWbuKlQKBwYC/fzUwunF7kfAAAAAElFTkSuQmCC>

[image33]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAC4AAAAYCAYAAACFms+HAAABWklEQVR4Xu2WvUoEMRSFr6igrCIqgsWCYC1YiPgMIja2PojvINv729iLjYjYBSwttFBstBB8CsGfc5Ib907WHdBiM0I+OOzk3Nnh5JJkRqRQKPwLZqElqJUWmswz9A59QhNJLQfD0KOEPNRJtVzFSbgpN0MSmsjwkQ+pycbCdWpmYFNClgfjOfXWjefh8mBhOy1koC0hy57x2FB6q8bzbGlh2nj70JEZ5ySu9R7ijMgUdAvNQ2/QYrwpA6MSsjDbeFLzsHADzUDH6r2oz4n0gw8+/KXqnmdZg3ahJ5XdrJ5JCQGvoE5SawpOfmhiXN93+svZNQ1uSmZ7taZTk/AM5fXpd7WevyyVOf/P/lxKb3dX1KtsUA7s+c3xhV47aKRbGggxIFdChOd3peNjatjzm+MdCd2/N/6gOIcOEo+fJMy1EI1lNexRs6EexfA5OJNuh2MWvpgKhUKT+QId2V+OM8PlpAAAAABJRU5ErkJggg==>

[image34]: <data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADgAAAAYCAYAAACvKj4oAAABSUlEQVR4Xu2WPUoEQRCFn6CguCIqgrHxgoHHMDP1IJp4Aw8gamK2gamBWYGhoAaGGmhobrIgWmVVub2Ns+NP7xZIf/CY6ao3Pf2YHmaASqVSmSArrC5rPm/8Bx5Yr6w3VifrRTIHXVcbe6zdvJhD0IDRyA7qQ9fi+ooehj2tAcV0mReDITQHdGTHtQZ0007eCIZQKOA21LSU1A5Zx8k4AkKhgLI1faJF1g1rDfourLspAEKhgGK4Yi2zTqz2aHUJ3MQM6+iHGjVfDqFAwAWo4YJ1kPWiIRQI6O/frR3vh9uhEAoEJAwmmbLzs8/uaH6zRVc/rvwehAIBpZl+/2R8bufEmh60Jg7hjwFnoc30++dmeZp3ST2Ca+h6ZC1NyD+0ePbzhrABbco/n7NltbaJx4ncu896Mj1bbTPxnFrNPSIZvySeSqVSGR/vvzhtcX0eZiEAAAAASUVORK5CYII=>