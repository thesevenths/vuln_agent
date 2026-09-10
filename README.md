1、设置常见的sink函数，比如executeQuery、exec等
2、使用joern提取这些sink函数完整的调用链，然后BFS遍历这些调用链
3、每种cwe的特征、判定条件都不同，需要实现预制写入skill，防止LLM产生幻觉
4、完整的sink-source调用链 + skill拼接输入LLM，让其判断该调用链是否有漏洞