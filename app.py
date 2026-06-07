"""
MITRE ATT&CK 知识图谱问答系统 - Streamlit Web UI
"""

import os
import sys

import streamlit as st

# 将项目根目录加入 Python 路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from utils.qa_engine import QAEngine


def init_engine():
    """初始化问答引擎（缓存）"""
    if "engine" not in st.session_state:
        password = os.getenv("NEO4J_PASSWORD", "")
        try:
            st.session_state.engine = QAEngine(neo4j_password=password)
        except Exception as e:
            st.error(f"引擎初始化失败: {e}")
            st.session_state.engine = None
    return st.session_state.engine


def main():
    st.set_page_config(
        page_title="MITRE ATT&CK 问答系统",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("🛡️ MITRE ATT&CK 知识图谱问答系统")
    st.caption("基于 MITRE ATT&CK 框架的网络安全威胁智能问答")

    # 侧边栏
    with st.sidebar:
        st.header("⚙️ 设置")

        # Neo4j 密码输入
        neo4j_password = st.text_input(
            "Neo4j 密码",
            value=os.getenv("NEO4J_PASSWORD", ""),
            type="password",
        )

        if st.button("🔄 重新初始化引擎"):
            if "engine" in st.session_state:
                if st.session_state.engine:
                    st.session_state.engine.close()
                del st.session_state.engine
            st.rerun()

        st.divider()

        # 引擎统计
        engine = init_engine()
        if engine:
            stats = engine.get_stats()
            st.metric("技术", stats.get("techniques", 0))
            st.metric("战术", stats.get("tactics", 0))
            st.metric("威胁组织", stats.get("groups", 0))
            st.metric("恶意软件", stats.get("malwares", 0))
            st.metric("工具", stats.get("tools", 0))
            st.metric("缓解措施", stats.get("mitigations", 0))
            st.metric("攻击活动", stats.get("campaigns", 0))
            total_rels = sum(stats.get(k, 0) for k in
                            ["belongs_to", "uses", "mitigates", "subtechnique_of", "attributed_to"])
            st.metric("关系总数", total_rels)

        st.divider()

        if st.button("🗑️ 清空对话历史"):
            if engine:
                engine.clear_history()
            st.session_state.messages = []
            st.rerun()

    # 初始化消息历史
    if "messages" not in st.session_state:
        st.session_state.messages = [
            {
                "role": "assistant",
                "content": (
                    "👋 您好！我是 **NTAD 智能攻防问答系统**，基于 MITRE ATT&CK 知识图谱构建。\n\n"
                    "我可以帮您：\n"
                    "- 查询攻击技术详情（如：T1059 是什么？）\n"
                    "- 了解战术阶段下的技术（如：初始访问有哪些技术？）\n"
                    "- 获取防御建议（如：怎么防御 PowerShell 攻击？）\n"
                    "- 追踪威胁组织活动（如：APT28 用了哪些技术？）\n"
                    "- 分析恶意软件和工具（如：Cobalt Strike 利用了什么技术？）\n\n"
                    "请输入您的问题，或输入「帮我查一下」获取引导。"
                ),
            }
        ]

    # 显示消息历史
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])

    # 用户输入
    if prompt := st.chat_input("请输入您的问题..."):
        # 显示用户消息
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)

        # 流式生成回答
        with st.chat_message("assistant"):
            engine = init_engine()
            if engine:
                try:
                    response = st.write_stream(engine.ask_stream(prompt))
                    st.session_state.messages.append(
                        {"role": "assistant", "content": response}
                    )
                except Exception as e:
                    error_msg = f"❌ 处理出错: {e}"
                    st.error(error_msg)
                    st.session_state.messages.append(
                        {"role": "assistant", "content": error_msg}
                    )
            else:
                st.error("引擎未初始化，请检查配置")


if __name__ == "__main__":
    main()
