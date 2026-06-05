"""
MITRE ATT&CK 知识图谱构建模块
将 Enterprise ATT&CK 数据导入 Neo4j 图数据库
"""

import json
import os
import sys
from typing import Optional

from neo4j import GraphDatabase

# 默认连接配置
DEFAULT_URI = "bolt://localhost:7687"
DEFAULT_USER = "neo4j"

# 数据文件路径
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
STIX_FILE = os.path.join(DATA_DIR, "enterprise-attack.json")


def _extract_external_id(obj: dict) -> Optional[str]:
    """从对象的 external_references 中提取 MITRE ID（如 T1059、TA0001）"""
    refs = obj.get("external_references", [])
    if refs and refs[0].get("source_name") == "mitre-attack":
        return refs[0].get("external_id")
    return None


def _extract_url(obj: dict) -> Optional[str]:
    """从对象的 external_references 中提取 MITRE URL"""
    refs = obj.get("external_references", [])
    if refs and refs[0].get("source_name") == "mitre-attack":
        return refs[0].get("url")
    return None


def _is_revoked_or_deprecated(obj: dict) -> bool:
    """检查对象是否已撤销或废弃"""
    return obj.get("revoked", False) or obj.get("x_mitre_deprecated", False)


class GraphBuilder:
    """Neo4j 图数据库构建器"""

    def __init__(self, uri: str = DEFAULT_URI, user: str = DEFAULT_USER, password: str = ""):
        """
        初始化连接

        Args:
            uri: Neo4j 连接地址
            user: 用户名
            password: 密码（不要硬编码，从参数或环境变量传入）
        """
        if not password:
            password = os.environ.get("NEO4J_PASSWORD", "")
        if not password:
            raise ValueError("请提供 Neo4j 密码（参数或 NEO4J_PASSWORD 环境变量）")

        try:
            self.driver = GraphDatabase.driver(uri, auth=(user, password))
            self.driver.verify_connectivity()
            print(f"✅ 已连接 Neo4j: {uri}")
        except Exception as e:
            raise ConnectionError(f"Neo4j 连接失败: {e}")

    def close(self):
        """关闭连接"""
        if hasattr(self, "driver"):
            self.driver.close()

    def _create_constraints(self):
        """为节点类型创建唯一约束（避免重复）"""
        constraints = [
            ("Technique", "attack_id"),
            ("Tactic", "attack_id"),
        ]
        with self.driver.session() as session:
            for label, prop in constraints:
                query = f"CREATE CONSTRAINT IF NOT EXISTS FOR (n:{label}) REQUIRE n.{prop} IS UNIQUE"
                session.run(query)
                print(f"  创建约束: {label}.{prop}")

    def _parse_attack_data(self) -> dict:
        """
        解析 MITRE ATT&CK STIX 数据

        直接解析 enterprise-attack.json，过滤已撤销/废弃的数据。
        返回 {"techniques": [...], "tactics": [...]}
        """
        if not os.path.exists(STIX_FILE):
            raise FileNotFoundError(f"数据文件不存在: {STIX_FILE}\n请先运行 utils/data_fetcher.py 下载数据")

        print("正在解析 MITRE ATT&CK 数据...")
        with open(STIX_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        techniques = []
        tactics = []

        for obj in data.get("objects", []):
            if _is_revoked_or_deprecated(obj):
                continue
            obj_type = obj.get("type", "")
            if obj_type == "attack-pattern":
                techniques.append(obj)
            elif obj_type == "x-mitre-tactic":
                tactics.append(obj)

        print(f"  技术数量: {len(techniques)}")
        print(f"  战术数量: {len(tactics)}")

        return {"techniques": techniques, "tactics": tactics}

    def _import_tactics(self, tactics: list) -> int:
        """批量导入战术节点"""
        batch = []
        for t in tactics:
            attack_id = _extract_external_id(t)
            if not attack_id:
                continue
            batch.append({
                "attack_id": attack_id,
                "name": t.get("name", ""),
                "description": t.get("description", "")[:500],
                "url": _extract_url(t) or "",
                "stix_id": t.get("id", ""),
                "shortname": t.get("x_mitre_shortname", ""),
            })

        query = """
        UNWIND $batch AS item
        MERGE (t:Tactic {attack_id: item.attack_id})
        SET t.name = item.name,
            t.description = item.description,
            t.url = item.url,
            t.stix_id = item.stix_id,
            t.shortname = item.shortname
        """

        with self.driver.session() as session:
            session.run(query, batch=batch)

        return len(batch)

    def _import_techniques(self, techniques: list) -> int:
        """批量导入技术节点"""
        batch = []
        for t in techniques:
            attack_id = _extract_external_id(t)
            if not attack_id:
                continue
            batch.append({
                "attack_id": attack_id,
                "name": t.get("name", ""),
                "description": t.get("description", "")[:500],
                "url": _extract_url(t) or "",
                "stix_id": t.get("id", ""),
                "platforms": t.get("x_mitre_platforms", []),
            })

        query = """
        UNWIND $batch AS item
        MERGE (t:Technique {attack_id: item.attack_id})
        SET t.name = item.name,
            t.description = item.description,
            t.url = item.url,
            t.stix_id = item.stix_id,
            t.platforms = item.platforms
        """

        with self.driver.session() as session:
            session.run(query, batch=batch)

        return len(batch)

    def _import_technique_tactic_relations(self, techniques: list) -> int:
        """导入技术-战术关系：(Technique)-[:BELONGS_TO]->(Tactic)"""
        relations = []
        for t in techniques:
            tech_id = _extract_external_id(t)
            if not tech_id:
                continue
            for phase in t.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactic_shortname = phase.get("phase_name", "")
                    relations.append({
                        "tech_id": tech_id,
                        "tactic_shortname": tactic_shortname,
                    })

        query = """
        UNWIND $batch AS item
        MATCH (tech:Technique {attack_id: item.tech_id})
        MATCH (tac:Tactic {shortname: item.tactic_shortname})
        MERGE (tech)-[:BELONGS_TO]->(tac)
        """

        with self.driver.session() as session:
            session.run(query, batch=relations)

        return len(relations)

    def build(self):
        """
        主构建流程：解析数据 → 创建约束 → 批量导入节点 → 建立关系
        """
        print("=" * 50)
        print("开始构建 MITRE ATT&CK 知识图谱")
        print("=" * 50)

        # 1. 解析数据
        data = self._parse_attack_data()

        # 2. 创建约束
        print("\n创建唯一约束...")
        self._create_constraints()

        # 3. 导入战术节点
        print("\n导入战术节点...")
        total_tactics = len(data["tactics"])
        imported = self._import_tactics(data["tactics"])
        print(f"已导入 {imported}/{total_tactics} 个战术")

        # 4. 导入技术节点
        print("\n导入技术节点...")
        total_techniques = len(data["techniques"])
        imported = self._import_techniques(data["techniques"])
        print(f"已导入 {imported}/{total_techniques} 个技术")

        # 5. 建立关系
        print("\n建立技术-战术关系...")
        rel_count = self._import_technique_tactic_relations(data["techniques"])
        print(f"已创建 {rel_count} 条关系")

        print("\n" + "=" * 50)
        print("✅ 知识图谱构建完成！")
        print("=" * 50)


def main():
    """命令行入口"""
    import argparse

    parser = argparse.ArgumentParser(description="MITRE ATT&CK 知识图谱构建工具")
    parser.add_argument("--uri", default=DEFAULT_URI, help="Neo4j 连接地址 (默认: bolt://localhost:7687)")
    parser.add_argument("--user", default=DEFAULT_USER, help="Neo4j 用户名 (默认: neo4j)")
    parser.add_argument("--password", default="", help="Neo4j 密码（或设置 NEO4J_PASSWORD 环境变量）")
    args = parser.parse_args()

    # 优先使用参数，其次环境变量
    password = args.password or os.environ.get("NEO4J_PASSWORD", "")

    builder = None
    try:
        builder = GraphBuilder(uri=args.uri, user=args.user, password=password)
        builder.build()
    except (ConnectionError, FileNotFoundError, ValueError) as e:
        print(f"❌ 错误: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        if builder:
            builder.close()


if __name__ == "__main__":
    main()
