"""
SQLite 管理模块
将 Neo4j 中的实体名称同步到 SQLite 本地数据库
"""

import os
import sqlite3
from neo4j import GraphDatabase

# 路径配置
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(BASE_DIR, "data")
DB_FILE = os.path.join(DB_DIR, "entities.db")

# Neo4j 默认配置
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"


def _init_db(conn: sqlite3.Connection):
    """初始化 SQLite 表结构"""
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS techniques (
            attack_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            url TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tactics (
            attack_id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            shortname TEXT,
            url TEXT
        )
    """)
    conn.commit()


def sync_from_neo4j(password: str):
    """
    从 Neo4j 读取所有技术/战术名称，写入 SQLite
    """
    os.makedirs(DB_DIR, exist_ok=True)

    # 连接 Neo4j
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, password))
        driver.verify_connectivity()
        print(f"✅ 已连接 Neo4j: {NEO4J_URI}")
    except Exception as e:
        raise ConnectionError(f"Neo4j 连接失败: {e}")

    # 读取数据
    with driver.session() as session:
        techniques = session.run(
            "MATCH (t:Technique) RETURN t.attack_id AS id, t.name AS name, t.url AS url"
        ).data()
        tactics = session.run(
            "MATCH (t:Tactic) RETURN t.attack_id AS id, t.name AS name, t.shortname AS shortname, t.url AS url"
        ).data()
    driver.close()

    # 写入 SQLite
    conn = sqlite3.connect(DB_FILE)
    _init_db(conn)
    cursor = conn.cursor()

    # 清空旧数据
    cursor.execute("DELETE FROM techniques")
    cursor.execute("DELETE FROM tactics")

    # 插入技术
    cursor.executemany(
        "INSERT INTO techniques (attack_id, name, url) VALUES (:id, :name, :url)",
        techniques
    )
    print(f"已同步 {len(techniques)} 个技术到 SQLite")

    # 插入战术
    cursor.executemany(
        "INSERT INTO tactics (attack_id, name, shortname, url) VALUES (:id, :name, :shortname, :url)",
        tactics
    )
    print(f"已同步 {len(tactics)} 个战术到 SQLite")

    conn.commit()
    conn.close()

    print(f"\n✅ SQLite 数据库: {DB_FILE}")


def query_techniques(keyword: str = "") -> list:
    """在 SQLite 中搜索技术"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if keyword:
        cursor.execute(
            "SELECT * FROM techniques WHERE name LIKE ? OR attack_id LIKE ?",
            (f"%{keyword}%", f"%{keyword}%")
        )
    else:
        cursor.execute("SELECT * FROM techniques")

    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return results


def query_tactics(keyword: str = "") -> list:
    """在 SQLite 中搜索战术"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    if keyword:
        cursor.execute(
            "SELECT * FROM tactics WHERE name LIKE ? OR attack_id LIKE ?",
            (f"%{keyword}%", f"%{keyword}%")
        )
    else:
        cursor.execute("SELECT * FROM tactics")

    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return results


def main():
    import argparse

    parser = argparse.ArgumentParser(description="SQLite 实体管理工具")
    parser.add_argument("action", choices=["sync", "search-tech", "search-tac"],
                        help="sync=从Neo4j同步, search-tech=搜索技术, search-tac=搜索战术")
    parser.add_argument("--password", default="", help="Neo4j 密码")
    parser.add_argument("--keyword", default="", help="搜索关键词")
    args = parser.parse_args()

    if args.action == "sync":
        password = args.password or os.environ.get("NEO4J_PASSWORD", "")
        sync_from_neo4j(password)
    elif args.action == "search-tech":
        results = query_techniques(args.keyword)
        for r in results:
            print(f"  {r['attack_id']} - {r['name']}")
        print(f"共 {len(results)} 条")
    elif args.action == "search-tac":
        results = query_tactics(args.keyword)
        for r in results:
            print(f"  {r['attack_id']} - {r['name']}")
        print(f"共 {len(results)} 条")


if __name__ == "__main__":
    main()
