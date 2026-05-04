"""
Unit tests for the Knowledge Store.
"""

import pytest
import os
from core.knowledge_base.knowledge_store import KnowledgeStore

@pytest.fixture
def temp_store():
    db_path = "logs/test_knowledge.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    store = KnowledgeStore(db_path=db_path)
    yield store
    if os.path.exists(db_path):
        os.remove(db_path)

def test_add_and_get_fact(temp_store):
    temp_store.add_fact("chall_1", "agent_1", "credential", {"user": "admin", "pass": "secret"})
    
    facts = temp_store.get_facts(challenge_id="chall_1")
    assert len(facts) == 1
    assert facts[0]["key"] == "credential"
    assert facts[0]["value"]["user"] == "admin"

def test_find_latest_fact(temp_store):
    temp_store.add_fact("chall_1", "agent_1", "status", "starting")
    temp_store.add_fact("chall_1", "agent_1", "status", "running")
    
    latest = temp_store.find_latest_fact("chall_1", "status")
    assert latest["value"] == "running"

def test_filtering(temp_store):
    temp_store.add_fact("chall_1", "agent_1", "key1", "val1")
    temp_store.add_fact("chall_2", "agent_1", "key1", "val2")
    
    facts_1 = temp_store.get_facts(challenge_id="chall_1")
    assert len(facts_1) == 1
    assert facts_1[0]["value"] == "val1"
    
    facts_all_key1 = temp_store.get_facts(key="key1")
    assert len(facts_all_key1) == 2
