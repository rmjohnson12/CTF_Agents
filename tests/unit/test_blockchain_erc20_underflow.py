"""Unit tests for ERC20 underflow-purchase discovery (no chain/network).

Covers the "Token to Wonderland" pattern: a pre-0.8 token whose transfer
underflows, so an unaffordable priced item (whose ownership isSolved checks)
can be bought after inflating the balance. Detection is source-driven.
"""
from agents.specialists.blockchain.blockchain_agent import BlockchainAgent

_SHOP = """
pragma solidity ^0.7.0;
contract Shop {
    struct Item { string name; uint256 price; address owner; }
    Item[] public items;
    SilverCoin silverCoin;
    function buyItem(uint256 _index) public {
        Item memory _item = items[_index];
        require(_item.owner == address(this), "Item already sold");
        bool success = silverCoin.transferFrom(msg.sender, address(this), _item.price);
        require(success, "Payment failed!");
        items[_index].owner = msg.sender;
    }
    function viewItem(uint256 _index) public view returns (string memory, uint256, address) {
        return (items[_index].name, items[_index].price, items[_index].owner);
    }
}
"""

_SETUP = """
pragma solidity ^0.7.0;
contract Setup {
    Shop public immutable TARGET;
    function isSolved(address _player) public view returns (bool) {
        (,, address ownerOfKey) = TARGET.viewItem(2);
        return ownerOfKey == _player;
    }
}
"""


def test_discovers_wonderland_buy_and_index():
    plan = BlockchainAgent._discover_token_shop_purchase(_SHOP + "\n" + _SETUP)
    assert plan == {"buy_fn": "buyItem", "item_index": 2}


def test_pre_0_8_required_for_underflow():
    # Same shop on 0.8+ has checked arithmetic — the playbook must decline.
    modern = (_SHOP + _SETUP).replace("^0.7.0", "^0.8.19")
    assert BlockchainAgent._discover_token_shop_purchase(modern) is None


def test_non_shop_source_not_detected():
    src = """pragma solidity ^0.7.0;
    contract C { function ping(uint256 x) public { emit E(x); } }"""
    assert BlockchainAgent._discover_token_shop_purchase(src) is None


def test_index_optional_when_isolved_absent():
    plan = BlockchainAgent._discover_token_shop_purchase(_SHOP)
    assert plan is not None
    assert plan["buy_fn"] == "buyItem"
    assert plan["item_index"] is None
