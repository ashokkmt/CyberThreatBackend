import json

class TrieNode:
    def __init__(self):
        self.children = {}
        self.end_of_word = False

class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, pattern: str):
        node = self.root
        for char in pattern.lower():
            node = node.children.setdefault(char, TrieNode())
        node.end_of_word = True

    def search(self, text: str) -> (bool, str | None): # type: ignore
        text = text.lower()
        for i in range(len(text)):
            node = self.root
            j = i
            matched = ""
            while j < len(text) and text[j] in node.children:
                node = node.children[text[j]]
                matched += text[j]
                if node.end_of_word:
                    return True, matched
                j += 1
        return False, None


# Initialize Trie with patterns from JSON
def load_trie_from_file(filepath: str) -> Trie:
    trie = Trie()
    with open(filepath, "r", encoding="utf-8") as f:
        signatures = json.load(f)

    for item in signatures:
        pattern = item["txt"].strip().lower()
        trie.insert(pattern)

    return trie
