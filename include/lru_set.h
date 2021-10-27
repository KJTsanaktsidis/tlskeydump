#ifndef __lru_set_h
#define __lru_set_h

#include <cstdint>
#include <map>
#include <unordered_map>
#include <vector>

namespace std {
template <> struct hash<std::vector<uint8_t>> {
  std::size_t operator()(const std::vector<uint8_t> &k) const {
    using std::hash;
    using std::size_t;
    using std::uint8_t;

    size_t res = 17;
    for (auto e : k) {
      res = res * 31 + hash<uint8_t>()(e);
    }
    return res;
  }
};
} // namespace std

template <typename T> class LRUSet {
public:
  LRUSet(int capacity) : _capacity(capacity) {}
  bool contains(const T &el) { return _set.contains(el); }
  void insert(const T &el) {
    int io = _insertion_counter++;
    if (_set.contains(el)) {
      int old_io = _set[el];
      _set[el] = io;
      _insertion_orders.erase(old_io);
    } else {
      _set[el] = io;
    }
    _insertion_orders[io] = el;
  }
  bool contains_with_insert(const T &el) {
    bool had = contains(el);
    insert(el);
    return had;
  }

private:
  int _capacity;
  int _insertion_counter = 0;
  std::unordered_map<T, int> _set;
  std::map<int, T> _insertion_orders;
};

#endif
