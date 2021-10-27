#ifndef __comma_separated_opts_h
#define __comma_separated_opts_h

#include <boost/tokenizer.hpp>
#include <string>
#include <vector>

template <typename T, T (*TParser)(std::string)> struct CommaSeparatedOpts {
  std::vector<T> values;
  void add_tokens(const std::string &str) {
    boost::char_separator<char> sep(",");
    std::vector<std::string> str_values;
    boost::tokenizer<boost::char_separator<char>> tok(str, sep);
    std::copy(tok.begin(), tok.end(), std::back_inserter(str_values));
    for (auto &s : str_values) {
      values.push_back(TParser(s));
    }
  }
  friend std::istream &operator>>(std::istream &in, CommaSeparatedOpts<T, TParser> &ol) {
    std::string token;
    in >> token;
    ol.add_tokens(token);
    return in;
  }
  static std::vector<T> squash_values(std::vector<CommaSeparatedOpts<T, TParser>> list) {
    std::vector<T> res;
    for (auto &v : list) {
      std::copy(v.values.begin(), v.values.end(), std::back_inserter(res));
    }
    return res;
  }
};

#endif
