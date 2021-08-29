#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <ranges>
#include <set>
#include <sstream>
#include <vector>

using buffer = std::vector<std::uint8_t>;

auto toBase64(const buffer& hex) {
  // Need to align with 3 bytes (since 3 bytes = 4 base64 digits)
  // const auto align = hex.size() % 3;

  buffer out;
  out.reserve(4 * (hex.size() / 3));

  for (std::size_t i = 0; i < hex.size(); i += 3) {
    const uint32_t val = [&] {
      // A bit ugly, could check it only in the end
      if (i + 1 > hex.size()) {
        return hex[i] << 16;
      } else if (i > hex.size()) {
        return (hex[i] << 16) + (hex[i + 1] << 8);
      }
      return (hex[i] << 16) + (hex[i + 1] << 8) + (hex[i + 2] << 0);
    }();
    out.push_back((val & 0b111111000000000000000000) >> 18);
    out.push_back((val & 0b000000111111000000000000) >> 12);
    out.push_back((val & 0b000000000000111111000000) >> 6);
    out.push_back((val & 0b000000000000000000111111) >> 0);
  }

  return out;
}

auto xorBuffers(const buffer& b1, const buffer& b2) {
  if (b1.size() != b2.size()) {
    throw std::invalid_argument("Buffers must be of the same size");
  }

  buffer out;
  out.reserve(b1.size());

  for (std::size_t i = 0; i < b1.size(); i++) {
    out.push_back(b1[i] xor b2[i]);
  }
  return out;
}

auto xorKey(const buffer& b1, const buffer& key) {
  if (key.empty()) {
    throw std::invalid_argument("Empty key");
  }
  buffer b2;
  b2.reserve(b1.size());
  for (std::size_t i = 0, j = 0; i < b1.size(); i++) {
    b2.push_back(key[j]);
    j++;
    if (j == key.size()) {
      j = 0;
    }
  }
  return xorBuffers(b1, b2);
}

auto charFrequenzy(const buffer& bytes) {
  // Based on wikipedia ( with a-z in one order, then spaces punctuation and
  // digits added separately)
  static const std::map<char, unsigned> english{
      {'e', 0},  {'t', 1},  {'a', 2},  {'o', 3},  {'i', 4},  {'n', 5},
      {'s', 6},  {'h', 7},  {'r', 8},  {'d', 9},  {'l', 10}, {'c', 11},
      {'u', 12}, {'m', 13}, {'w', 14}, {'f', 15}, {'g', 16}, {'y', 17},
      {'p', 18}, {'b', 19}, {'v', 20}, {'k', 21}, {'j', 22}, {'x', 23},
      {'q', 24}, {'z', 25}, {'E', 0},  {'T', 1},  {'A', 2},  {'O', 3},
      {'I', 4},  {'N', 5},  {'S', 6},  {'H', 7},  {'R', 8},  {'D', 9},
      {'L', 10}, {'C', 11}, {'U', 12}, {'M', 13}, {'W', 14}, {'F', 15},
      {'G', 16}, {'Y', 17}, {'P', 18}, {'B', 19}, {'V', 20}, {'K', 21},
      {'J', 22}, {'X', 23}, {'Q', 24}, {'Z', 25}, {' ', 0},  {'.', 3},
      {'0', 3},  {'1', 3},  {'2', 3},  {'3', 3},  {'4', 3},  {'5', 3},
      {'6', 3},  {'7', 3},  {'8', 3},  {'9', 3}};

  long score = 0;
  for (auto byte : bytes) {
    score += english.contains(byte) ? english.at(byte) : 26;
  }
  // Does this work well for large texts?
  return static_cast<double>(score) / bytes.size();
}

auto bytesToHex(const buffer& bytes) {
  std::stringstream ss;
  for (uint8_t byte : bytes) {
    // Important to cast (uint8_t is treated as a char)
    ss << std::hex << static_cast<uint32_t>(byte);
  }
  return ss.str();
}

auto bytesToStr(const buffer& bytes) {
  std::stringstream ss;
  for (uint8_t byte : bytes) {
    ss << byte;
  }
  return ss.str();
}

using decrypt = std::tuple<double, unsigned char, std::string>;

auto tryKeys(const buffer& bytes, bool printTop = false) {
  std::vector<decrypt> scores;
  for (unsigned char c = 0; c < 255; c++) {
    const auto buf = xorKey(bytes, {c});
    scores.push_back({charFrequenzy(buf), c, bytesToStr(buf)});
  }
  std::ranges::sort(scores);
  if (printTop) {
    // Print top 10 candidates
    for (unsigned i = 0; i < 10; i++) {
      const auto& [f, c, s] = scores[i];
      std::cout << f << " " << c << " " << s << "\n";
    }
  }
  return scores[0];
}

auto hexStringToBytes(const std::string& str) {
  if (str.size() % 2 != 0) {
    throw std::invalid_argument("Str length must be divisible by 2");
  }
  buffer out;
  out.reserve(str.size() / 2);
  for (std::size_t i = 0; i < str.size(); i += 2) {
    out.push_back(std::stoi(str.substr(i, 2), nullptr, 16));
  }
  return out;
}

auto base64ToStr(const buffer& bytes) {
  std::stringstream ss;
  for (uint8_t byte : bytes) {
    if (byte <= 25)
      ss << static_cast<char>('A' + byte);
    else if (byte <= 51)
      ss << static_cast<char>('a' + byte - 26);
    else if (byte <= 61)
      ss << static_cast<char>('0' + byte - 52);
    else if (byte == 62)
      ss << '+';
    else
      ss << '/';
  }
  return ss.str();
}

auto tryFromFile(const std::filesystem::path& path) {
  std::ifstream inf{path};
  if (!inf) {
    throw std::invalid_argument("Could not open file");
  }
  std::vector<decrypt> decrypts;
  std::string line;
  while (std::getline(inf, line)) {
    const auto decrypt = tryKeys(hexStringToBytes(line));
    decrypts.push_back(decrypt);
  }
  std::ranges::sort(decrypts);
  return decrypts.front();
}

int main() {
  // 1
  {
    const auto bytes = hexStringToBytes(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f"
        "6e"
        "6f7573206d757368726f6f6d");
    const auto base64 = toBase64(bytes);
    const auto base64str = base64ToStr(base64);
    std::cout << base64str << "\n";
    const auto expected =
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    if (expected != base64str) {
      throw std::runtime_error("Invalid challenge 1");
    }
  }

  // 2
  {
    const auto bytes2_1 =
        hexStringToBytes("1c0111001f010100061a024b53535009181c");
    const auto bytes2_2 =
        hexStringToBytes("686974207468652062756c6c277320657965");
    const auto xored = xorBuffers(bytes2_1, bytes2_2);
    const auto xoredHex = bytesToHex(xored);
    std::cout << xoredHex << "\n";
    const auto expected2 = "746865206b696420646f6e277420706c6179";
    if (xoredHex != expected2) {
      throw std::runtime_error("Invalid challenge 2");
    }
  }
  // 3
  {
    const auto bytes3 = hexStringToBytes(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    const auto s = tryKeys(bytes3);
    std::cout << std::get<2>(s) << "\n";
    if (std::get<1>(s) != 'X' ||
        std::get<2>(s) != "Cooking MC's like a pound of bacon") {
      throw std::runtime_error("Invalid challenge 3");
    }
  }

  // 4
  {
    const auto& [f, c, s] = tryFromFile("4.txt");
    std::cout << f << " " << c << " " << s << "\n";
    if (s != "Now that the party is jumping\n") {
      throw std::runtime_error("Invalid challenge 4");
    }
  }

  return 0;
}