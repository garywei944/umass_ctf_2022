#include <iostream>
#include <numeric>
#include <ranges>
#include <string>
#include <vector>
int main() {
  using namespace std::literals;
  const std::vector<std::tuple<long, std::string>> v{
      // {0,
      //  "V"s
      //  "T"s
      //  "T"s
      //  "7"s
      //  "1"s
      //  "T"s
      //  "T"s
      //  "N"s
      //  "R"s
      //  "0"s},
      // {1,
      //  "R"s
      //  "Z"s
      //  "W"s
      //  "N"s
      //  "Z"s
      //  "7"s
      //  "M"s
      //  "U"s
      //  "U"s
      //  "Y"s},
      {2,
       "U"s
       "S"s
       "N"s
       "T"s
       "_"s
       "_"s
       "F"s
       "1"s
       "T"s
       "?"s},
      {3,
       "Z"s
       "X"s
       "C"s
       "X"s
       "X"s
       "Z"s
       "X"s
       "C"s
       "9"s
       "A"s},
      {4,
       "M"s
       "{"s
       "G"s
       "5"s
       "C"s
       "1"s
       "U"s
       "S"s
       "_"s
       "}"s},
      {5,
       "D"s
       "S"s
       "D"s
       "5"s
       "A"s
       "D"s
       "5"s
       "A"s
       "D"s
       "X"s},
      {6,
       "A"s
       "C"s
       "R"s
       "!"s
       "+"s
       "5"s
       "N"s
       "N"s
       "1"s
       " "s},
      {7,
       "3"s
       "8"s
       "2"s
       "1"s
       "3"s
       "X"s
       "3"s
       "3"s
       "0"s
       "X"s},
      {8,
       "S"s
       "0"s
       "4"s
       "_"s
       "+"s
       "_"s
       "_"s
       "'"s
       "T"s
       " "s},
      // {9,
      //  "X"s
      //  "B"s
      //  "1"s
      //  "X"s
      //  "V"s
      //  "X"s
      //  "Z"s
      //  "F"s
      //  ","s
      //  ">"s},
      // {10,
      //  "B"s
      //  "1"s
      //  "X"s
      //  "V"s
      //  "X"s
      //  "Z"s
      //  " "s
      //  ","s
      //  ">"s
      //  "k"s},
      // {11,
      //  "B"s
      //  "e"s
      //  "N"s
      //  "g"s
      //  " "s
      //  "e"s
      //  "7"s
      //  "W"s
      //  "I"s
      //  "V"s},
      // {12,
      //  "N"s
      //  "8"s
      //  "0"s
      //  "M"s
      //  "Z"s
      //  "N"s
      //  "O"s
      //  "m"s
      //  "X"s
      //  "J"s},
      // {13,
      //  "3"s
      //  "y"s
      //  "F"s
      //  "5"s
      //  "8"s
      //  "q"s
      //  "<"s
      //  "0"s
      //  "P"s
      //  "U"s},
      // {14,
      //  "1"s
      //  "Z"s
      //  ":"s
      //  "4"s
      //  "V"s
      //  " "s
      //  "&"s
      //  "q"s
      //  "}"s
      //  "{"s},
      // {15,
      //  "U"s
      //  "D"s
      //  "s"s
      //  "{"s
      //  "D"s
      //  "B"s
      //  "_"s
      //  "C"s
      //  "D"s
      //  "i"s},
      // {16,
      //  "2"s
      //  "D"s
      //  "D"s
      //  "Y"s
      //  "b"s
      //  "k"s
      //  "R"s
      //  "7"s
      //  "H"s
      //  "i"s},
      // {17,
      //  "Y"s
      //  "5"s
      //  "P"s
      //  "M"s
      //  "Z"s
      //  "N"s
      //  "E"s
      //  "s"s
      //  "D"s
      //  "g"s},
      // {18,
      //  "K"s
      //  "o"s
      //  "N"s
      //  "w"s
      //  "p"s
      //  "3"s
      //  "X"s
      //  "l"s
      //  "b"s
      //  "X"s},
      // {19,
      //  "U"s
      //  "k"s
      //  "G"s
      //  "T"s
      //  "M"s
      //  "w"s
      //  "Z"s
      //  "L"s
      //  "M"s
      //  "y"s},
      // {20,
      //  "2"s
      //  "K"s
      //  "5"s
      //  "8"s
      //  "4"s
      //  "D"s
      //  "b"s
      //  "4"s
      //  "4"s
      //  "L"s},
  };
  auto s = v
           //  | std::views::reverse
           //  | std::views::drop(12)
           //  | std::views::reverse
           //  | std::views::drop(2)
           | std::views::filter([](auto k) {
               auto [v, s] = k;
               return v % 2 == 0;
               //  return v & 1;
             });
  auto z = std::get<1>(v[0]).size();  // z = 10
  // std::cout<<z<<std::endl;
  for (auto i = 0; i < z; ++i) {
    for (auto [z, k] : s) {
      std::cout << k[i];
    }
  }
  std::cout << std::endl;
}
