#include <iostream>
#include <vector>
using namespace std;

vector<int> a, b;
vector<int> ans;

void rotate(int i) {
  int tmp = a[i];
  a[i] = b[i];
  b[i] = a[i + 1];
  a[i + 1] = tmp;
  ans.push_back(i + 1);
}

int findA(int x) {
  for (int i = 0; i < (int) a.size(); ++i) if (a[i] == x) return i;
  return -1;
}

int findB(int x) {
  for (int i = 0; i < (int) b.size(); ++i) if (b[i] == x) return i;
  return -1;
}

void solve() {
  int n; cin >> n;
  a.clear(), b.clear();
  a.resize(n), b.resize(n - 1);
  for (int i = 0; i < n; ++i) cin >> a[i];
  for (int i = 0; i < n - 1; ++i) cin >> b[i];
  for (int i = 0; i < n; ++i) --a[i];
  for (int i = 0; i < n - 1; ++i) --b[i];
  ans.clear();
  for (int i = n - 1; i > 1; --i) {
    int top = i, bottom = i + n - 1;
    int ta = findA(top), tb = findB(top);
    int ba = findA(bottom), bb = findB(bottom);
    if (ta >= 0 && ba >= 0) {
      if (ta == i) {
        if (ba == i - 1) rotate(ba - 1);
        rotate(ta - 1);
      }
    } else if (ta >= 0) {
      if (ta == i && bb == i - 1) continue;
      if (ta == i) rotate(ta - 1);
      else if (ta == i - 1 && bb == i - 1) rotate(ta - 1);
    } else if (ba >= 0) {
      if (ba == i && tb == i - 1) {
        rotate(tb);
        rotate(tb - 1);
      }
    } else {
      if (tb == i - 1) rotate(tb);
    }
    ba = findA(bottom), bb = findB(bottom);
    if (bb >= 0) {
      rotate(bb);
      ba = bb;
    }
    while (ba < i) {
      rotate(ba);
      ++ba;
    }
    ta = findA(top), tb = findB(top);
    if (tb >= 0) {
      rotate(tb);
      ta = tb;
    }
    while (ta < i) {
      rotate(ta);
      ++ta;
    }
  }
  while (a[0]) rotate(0);
  if (a[1] != 1) {
    cout << "NO\n";
    return;
  }
  cout << "YES\n" << (int) ans.size() << '\n';
  for (int num : ans) cout << num << ' ';
  cout << '\n';
}

int main() {
  int t; cin >> t;
  for (int i = 0; i < t; ++i) solve();
  return 0;
}
