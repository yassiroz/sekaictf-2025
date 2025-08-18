#include <iostream>
#include <vector>
#include <set>
#include <map>
#include <climits>
#include <algorithm>
#include <assert.h>
using namespace std;

#define IS_SAME(f) ((f) & 1)
#define IS_ALT(f) ((f) & 2)

int GLOBAL_ID = 0;
const int MAX_N = 150000;
const int MAX_TN = MAX_N - 2;
const int MAX_LG = 18;

struct Node {

  int nd[3];

  Node() {}

  Node(int a, int b, int c) {
    nd[0] = a, nd[1] = b, nd[2] = c;
  }
};

struct State {
  
  int changes; // actually is changes - halfSum but i made this optimization

  int first; // first common element
  int firstCount; // number of first common elements
  int last; // last common element
  int lastCount; // number of last common elements

  int firstAltCount; // number of first alternating elements
  int lastAltCount; // number of last alternating elements

  int ns[4];
  int count;

  uint8_t flags;

  State() : changes(0), first(-1), firstCount(0), last(-1),
        lastCount(0), firstAltCount(0), lastAltCount(0), flags(3), count(0) {}
};

void reverse(State& state) {
  swap(state.first, state.last);
  swap(state.firstCount, state.lastCount);
  swap(state.firstAltCount, state.lastAltCount);
  swap(state.ns[0], state.ns[3]);
  swap(state.ns[1], state.ns[2]);
}

int tn;
short com[MAX_N];
Node nodes[MAX_TN];
vector<int> adj[MAX_TN];
map<pair<int, int>, int> m;
  
int ps[MAX_TN], depths[MAX_TN], minDepths[MAX_N], minDepthNodes[MAX_N];

int up[MAX_LG][MAX_TN];

State stateUp[MAX_LG][MAX_TN];

struct Tree {

  Tree(int n) {
    tn = n - 2;
    for (int i = 0; i < n; ++i) minDepths[i] = INT_MAX, com[i] = 0;
  }

  inline static int common(int a, int b, int c) {
    for (int i = 0; i < 3; ++i) ++com[nodes[a].nd[i]], ++com[nodes[b].nd[i]];
    for (int x : nodes[c].nd) if (com[x] == 2) {
      for (int i = 0; i < 3; ++i) --com[nodes[a].nd[i]], --com[nodes[b].nd[i]];
      return x;
    }
    assert(0);
    return -1;
  }

  inline void initialize() {
    nodes[0] = Node(0, 1, 2);
    GLOBAL_ID++;
    for (int i = 0; i < 3; ++i) m[{i, (i + 1) % 3}] = m[{(i + 1) % 3, i}] = 0;
  }

  inline void addFaceNode(int a, int b, int c) {
    int from = m[{a, b}];
    Node node = Node(a, b, c);
    int idn = GLOBAL_ID++;
    nodes[idn] = node;
    adj[from].push_back(idn), adj[idn].push_back(from);
    m[{a, c}] = m[{c, a}] = m[{b, c}] = m[{c, b}] = idn;
  }

  inline int getAnc(int v, int u) {
    for (int b = 0; b < MAX_LG; ++b) if ((1 << b) & u) v = up[b][v];
    return v;
  }

  inline void preBinaryJump() {
    for (int i = 0; i < tn; ++i) up[0][i] = ps[i];
    for (int i = 1; i < MAX_LG; ++i)
      for (int j = 0; j < tn; ++j)
        up[i][j] = up[i - 1][up[i - 1][j]];
  }

  void dps(int v, int p, int d) {
    ps[v] = p, depths[v] = d;
    for (int u : adj[v]) if (u != p) dps(u, v, d + 1);
  }

  inline void minDps() {
    for (int i = 0; i < tn; ++i)
      for (int v : nodes[i].nd)
        if (depths[i] < minDepths[v]) minDepths[v] = depths[i], minDepthNodes[v] = i;
  }

  inline pair<int, int> findFocusNodes(int s, int t) {
    int c1 = minDepthNodes[s], c2 = minDepthNodes[t];
    if (depths[c1] < depths[c2]) swap(c1, c2), swap(s, t);
    int test = getAnc(c1, depths[c1] - depths[c2]);
    if (test != c2) return {c1, c2};
    int cur = c1;
    for (int i = MAX_LG - 1; i >= 0; --i) {
      int cand = up[i][cur];
      if (depths[cand] < depths[c2]) continue;
      bool has = false;
      for (int v : nodes[cand].nd) if (v == t) has = true;
      if (!has) cur = cand;
    }
    cur = up[0][cur];
    return {c1, cur};
  }

  inline void addOn(State& a, int x) {
    if (x == a.last) {
      if (IS_SAME(a.flags)) ++a.firstCount;
      ++a.lastCount;
      if (IS_ALT(a.flags)) --a.firstAltCount;
      else {
        a.changes -= a.lastAltCount / 2; // would expect a.lastAltCount - 1 but we need to round up anyway so this works
      }
      a.lastAltCount = 0;
      a.flags &= 1;
    } else {
      ++a.changes;
      a.last = x;
      a.lastCount = 1;
      a.flags &= 2;
      if (IS_ALT(a.flags)) ++a.firstAltCount;
      ++a.lastAltCount;
    }
  }

  inline void addBef(State& a, int x) {
    if (x == a.first) {
      ++a.firstCount;
      if (IS_SAME(a.flags)) ++a.lastCount;
      if (IS_ALT(a.flags)) --a.lastAltCount;
      else {
        a.changes -= a.firstAltCount / 2; // would expect a.lastAltCount - 1 but we need to round up anyway so this works
      }
      a.firstAltCount = 0;
      a.flags &= 1;
    } else {
      ++a.changes;
      a.first = x;
      a.firstCount = 1;
      a.flags &= 2;
      if (IS_ALT(a.flags)) ++a.lastAltCount;
      ++a.firstAltCount;
    }
  }

  inline State combGeneral(State a, State b) {
    // cout << "hi!\n";
    addOn(a, common(a.ns[2], a.ns[3], b.ns[0]));
    addOn(a, common(a.ns[3], b.ns[0], b.ns[1]));
    // cout << a.changes << '\n';
    State state;
    if (a.last == b.first) {
      state.changes = a.changes + b.changes;
      if (!IS_ALT(a.flags)) {
        state.changes -= a.lastAltCount / 2; // would expect a.lastAltCount - 1 but we need to round up anyway so this works
      }
      if (!IS_ALT(b.flags)) {
        state.changes -= b.firstAltCount / 2; // would expect a.lastAltCount - 1 but we need to round up anyway so this works
      }
      state.first = a.first;
      state.firstCount = a.firstCount;
      if (IS_SAME(a.flags)) state.firstCount += b.firstCount;
      state.last = b.last;
      state.lastCount = b.lastCount;
      if (IS_SAME(b.flags)) state.lastCount += a.lastCount;
      state.flags = IS_SAME(a.flags) && IS_SAME(b.flags); 
      state.firstAltCount = a.firstAltCount;
      if (IS_ALT(a.flags)) --state.firstAltCount;
      state.lastAltCount = b.lastAltCount;
      if (IS_ALT(b.flags)) --state.lastAltCount;
      state.flags &= 1;
    } else {
      state.changes = a.changes + b.changes + 1;
      if (!IS_ALT(a.flags) && !IS_ALT(b.flags)) {
        state.changes -= (a.lastAltCount + b.firstAltCount + 1) / 2;
      }
      state.first = a.first;
      state.firstCount = a.firstCount;
      state.last = b.last;
      state.lastCount = b.lastCount;
      state.flags &= 2;
      state.firstAltCount = a.firstAltCount;
      if (IS_ALT(a.flags)) state.firstAltCount += b.firstAltCount;
      state.lastAltCount = b.lastAltCount;
      if (IS_ALT(b.flags)) state.lastAltCount += a.lastAltCount;
      state.flags = (IS_ALT(a.flags) && IS_ALT(b.flags)) << 1;
    }
    state.ns[0] = a.ns[0], state.ns[1] = a.ns[1], state.ns[2] = b.ns[2], state.ns[3] = b.ns[3];
    state.count = a.count + b.count;
    return state;
  }

  inline State comb(State a, State b) {
    if (a.count == 0) return b;
    if (b.count == 0) return a;
    if (a.count > 2 && b.count > 2) return combGeneral(a, b);
    if (a.count > 2 && b.count < 3) {
      addOn(a, common(a.ns[2], a.ns[3], b.ns[0]));
      a.ns[2] = a.ns[3], a.ns[3] = b.ns[0];
      if (a.count == 1) a.ns[1] = b.ns[0];
      if (b.count == 2) {
        addOn(a, common(a.ns[2], a.ns[3], b.ns[1]));
        a.ns[2] = a.ns[3], a.ns[3] = b.ns[1];
      }
      a.count += b.count;
      return a;
    }
    if (a.count < 3 && b.count > 2) {
      addBef(b, common(a.ns[3], b.ns[0], b.ns[1]));
      b.ns[1] = b.ns[0], b.ns[0] = a.ns[3];
      if (b.count == 1) b.ns[2] = a.ns[3];
      if (a.count == 2) {
        addBef(b, common(a.ns[2], b.ns[0], b.ns[1]));
        b.ns[1] = b.ns[0], b.ns[0] = a.ns[2];
      }
      b.count += a.count;
      return b;
    }
    vector<int> nds;
    nds.push_back(a.ns[0]);
    if (a.count == 2) nds.push_back(a.ns[1]);
    nds.push_back(b.ns[0]);
    if (b.count == 2) nds.push_back(b.ns[1]);
    State state;
    int c1 = 0;
    if (nds.size() > 2) c1 = common(nds[0], nds[1], nds[2]);
    if (nds.size() == 3) {
      state.changes = 0;
      state.first = state.last = c1;
      state.firstCount = state.lastCount = 1;
      state.firstAltCount = state.lastAltCount = 1;
      state.flags = 3;
    } else if (nds.size() == 4) {
      int c2 = common(nds[1], nds[2], nds[3]);
      state.changes = (c1 != c2);
      state.first = c1;
      state.last = c2;
      state.firstCount = state.lastCount = 1 + (c1 == c2);
      state.firstAltCount = state.lastAltCount = 2 * (c1 != c2);
      state.flags = (c1 == c2) ^ ((c1 != c2) << 1);
    }
    state.count = nds.size();
    state.ns[0] = nds[0];
    state.ns[3] = nds[state.count - 1];
    if (state.count > 1) {
      state.ns[1] = nds[1];
      state.ns[2] = nds[state.count - 2];
    }
    return state;
  }

  inline void initUseJump() {
    for (int i = 0; i < tn; ++i) {
      State state;
      state.changes = 0;
      state.flags = 3;
      state.count = 1;
      state.ns[0] = state.ns[3] = i;
      stateUp[0][i] = state;
    }
    for (int i = 1; i < MAX_LG; ++i) {
      for (int j = 0; j < tn; ++j) {
        int cur = j;
        int curUp = up[i - 1][j];
        stateUp[i][j] = comb(stateUp[i - 1][cur], stateUp[i - 1][curUp]);
      }
    }
  }

  inline State calcPathUp(int s, int t) { // t is ancestor of s
    State cur = stateUp[0][s];
    s = up[0][s];
    for (int i = MAX_LG - 1; i >= 0; --i) {
      if (depths[s] < depths[t]) return cur;
      if (depths[up[i][s]] + 1 >= depths[t] && depths[s] >= (1 << i)) {
        cur = comb(cur, stateUp[i][s]);
        s = up[i][s];
      }
    }
    if (depths[s] == depths[t]) cur = comb(cur, stateUp[0][s]);
    return cur;
  }

  inline int minDist(int s, int t) {
    if (depths[s] < depths[t]) swap(s, t);
    int ss = getAnc(s, depths[s] - depths[t]), tt = t;
    for (int i = MAX_LG - 1; i >= 0; --i) {
      if (up[i][ss] != up[i][tt]) {
        ss = up[i][ss];
        tt = up[i][tt];
      }
    }
    State state;
    if (ss == tt) {
      // t was ancestor of s already:
      state = calcPathUp(s, t);
      if (state.count <= 3) return 0;
      if (IS_ALT(state.flags)) state.changes -= (state.firstAltCount - 1) / 2;
      else state.changes -= state.firstAltCount / 2 + state.lastAltCount / 2;
      return state.changes;
    }
    int par = up[0][ss];
    State state1 = calcPathUp(s, ss);
    State state2 = calcPathUp(t, tt);
    reverse(state2);
    int last = state1.ns[3];
    int first = state2.ns[0];
    int same = 0;
    for (int x : nodes[last].nd) for (int y : nodes[first].nd) if (x == y) ++same;
    if (same == 1) state1 = comb(state1, stateUp[0][par]);
    state = comb(state1, state2);
    if (IS_ALT(state.flags)) state.changes -= (state.firstAltCount - 1) / 2;
    else state.changes -= state.firstAltCount / 2 + state.lastAltCount / 2;
    return state.changes;
  }
};

int main() {
  ios_base::sync_with_stdio(false); cin.tie(nullptr);
  int n; cin >> n;
  set<pair<int, int>> edges;
  Tree tree = Tree(n);
  tree.initialize();
  for (int i = 0; i < 3; ++i) edges.insert({i, (i + 1) % 3}), edges.insert({(i + 1) % 3, i});
  for (int i = 3; i < n; ++i) {
    int u, v; cin >> u >> v; --u, --v;
    // add edges (u, i) and (v, i)
    tree.addFaceNode(u, v, i);
    edges.insert({u, i}), edges.insert({i, u});
    edges.insert({v, i}), edges.insert({i, v});
  }
  tree.dps(0, 0, 0);
  tree.preBinaryJump();
  tree.minDps();
  tree.initUseJump();
  int q; cin >> q;
  for (int i = 0; i < q; ++i) {
    int s, t; cin >> s >> t; --s, --t;
    if (s == t) {
      cout << 0 << '\n';
      continue;
    }
    if (edges.count({s, t})) {
      cout << 1 << '\n';
      continue;
    }
    pair<int, int> focus = tree.findFocusNodes(s, t);
    cout << tree.minDist(focus.first, focus.second) + 2 << '\n';
  }
  return 0;
}
