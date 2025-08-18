#include <bits/stdc++.h>
using namespace std;

typedef long long ll;

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int n, m, t;
    cin >> n >> m >> t;

    int T = n - t + 1;
    vector<vector<ll>> add(T + 2), remove(T + 2);  // range [1..T]

    for (int i = 0; i < m; ++i) {
        int l, r;
        ll p;
        cin >> l >> r >> p;

        int start = l;
        int end = r - t + 1;
        if (start > end) continue;

        add[start].push_back(p);
        remove[end + 1].push_back(p);
    }

    // Compute best gain at each possible start time [1..T]
    multiset<ll> active;
    vector<ll> gain(T + 2, 0);

    for (int i = 1; i <= T; ++i) {
        for (ll p : add[i]) active.insert(p);
        for (ll p : remove[i]) active.erase(active.find(p));

        if (!active.empty())
            gain[i] = *active.rbegin();
    }

    // DP
    vector<ll> dp(n + 2, 0);
    for (int i = 1; i <= n; ++i) {
        dp[i] = dp[i - 1];
        if (i >= t) {
            dp[i] = max(dp[i], dp[i - t] + gain[i - t + 1]);
        }
    }

    cout << dp[n] << "\n";
    return 0;
}
