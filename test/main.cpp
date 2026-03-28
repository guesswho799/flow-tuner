#define NOINLINE __attribute__((noinline)) __attribute__((noclone))

constexpr int N = 250;
constexpr int MAX_DEPTH = 10;

constexpr long long rnd(long long x) {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

constexpr int next(int i) {
    return rnd(i) % N;
}

template<int I, int D>
NOINLINE int f() {
    if constexpr (D == 0) {
        return I;
    } else {
        constexpr int n = next(I);
        return f<n, D - 1>();
    }
}

typedef int (*FuncPtr)();

template<int Lo, int Hi>
static void fill(FuncPtr* t) {
    if constexpr (Lo == Hi) { t[Lo] = f<Lo, MAX_DEPTH>; }
    else {
        constexpr int Mid = (Lo + Hi) / 2;
        fill<Lo,    Mid>(t);
        fill<Mid+1, Hi>(t);
    }
}

int main() {
    FuncPtr function_table[N];
    fill<0, N-1>(function_table);

    volatile int result = 0;
    for (int i = 0; i < 20000; i++) {
        for (int j = 0; j < 20000; j++) {
            int seed = (i + j) % N;
            result = function_table[seed]();
        }
    }
    return result;
}
