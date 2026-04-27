package w2;

import t2.j;

/* JADX INFO: loaded from: classes.dex */
abstract class e {
    public static final void a(boolean z3, Number number) {
        j.f(number, "step");
        if (z3) {
            return;
        }
        throw new IllegalArgumentException("Step must be positive, was: " + number + '.');
    }
}
