package androidx.core.util;

import q.e;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public class Pools$SimplePool implements e {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final Object[] f4386a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private int f4387b;

    public Pools$SimplePool(int i3) {
        if (i3 <= 0) {
            throw new IllegalArgumentException("The max pool size must be > 0");
        }
        this.f4386a = new Object[i3];
    }

    private final boolean c(Object obj) {
        int i3 = this.f4387b;
        for (int i4 = 0; i4 < i3; i4++) {
            if (this.f4386a[i4] == obj) {
                return true;
            }
        }
        return false;
    }

    @Override // q.e
    public boolean a(Object obj) {
        j.f(obj, "instance");
        if (c(obj)) {
            throw new IllegalStateException("Already in the pool!");
        }
        int i3 = this.f4387b;
        Object[] objArr = this.f4386a;
        if (i3 >= objArr.length) {
            return false;
        }
        objArr[i3] = obj;
        this.f4387b = i3 + 1;
        return true;
    }

    @Override // q.e
    public Object b() {
        int i3 = this.f4387b;
        if (i3 <= 0) {
            return null;
        }
        int i4 = i3 - 1;
        Object obj = this.f4386a[i4];
        j.d(obj, "null cannot be cast to non-null type T of androidx.core.util.Pools.SimplePool");
        this.f4386a[i4] = null;
        this.f4387b--;
        return obj;
    }
}
