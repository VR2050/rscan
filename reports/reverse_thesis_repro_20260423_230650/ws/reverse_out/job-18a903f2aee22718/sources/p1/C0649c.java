package p1;

import c2.C0353a;
import t2.j;

/* JADX INFO: renamed from: p1.c, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public final class C0649c implements AutoCloseable {
    public C0649c(String str) {
        j.f(str, "sectionName");
        C0353a.c(0L, str);
    }

    @Override // java.lang.AutoCloseable
    public void close() {
        C0353a.i(0L);
    }
}
