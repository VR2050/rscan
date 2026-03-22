package p005b.p199l.p200a.p201a.p248o1.p249h0;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.io.File;

/* renamed from: b.l.a.a.o1.h0.k */
/* loaded from: classes.dex */
public class C2305k implements Comparable<C2305k> {

    /* renamed from: c */
    public final String f5863c;

    /* renamed from: e */
    public final long f5864e;

    /* renamed from: f */
    public final long f5865f;

    /* renamed from: g */
    public final boolean f5866g;

    /* renamed from: h */
    @Nullable
    public final File f5867h;

    /* renamed from: i */
    public final long f5868i;

    public C2305k(String str, long j2, long j3, long j4, @Nullable File file) {
        this.f5863c = str;
        this.f5864e = j2;
        this.f5865f = j3;
        this.f5866g = file != null;
        this.f5867h = file;
        this.f5868i = j4;
    }

    @Override // java.lang.Comparable
    /* renamed from: a, reason: merged with bridge method [inline-methods] */
    public int compareTo(@NonNull C2305k c2305k) {
        if (!this.f5863c.equals(c2305k.f5863c)) {
            return this.f5863c.compareTo(c2305k.f5863c);
        }
        long j2 = this.f5864e - c2305k.f5864e;
        if (j2 == 0) {
            return 0;
        }
        return j2 < 0 ? -1 : 1;
    }
}
