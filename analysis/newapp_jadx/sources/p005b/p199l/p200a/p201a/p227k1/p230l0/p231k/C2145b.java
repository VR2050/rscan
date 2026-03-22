package p005b.p199l.p200a.p201a.p227k1.p230l0.p231k;

import android.net.Uri;
import androidx.annotation.Nullable;
import java.util.Collections;
import java.util.List;
import p005b.p199l.p200a.p201a.C2399v;

/* renamed from: b.l.a.a.k1.l0.k.b */
/* loaded from: classes.dex */
public class C2145b {

    /* renamed from: a */
    public final long f4780a;

    /* renamed from: b */
    public final long f4781b;

    /* renamed from: c */
    public final long f4782c;

    /* renamed from: d */
    public final boolean f4783d;

    /* renamed from: e */
    public final long f4784e;

    /* renamed from: f */
    public final long f4785f;

    /* renamed from: g */
    public final long f4786g;

    /* renamed from: h */
    public final long f4787h;

    /* renamed from: i */
    @Nullable
    public final C2156m f4788i;

    /* renamed from: j */
    @Nullable
    public final Uri f4789j;

    /* renamed from: k */
    @Nullable
    public final C2150g f4790k;

    /* renamed from: l */
    public final List<C2149f> f4791l;

    public C2145b(long j2, long j3, long j4, boolean z, long j5, long j6, long j7, long j8, @Nullable C2150g c2150g, @Nullable C2156m c2156m, @Nullable Uri uri, List<C2149f> list) {
        this.f4780a = j2;
        this.f4781b = j3;
        this.f4782c = j4;
        this.f4783d = z;
        this.f4784e = j5;
        this.f4785f = j6;
        this.f4786g = j7;
        this.f4787h = j8;
        this.f4790k = c2150g;
        this.f4788i = c2156m;
        this.f4789j = uri;
        this.f4791l = list == null ? Collections.emptyList() : list;
    }

    /* renamed from: a */
    public final C2149f m1887a(int i2) {
        return this.f4791l.get(i2);
    }

    /* renamed from: b */
    public final int m1888b() {
        return this.f4791l.size();
    }

    /* renamed from: c */
    public final long m1889c(int i2) {
        if (i2 != this.f4791l.size() - 1) {
            return this.f4791l.get(i2 + 1).f4811b - this.f4791l.get(i2).f4811b;
        }
        long j2 = this.f4781b;
        if (j2 == -9223372036854775807L) {
            return -9223372036854775807L;
        }
        return j2 - this.f4791l.get(i2).f4811b;
    }

    /* renamed from: d */
    public final long m1890d(int i2) {
        return C2399v.m2668a(m1889c(i2));
    }
}
