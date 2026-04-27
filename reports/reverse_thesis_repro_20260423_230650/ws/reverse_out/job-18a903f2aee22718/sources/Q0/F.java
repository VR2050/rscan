package Q0;

import android.util.SparseIntArray;

/* JADX INFO: loaded from: classes.dex */
public class F {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public final int f2350a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public final int f2351b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public final SparseIntArray f2352c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public final int f2353d;

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public final int f2354e;

    /* JADX INFO: renamed from: f, reason: collision with root package name */
    public boolean f2355f;

    /* JADX INFO: renamed from: g, reason: collision with root package name */
    public final int f2356g;

    public F(int i3, int i4, SparseIntArray sparseIntArray) {
        this(i3, i4, sparseIntArray, 0, Integer.MAX_VALUE, -1);
    }

    public F(int i3, int i4, SparseIntArray sparseIntArray, int i5, int i6, int i7) {
        X.k.i(i3 >= 0 && i4 >= i3);
        this.f2351b = i3;
        this.f2350a = i4;
        this.f2352c = sparseIntArray;
        this.f2353d = i5;
        this.f2354e = i6;
        this.f2356g = i7;
    }
}
