package w2;

import i2.C;
import java.util.NoSuchElementException;

/* JADX INFO: loaded from: classes.dex */
public final class b extends C {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final int f10301a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f10302b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private boolean f10303c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int f10304d;

    public b(int i3, int i4, int i5) {
        this.f10301a = i5;
        this.f10302b = i4;
        boolean z3 = false;
        if (i5 <= 0 ? i3 >= i4 : i3 <= i4) {
            z3 = true;
        }
        this.f10303c = z3;
        this.f10304d = z3 ? i3 : i4;
    }

    @Override // i2.C
    public int a() {
        int i3 = this.f10304d;
        if (i3 != this.f10302b) {
            this.f10304d = this.f10301a + i3;
        } else {
            if (!this.f10303c) {
                throw new NoSuchElementException();
            }
            this.f10303c = false;
        }
        return i3;
    }

    @Override // java.util.Iterator
    public boolean hasNext() {
        return this.f10303c;
    }
}
