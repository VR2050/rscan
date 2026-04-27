package O1;

import android.util.SparseIntArray;

/* JADX INFO: loaded from: classes.dex */
public final class r {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final SparseIntArray f2135a = new SparseIntArray();

    public final void a(long j3) {
        this.f2135a.put((int) j3, 0);
    }

    public final short b(long j3) {
        int i3 = this.f2135a.get((int) j3, -1);
        if (i3 != -1) {
            return (short) (i3 & 65535);
        }
        throw new RuntimeException("Tried to get non-existent cookie");
    }

    public final boolean c(long j3) {
        return this.f2135a.get((int) j3, -1) != -1;
    }

    public final void d(long j3) {
        int i3 = (int) j3;
        int i4 = this.f2135a.get(i3, -1);
        if (i4 == -1) {
            throw new RuntimeException("Tried to increment non-existent cookie");
        }
        this.f2135a.put(i3, i4 + 1);
    }

    public final void e(long j3) {
        this.f2135a.delete((int) j3);
    }
}
