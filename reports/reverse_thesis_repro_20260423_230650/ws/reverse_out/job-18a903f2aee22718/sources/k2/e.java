package k2;

import java.util.Comparator;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
final class e implements Comparator {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final e f9422a = new e();

    private e() {
    }

    @Override // java.util.Comparator
    /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
    public int compare(Comparable comparable, Comparable comparable2) {
        j.f(comparable, "a");
        j.f(comparable2, "b");
        return comparable.compareTo(comparable2);
    }

    @Override // java.util.Comparator
    public final Comparator reversed() {
        return f.f9423a;
    }
}
