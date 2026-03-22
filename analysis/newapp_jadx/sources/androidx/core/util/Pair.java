package androidx.core.util;

import androidx.annotation.NonNull;
import p005b.p131d.p132a.p133a.C1499a;

/* loaded from: classes.dex */
public class Pair<F, S> {
    public final F first;
    public final S second;

    public Pair(F f2, S s) {
        this.first = f2;
        this.second = s;
    }

    @NonNull
    public static <A, B> Pair<A, B> create(A a, B b2) {
        return new Pair<>(a, b2);
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof Pair)) {
            return false;
        }
        Pair pair = (Pair) obj;
        return ObjectsCompat.equals(pair.first, this.first) && ObjectsCompat.equals(pair.second, this.second);
    }

    public int hashCode() {
        F f2 = this.first;
        int hashCode = f2 == null ? 0 : f2.hashCode();
        S s = this.second;
        return hashCode ^ (s != null ? s.hashCode() : 0);
    }

    @NonNull
    public String toString() {
        StringBuilder m586H = C1499a.m586H("Pair{");
        m586H.append(this.first);
        m586H.append(" ");
        m586H.append(this.second);
        m586H.append("}");
        return m586H.toString();
    }
}
