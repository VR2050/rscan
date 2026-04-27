package androidx.core.os;

import android.os.LocaleList;
import java.util.Locale;

/* JADX INFO: loaded from: classes.dex */
final class e implements d {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final LocaleList f4371a;

    e(Object obj) {
        this.f4371a = (LocaleList) obj;
    }

    @Override // androidx.core.os.d
    public String a() {
        return this.f4371a.toLanguageTags();
    }

    @Override // androidx.core.os.d
    public Object b() {
        return this.f4371a;
    }

    public boolean equals(Object obj) {
        return this.f4371a.equals(((d) obj).b());
    }

    @Override // androidx.core.os.d
    public Locale get(int i3) {
        return this.f4371a.get(i3);
    }

    public int hashCode() {
        return this.f4371a.hashCode();
    }

    @Override // androidx.core.os.d
    public boolean isEmpty() {
        return this.f4371a.isEmpty();
    }

    @Override // androidx.core.os.d
    public int size() {
        return this.f4371a.size();
    }

    public String toString() {
        return this.f4371a.toString();
    }
}
