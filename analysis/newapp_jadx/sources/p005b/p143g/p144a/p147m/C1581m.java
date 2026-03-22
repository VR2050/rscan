package p005b.p143g.p144a.p147m;

import android.text.TextUtils;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.security.MessageDigest;
import java.util.Objects;
import p005b.p131d.p132a.p133a.C1499a;

/* renamed from: b.g.a.m.m */
/* loaded from: classes.dex */
public final class C1581m<T> {

    /* renamed from: a */
    public static final b<Object> f1990a = new a();

    /* renamed from: b */
    public final T f1991b;

    /* renamed from: c */
    public final b<T> f1992c;

    /* renamed from: d */
    public final String f1993d;

    /* renamed from: e */
    public volatile byte[] f1994e;

    /* renamed from: b.g.a.m.m$a */
    public class a implements b<Object> {
        @Override // p005b.p143g.p144a.p147m.C1581m.b
        /* renamed from: a */
        public void mo826a(@NonNull byte[] bArr, @NonNull Object obj, @NonNull MessageDigest messageDigest) {
        }
    }

    /* renamed from: b.g.a.m.m$b */
    public interface b<T> {
        /* renamed from: a */
        void mo826a(@NonNull byte[] bArr, @NonNull T t, @NonNull MessageDigest messageDigest);
    }

    public C1581m(@NonNull String str, @Nullable T t, @NonNull b<T> bVar) {
        if (TextUtils.isEmpty(str)) {
            throw new IllegalArgumentException("Must not be null or empty");
        }
        this.f1993d = str;
        this.f1991b = t;
        Objects.requireNonNull(bVar, "Argument must not be null");
        this.f1992c = bVar;
    }

    @NonNull
    /* renamed from: a */
    public static <T> C1581m<T> m825a(@NonNull String str, @NonNull T t) {
        return new C1581m<>(str, t, f1990a);
    }

    public boolean equals(Object obj) {
        if (obj instanceof C1581m) {
            return this.f1993d.equals(((C1581m) obj).f1993d);
        }
        return false;
    }

    public int hashCode() {
        return this.f1993d.hashCode();
    }

    public String toString() {
        StringBuilder m586H = C1499a.m586H("Option{key='");
        m586H.append(this.f1993d);
        m586H.append('\'');
        m586H.append('}');
        return m586H.toString();
    }
}
