package p005b.p199l.p200a.p201a.p208f1;

import androidx.annotation.Nullable;
import com.google.android.exoplayer2.Format;
import java.util.Arrays;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.f1.s */
/* loaded from: classes.dex */
public interface InterfaceC2052s {

    /* renamed from: b.l.a.a.f1.s$a */
    public static final class a {

        /* renamed from: a */
        public final int f4195a;

        /* renamed from: b */
        public final byte[] f4196b;

        /* renamed from: c */
        public final int f4197c;

        /* renamed from: d */
        public final int f4198d;

        public a(int i2, byte[] bArr, int i3, int i4) {
            this.f4195a = i2;
            this.f4196b = bArr;
            this.f4197c = i3;
            this.f4198d = i4;
        }

        public boolean equals(@Nullable Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj == null || a.class != obj.getClass()) {
                return false;
            }
            a aVar = (a) obj;
            return this.f4195a == aVar.f4195a && this.f4197c == aVar.f4197c && this.f4198d == aVar.f4198d && Arrays.equals(this.f4196b, aVar.f4196b);
        }

        public int hashCode() {
            return ((((Arrays.hashCode(this.f4196b) + (this.f4195a * 31)) * 31) + this.f4197c) * 31) + this.f4198d;
        }
    }

    /* renamed from: a */
    int mo1612a(C2003e c2003e, int i2, boolean z);

    /* renamed from: b */
    void mo1613b(C2360t c2360t, int i2);

    /* renamed from: c */
    void mo1614c(long j2, int i2, int i3, int i4, @Nullable a aVar);

    /* renamed from: d */
    void mo1615d(Format format);
}
