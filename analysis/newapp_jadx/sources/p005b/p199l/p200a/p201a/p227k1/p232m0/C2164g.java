package p005b.p199l.p200a.p201a.p227k1.p232m0;

import android.net.Uri;
import java.util.LinkedHashMap;
import java.util.Map;

/* renamed from: b.l.a.a.k1.m0.g */
/* loaded from: classes.dex */
public final class C2164g {

    /* renamed from: a */
    public final LinkedHashMap<Uri, byte[]> f4864a;

    /* renamed from: b.l.a.a.k1.m0.g$a */
    public class a extends LinkedHashMap<Uri, byte[]> {

        /* renamed from: c */
        public final /* synthetic */ int f4865c;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(C2164g c2164g, int i2, float f2, boolean z, int i3) {
            super(i2, f2, z);
            this.f4865c = i3;
        }

        @Override // java.util.LinkedHashMap
        public boolean removeEldestEntry(Map.Entry<Uri, byte[]> entry) {
            return size() > this.f4865c;
        }
    }

    public C2164g(int i2) {
        this.f4864a = new a(this, i2 + 1, 1.0f, false, i2);
    }
}
