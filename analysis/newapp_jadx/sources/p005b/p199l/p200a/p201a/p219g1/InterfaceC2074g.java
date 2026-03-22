package p005b.p199l.p200a.p201a.p219g1;

import androidx.annotation.Nullable;
import java.util.List;

/* renamed from: b.l.a.a.g1.g */
/* loaded from: classes.dex */
public interface InterfaceC2074g {

    /* renamed from: a */
    public static final InterfaceC2074g f4351a = new a();

    /* renamed from: b.l.a.a.g1.g$a */
    public static class a implements InterfaceC2074g {
        @Override // p005b.p199l.p200a.p201a.p219g1.InterfaceC2074g
        @Nullable
        /* renamed from: a */
        public C2072e mo1687a() {
            C2072e m1692d = C2075h.m1692d("audio/raw", false, false);
            if (m1692d == null) {
                return null;
            }
            return new C2072e(m1692d.f4280a, null, null, null, true, false, true, false, false, false);
        }

        @Override // p005b.p199l.p200a.p201a.p219g1.InterfaceC2074g
        /* renamed from: b */
        public List<C2072e> mo1688b(String str, boolean z, boolean z2) {
            return C2075h.m1693e(str, z, z2);
        }
    }

    @Nullable
    /* renamed from: a */
    C2072e mo1687a();

    /* renamed from: b */
    List<C2072e> mo1688b(String str, boolean z, boolean z2);
}
