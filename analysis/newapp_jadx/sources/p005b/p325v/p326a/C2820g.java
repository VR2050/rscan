package p005b.p325v.p326a;

import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import java.util.Objects;

/* renamed from: b.v.a.g */
/* loaded from: classes2.dex */
public class C2820g implements InterfaceC2815b {

    /* renamed from: a */
    public final int f7658a = 2;

    /* renamed from: b */
    public final boolean f7659b = true;

    /* renamed from: c */
    @NonNull
    public final C2817d f7660c;

    /* renamed from: d */
    @Nullable
    public final String f7661d;

    /* renamed from: b.v.a.g$b */
    public static class b {

        /* renamed from: a */
        @Nullable
        public C2817d f7662a;

        /* renamed from: b */
        @Nullable
        public String f7663b = "PRETTY_LOGGER";

        public b(a aVar) {
        }
    }

    public C2820g(b bVar, a aVar) {
        this.f7660c = bVar.f7662a;
        this.f7661d = bVar.f7663b;
    }

    /* JADX WARN: Removed duplicated region for block: B:10:0x004b  */
    /* JADX WARN: Removed duplicated region for block: B:14:0x006d  */
    /* JADX WARN: Removed duplicated region for block: B:22:0x0098  */
    /* JADX WARN: Removed duplicated region for block: B:25:0x00a0  */
    /* JADX WARN: Removed duplicated region for block: B:34:0x0128  */
    /* JADX WARN: Removed duplicated region for block: B:40:0x0136  */
    /* JADX WARN: Removed duplicated region for block: B:52:0x0091 A[SYNTHETIC] */
    @Override // p005b.p325v.p326a.InterfaceC2815b
    /* renamed from: a */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void mo3271a(int r12, @androidx.annotation.Nullable java.lang.String r13, @androidx.annotation.NonNull java.lang.String r14) {
        /*
            Method dump skipped, instructions count: 340
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p005b.p325v.p326a.C2820g.mo3271a(int, java.lang.String, java.lang.String):void");
    }

    /* renamed from: b */
    public final void m3278b(int i2, @Nullable String str, @NonNull String str2) {
        Objects.requireNonNull(str2);
        Objects.requireNonNull(this.f7660c);
        if (str == null) {
            str = "NO_TAG";
        }
        Log.println(i2, str, str2);
    }

    /* renamed from: c */
    public final void m3279c(int i2, @Nullable String str, @NonNull String str2) {
        for (String str3 : str2.split(System.getProperty("line.separator"))) {
            m3278b(i2, str, "│ " + str3);
        }
    }
}
