package p474l;

import java.util.zip.Inflater;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: l.n */
/* loaded from: classes3.dex */
public final class C4752n implements InterfaceC4764z {

    /* renamed from: c */
    public int f12148c;

    /* renamed from: e */
    public boolean f12149e;

    /* renamed from: f */
    public final InterfaceC4746h f12150f;

    /* renamed from: g */
    public final Inflater f12151g;

    public C4752n(@NotNull InterfaceC4746h source, @NotNull Inflater inflater) {
        Intrinsics.checkNotNullParameter(source, "source");
        Intrinsics.checkNotNullParameter(inflater, "inflater");
        this.f12150f = source;
        this.f12151g = inflater;
    }

    /* JADX WARN: Removed duplicated region for block: B:12:0x009a  */
    /* JADX WARN: Removed duplicated region for block: B:27:0x0099 A[SYNTHETIC] */
    @Override // p474l.InterfaceC4764z
    /* renamed from: J */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public long mo4924J(@org.jetbrains.annotations.NotNull p474l.C4744f r10, long r11) {
        /*
            Method dump skipped, instructions count: 227
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p474l.C4752n.mo4924J(l.f, long):long");
    }

    @Override // p474l.InterfaceC4764z
    @NotNull
    /* renamed from: c */
    public C4737a0 mo5044c() {
        return this.f12150f.mo5044c();
    }

    @Override // p474l.InterfaceC4764z, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        if (this.f12149e) {
            return;
        }
        this.f12151g.end();
        this.f12149e = true;
        this.f12150f.close();
    }
}
