package p458k.p459p0.p465i;

import java.io.Closeable;
import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.p459p0.C4401c;
import p458k.p459p0.p465i.C4438d;
import p474l.C4744f;
import p474l.InterfaceC4745g;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

/* renamed from: k.p0.i.p */
/* loaded from: classes3.dex */
public final class C4450p implements Closeable {

    /* renamed from: c */
    public static final Logger f11940c = Logger.getLogger(C4439e.class.getName());

    /* renamed from: e */
    public final C4744f f11941e;

    /* renamed from: f */
    public int f11942f;

    /* renamed from: g */
    public boolean f11943g;

    /* renamed from: h */
    @NotNull
    public final C4438d.b f11944h;

    /* renamed from: i */
    public final InterfaceC4745g f11945i;

    /* renamed from: j */
    public final boolean f11946j;

    public C4450p(@NotNull InterfaceC4745g sink, boolean z) {
        Intrinsics.checkParameterIsNotNull(sink, "sink");
        this.f11945i = sink;
        this.f11946j = z;
        C4744f c4744f = new C4744f();
        this.f11941e = c4744f;
        this.f11942f = 16384;
        this.f11944h = new C4438d.b(0, false, c4744f, 3);
    }

    /* renamed from: b */
    public final synchronized void m5207b(@NotNull C4454t peerSettings) {
        Intrinsics.checkParameterIsNotNull(peerSettings, "peerSettings");
        if (this.f11943g) {
            throw new IOException("closed");
        }
        int i2 = this.f11942f;
        int i3 = peerSettings.f11955a;
        if ((i3 & 32) != 0) {
            i2 = peerSettings.f11956b[5];
        }
        this.f11942f = i2;
        int i4 = i3 & 2;
        if ((i4 != 0 ? peerSettings.f11956b[1] : -1) != -1) {
            C4438d.b bVar = this.f11944h;
            int i5 = i4 != 0 ? peerSettings.f11956b[1] : -1;
            bVar.f11810h = i5;
            int min = Math.min(i5, 16384);
            int i6 = bVar.f11805c;
            if (i6 != min) {
                if (min < i6) {
                    bVar.f11803a = Math.min(bVar.f11803a, min);
                }
                bVar.f11804b = true;
                bVar.f11805c = min;
                int i7 = bVar.f11809g;
                if (min < i7) {
                    if (min == 0) {
                        bVar.m5160a();
                    } else {
                        bVar.m5161b(i7 - min);
                    }
                }
            }
        }
        m5209e(0, 0, 4, 1);
        this.f11945i.flush();
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public synchronized void close() {
        this.f11943g = true;
        this.f11945i.close();
    }

    /* renamed from: d */
    public final synchronized void m5208d(boolean z, int i2, @Nullable C4744f c4744f, int i3) {
        if (this.f11943g) {
            throw new IOException("closed");
        }
        m5209e(i2, i3, 0, z ? 1 : 0);
        if (i3 > 0) {
            InterfaceC4745g interfaceC4745g = this.f11945i;
            if (c4744f == null) {
                Intrinsics.throwNpe();
            }
            interfaceC4745g.mo4923x(c4744f, i3);
        }
    }

    /* renamed from: e */
    public final void m5209e(int i2, int i3, int i4, int i5) {
        Logger logger = f11940c;
        if (logger.isLoggable(Level.FINE)) {
            logger.fine(C4439e.f11817e.m5166a(false, i2, i3, i4, i5));
        }
        if (!(i3 <= this.f11942f)) {
            StringBuilder m586H = C1499a.m586H("FRAME_SIZE_ERROR length > ");
            m586H.append(this.f11942f);
            m586H.append(": ");
            m586H.append(i3);
            throw new IllegalArgumentException(m586H.toString().toString());
        }
        if (!((((int) IjkMediaMeta.AV_CH_WIDE_LEFT) & i2) == 0)) {
            throw new IllegalArgumentException(C1499a.m626l("reserved bit set: ", i2).toString());
        }
        InterfaceC4745g writeMedium = this.f11945i;
        byte[] bArr = C4401c.f11556a;
        Intrinsics.checkParameterIsNotNull(writeMedium, "$this$writeMedium");
        writeMedium.mo5388n((i3 >>> 16) & 255);
        writeMedium.mo5388n((i3 >>> 8) & 255);
        writeMedium.mo5388n(i3 & 255);
        this.f11945i.mo5388n(i4 & 255);
        this.f11945i.mo5388n(i5 & 255);
        this.f11945i.mo5385j(i2 & Integer.MAX_VALUE);
    }

    public final synchronized void flush() {
        if (this.f11943g) {
            throw new IOException("closed");
        }
        this.f11945i.flush();
    }

    /* renamed from: k */
    public final synchronized void m5210k(int i2, @NotNull EnumC4436b errorCode, @NotNull byte[] debugData) {
        Intrinsics.checkParameterIsNotNull(errorCode, "errorCode");
        Intrinsics.checkParameterIsNotNull(debugData, "debugData");
        if (this.f11943g) {
            throw new IOException("closed");
        }
        if (!(errorCode.f11782l != -1)) {
            throw new IllegalArgumentException("errorCode.httpCode == -1".toString());
        }
        m5209e(0, debugData.length + 8, 7, 0);
        this.f11945i.mo5385j(i2);
        this.f11945i.mo5385j(errorCode.f11782l);
        if (!(debugData.length == 0)) {
            this.f11945i.mo5356G(debugData);
        }
        this.f11945i.flush();
    }

    /* renamed from: o */
    public final synchronized void m5211o(boolean z, int i2, @NotNull List<C4437c> headerBlock) {
        Intrinsics.checkParameterIsNotNull(headerBlock, "headerBlock");
        if (this.f11943g) {
            throw new IOException("closed");
        }
        this.f11944h.m5164e(headerBlock);
        long j2 = this.f11941e.f12133e;
        long min = Math.min(this.f11942f, j2);
        int i3 = j2 == min ? 4 : 0;
        if (z) {
            i3 |= 1;
        }
        m5209e(i2, (int) min, 1, i3);
        this.f11945i.mo4923x(this.f11941e, min);
        if (j2 > min) {
            m5215v(i2, j2 - min);
        }
    }

    /* renamed from: q */
    public final synchronized void m5212q(boolean z, int i2, int i3) {
        if (this.f11943g) {
            throw new IOException("closed");
        }
        m5209e(0, 8, 6, z ? 1 : 0);
        this.f11945i.mo5385j(i2);
        this.f11945i.mo5385j(i3);
        this.f11945i.flush();
    }

    /* renamed from: s */
    public final synchronized void m5213s(int i2, @NotNull EnumC4436b errorCode) {
        Intrinsics.checkParameterIsNotNull(errorCode, "errorCode");
        if (this.f11943g) {
            throw new IOException("closed");
        }
        if (!(errorCode.f11782l != -1)) {
            throw new IllegalArgumentException("Failed requirement.".toString());
        }
        m5209e(i2, 4, 3, 0);
        this.f11945i.mo5385j(errorCode.f11782l);
        this.f11945i.flush();
    }

    /* renamed from: t */
    public final synchronized void m5214t(int i2, long j2) {
        if (this.f11943g) {
            throw new IOException("closed");
        }
        if (!(j2 != 0 && j2 <= 2147483647L)) {
            throw new IllegalArgumentException(("windowSizeIncrement == 0 || windowSizeIncrement > 0x7fffffffL: " + j2).toString());
        }
        m5209e(i2, 4, 8, 0);
        this.f11945i.mo5385j((int) j2);
        this.f11945i.flush();
    }

    /* renamed from: v */
    public final void m5215v(int i2, long j2) {
        while (j2 > 0) {
            long min = Math.min(this.f11942f, j2);
            j2 -= min;
            m5209e(i2, (int) min, 9, j2 == 0 ? 4 : 0);
            this.f11945i.mo4923x(this.f11941e, min);
        }
    }
}
