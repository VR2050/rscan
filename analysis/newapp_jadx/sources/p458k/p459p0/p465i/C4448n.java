package p458k.p459p0.p465i;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import kotlin.UShort;
import kotlin.jvm.internal.Intrinsics;
import kotlin.ranges.IntProgression;
import kotlin.ranges.RangesKt___RangesKt;
import org.jetbrains.annotations.NotNull;
import p005b.p131d.p132a.p133a.C1499a;
import p458k.p459p0.C4401c;
import p458k.p459p0.p465i.C4438d;
import p474l.C4737a0;
import p474l.C4744f;
import p474l.C4747i;
import p474l.InterfaceC4746h;
import p474l.InterfaceC4764z;
import tv.danmaku.ijk.media.player.IjkMediaMeta;

/* renamed from: k.p0.i.n */
/* loaded from: classes3.dex */
public final class C4448n implements Closeable {

    /* renamed from: c */
    @NotNull
    public static final Logger f11903c;

    /* renamed from: e */
    public static final C4448n f11904e = null;

    /* renamed from: f */
    public final a f11905f;

    /* renamed from: g */
    public final C4438d.a f11906g;

    /* renamed from: h */
    public final InterfaceC4746h f11907h;

    /* renamed from: i */
    public final boolean f11908i;

    /* renamed from: k.p0.i.n$a */
    public static final class a implements InterfaceC4764z {

        /* renamed from: c */
        public int f11909c;

        /* renamed from: e */
        public int f11910e;

        /* renamed from: f */
        public int f11911f;

        /* renamed from: g */
        public int f11912g;

        /* renamed from: h */
        public int f11913h;

        /* renamed from: i */
        public final InterfaceC4746h f11914i;

        public a(@NotNull InterfaceC4746h source) {
            Intrinsics.checkParameterIsNotNull(source, "source");
            this.f11914i = source;
        }

        @Override // p474l.InterfaceC4764z
        /* renamed from: J */
        public long mo4924J(@NotNull C4744f sink, long j2) {
            int i2;
            int readInt;
            Intrinsics.checkParameterIsNotNull(sink, "sink");
            do {
                int i3 = this.f11912g;
                if (i3 != 0) {
                    long mo4924J = this.f11914i.mo4924J(sink, Math.min(j2, i3));
                    if (mo4924J == -1) {
                        return -1L;
                    }
                    this.f11912g -= (int) mo4924J;
                    return mo4924J;
                }
                this.f11914i.skip(this.f11913h);
                this.f11913h = 0;
                if ((this.f11910e & 4) != 0) {
                    return -1L;
                }
                i2 = this.f11911f;
                int m5034s = C4401c.m5034s(this.f11914i);
                this.f11912g = m5034s;
                this.f11909c = m5034s;
                int readByte = this.f11914i.readByte() & 255;
                this.f11910e = this.f11914i.readByte() & 255;
                C4448n c4448n = C4448n.f11904e;
                Logger logger = C4448n.f11903c;
                if (logger.isLoggable(Level.FINE)) {
                    logger.fine(C4439e.f11817e.m5166a(true, this.f11911f, this.f11909c, readByte, this.f11910e));
                }
                readInt = this.f11914i.readInt() & Integer.MAX_VALUE;
                this.f11911f = readInt;
                if (readByte != 9) {
                    throw new IOException(readByte + " != TYPE_CONTINUATION");
                }
            } while (readInt == i2);
            throw new IOException("TYPE_CONTINUATION streamId changed");
        }

        @Override // p474l.InterfaceC4764z
        @NotNull
        /* renamed from: c */
        public C4737a0 mo5044c() {
            return this.f11914i.mo5044c();
        }

        @Override // p474l.InterfaceC4764z, java.io.Closeable, java.lang.AutoCloseable
        public void close() {
        }
    }

    /* renamed from: k.p0.i.n$b */
    public interface b {
        /* renamed from: a */
        void mo5177a();

        /* renamed from: b */
        void mo5178b(boolean z, @NotNull C4454t c4454t);

        /* renamed from: c */
        void mo5179c(boolean z, int i2, int i3, @NotNull List<C4437c> list);

        /* renamed from: d */
        void mo5180d(int i2, long j2);

        /* renamed from: e */
        void mo5181e(boolean z, int i2, @NotNull InterfaceC4746h interfaceC4746h, int i3);

        /* renamed from: f */
        void mo5182f(boolean z, int i2, int i3);

        /* renamed from: g */
        void mo5183g(int i2, int i3, int i4, boolean z);

        /* renamed from: h */
        void mo5184h(int i2, @NotNull EnumC4436b enumC4436b);

        /* renamed from: i */
        void mo5185i(int i2, int i3, @NotNull List<C4437c> list);

        /* renamed from: j */
        void mo5186j(int i2, @NotNull EnumC4436b enumC4436b, @NotNull C4747i c4747i);
    }

    static {
        Logger logger = Logger.getLogger(C4439e.class.getName());
        Intrinsics.checkExpressionValueIsNotNull(logger, "Logger.getLogger(Http2::class.java.name)");
        f11903c = logger;
    }

    public C4448n(@NotNull InterfaceC4746h source, boolean z) {
        Intrinsics.checkParameterIsNotNull(source, "source");
        this.f11907h = source;
        this.f11908i = z;
        a aVar = new a(source);
        this.f11905f = aVar;
        this.f11906g = new C4438d.a(aVar, 4096, 0, 4);
    }

    /* renamed from: b */
    public final boolean m5187b(boolean z, @NotNull b handler) {
        int readInt;
        Intrinsics.checkParameterIsNotNull(handler, "handler");
        int i2 = 0;
        int i3 = 0;
        int i4 = 0;
        try {
            this.f11907h.mo5360M(9L);
            int m5034s = C4401c.m5034s(this.f11907h);
            if (m5034s > 16384) {
                throw new IOException(C1499a.m626l("FRAME_SIZE_ERROR: ", m5034s));
            }
            int readByte = this.f11907h.readByte() & 255;
            if (z && readByte != 4) {
                throw new IOException(C1499a.m626l("Expected a SETTINGS frame but was ", readByte));
            }
            int readByte2 = this.f11907h.readByte() & 255;
            int readInt2 = this.f11907h.readInt() & Integer.MAX_VALUE;
            Logger logger = f11903c;
            if (logger.isLoggable(Level.FINE)) {
                logger.fine(C4439e.f11817e.m5166a(true, readInt2, m5034s, readByte, readByte2));
            }
            EnumC4436b enumC4436b = null;
            switch (readByte) {
                case 0:
                    if (readInt2 == 0) {
                        throw new IOException("PROTOCOL_ERROR: TYPE_DATA streamId == 0");
                    }
                    boolean z2 = (readByte2 & 1) != 0;
                    if ((readByte2 & 32) != 0) {
                        throw new IOException("PROTOCOL_ERROR: FLAG_COMPRESSED without SETTINGS_COMPRESS_DATA");
                    }
                    int i5 = readByte2 & 8;
                    if (i5 != 0) {
                        byte readByte3 = this.f11907h.readByte();
                        byte[] bArr = C4401c.f11556a;
                        i2 = readByte3 & 255;
                    }
                    if (i5 != 0) {
                        m5034s--;
                    }
                    if (i2 > m5034s) {
                        throw new IOException(C1499a.m629o("PROTOCOL_ERROR padding ", i2, " > remaining length ", m5034s));
                    }
                    handler.mo5181e(z2, readInt2, this.f11907h, m5034s - i2);
                    this.f11907h.skip(i2);
                    return true;
                case 1:
                    if (readInt2 == 0) {
                        throw new IOException("PROTOCOL_ERROR: TYPE_HEADERS streamId == 0");
                    }
                    boolean z3 = (readByte2 & 1) != 0;
                    int i6 = readByte2 & 8;
                    if (i6 != 0) {
                        byte readByte4 = this.f11907h.readByte();
                        byte[] bArr2 = C4401c.f11556a;
                        i4 = readByte4 & 255;
                    }
                    if ((readByte2 & 32) != 0) {
                        m5190k(handler, readInt2);
                        m5034s -= 5;
                    }
                    if (i6 != 0) {
                        m5034s--;
                    }
                    if (i4 > m5034s) {
                        throw new IOException(C1499a.m629o("PROTOCOL_ERROR padding ", i4, " > remaining length ", m5034s));
                    }
                    handler.mo5179c(z3, readInt2, -1, m5189e(m5034s - i4, i4, readByte2, readInt2));
                    return true;
                case 2:
                    if (m5034s != 5) {
                        throw new IOException(C1499a.m628n("TYPE_PRIORITY length: ", m5034s, " != 5"));
                    }
                    if (readInt2 == 0) {
                        throw new IOException("TYPE_PRIORITY streamId == 0");
                    }
                    m5190k(handler, readInt2);
                    return true;
                case 3:
                    if (m5034s != 4) {
                        throw new IOException(C1499a.m628n("TYPE_RST_STREAM length: ", m5034s, " != 4"));
                    }
                    if (readInt2 == 0) {
                        throw new IOException("TYPE_RST_STREAM streamId == 0");
                    }
                    int readInt3 = this.f11907h.readInt();
                    EnumC4436b[] values = EnumC4436b.values();
                    int i7 = 0;
                    while (true) {
                        if (i7 < 14) {
                            EnumC4436b enumC4436b2 = values[i7];
                            if (enumC4436b2.f11782l == readInt3) {
                                enumC4436b = enumC4436b2;
                            } else {
                                i7++;
                            }
                        }
                    }
                    if (enumC4436b == null) {
                        throw new IOException(C1499a.m626l("TYPE_RST_STREAM unexpected error code: ", readInt3));
                    }
                    handler.mo5184h(readInt2, enumC4436b);
                    return true;
                case 4:
                    if (readInt2 != 0) {
                        throw new IOException("TYPE_SETTINGS streamId != 0");
                    }
                    if ((readByte2 & 1) != 0) {
                        if (m5034s != 0) {
                            throw new IOException("FRAME_SIZE_ERROR ack frame should be empty!");
                        }
                        handler.mo5177a();
                    } else {
                        if (m5034s % 6 != 0) {
                            throw new IOException(C1499a.m626l("TYPE_SETTINGS length % 6 != 0: ", m5034s));
                        }
                        C4454t c4454t = new C4454t();
                        IntProgression step = RangesKt___RangesKt.step(RangesKt___RangesKt.until(0, m5034s), 6);
                        int first = step.getFirst();
                        int last = step.getLast();
                        int step2 = step.getStep();
                        if (step2 < 0 ? first >= last : first <= last) {
                            while (true) {
                                short readShort = this.f11907h.readShort();
                                byte[] bArr3 = C4401c.f11556a;
                                int i8 = readShort & UShort.MAX_VALUE;
                                readInt = this.f11907h.readInt();
                                if (i8 != 2) {
                                    if (i8 == 3) {
                                        i8 = 4;
                                    } else if (i8 == 4) {
                                        i8 = 7;
                                        if (readInt < 0) {
                                            throw new IOException("PROTOCOL_ERROR SETTINGS_INITIAL_WINDOW_SIZE > 2^31 - 1");
                                        }
                                    } else if (i8 == 5 && (readInt < 16384 || readInt > 16777215)) {
                                    }
                                } else if (readInt != 0 && readInt != 1) {
                                    throw new IOException("PROTOCOL_ERROR SETTINGS_ENABLE_PUSH != 0 or 1");
                                }
                                c4454t.m5223c(i8, readInt);
                                if (first != last) {
                                    first += step2;
                                }
                            }
                            throw new IOException(C1499a.m626l("PROTOCOL_ERROR SETTINGS_MAX_FRAME_SIZE: ", readInt));
                        }
                        handler.mo5178b(false, c4454t);
                    }
                    return true;
                case 5:
                    if (readInt2 == 0) {
                        throw new IOException("PROTOCOL_ERROR: TYPE_PUSH_PROMISE streamId == 0");
                    }
                    int i9 = readByte2 & 8;
                    if (i9 != 0) {
                        byte readByte5 = this.f11907h.readByte();
                        byte[] bArr4 = C4401c.f11556a;
                        i3 = readByte5 & 255;
                    }
                    int readInt4 = this.f11907h.readInt() & Integer.MAX_VALUE;
                    int i10 = m5034s - 4;
                    if (i9 != 0) {
                        i10--;
                    }
                    if (i3 > i10) {
                        throw new IOException(C1499a.m629o("PROTOCOL_ERROR padding ", i3, " > remaining length ", i10));
                    }
                    handler.mo5185i(readInt2, readInt4, m5189e(i10 - i3, i3, readByte2, readInt2));
                    return true;
                case 6:
                    if (m5034s != 8) {
                        throw new IOException(C1499a.m626l("TYPE_PING length != 8: ", m5034s));
                    }
                    if (readInt2 != 0) {
                        throw new IOException("TYPE_PING streamId != 0");
                    }
                    handler.mo5182f((readByte2 & 1) != 0, this.f11907h.readInt(), this.f11907h.readInt());
                    return true;
                case 7:
                    if (m5034s < 8) {
                        throw new IOException(C1499a.m626l("TYPE_GOAWAY length < 8: ", m5034s));
                    }
                    if (readInt2 != 0) {
                        throw new IOException("TYPE_GOAWAY streamId != 0");
                    }
                    int readInt5 = this.f11907h.readInt();
                    int readInt6 = this.f11907h.readInt();
                    int i11 = m5034s - 8;
                    EnumC4436b[] values2 = EnumC4436b.values();
                    int i12 = 0;
                    while (true) {
                        if (i12 < 14) {
                            EnumC4436b enumC4436b3 = values2[i12];
                            if (enumC4436b3.f11782l == readInt6) {
                                enumC4436b = enumC4436b3;
                            } else {
                                i12++;
                            }
                        }
                    }
                    if (enumC4436b == null) {
                        throw new IOException(C1499a.m626l("TYPE_GOAWAY unexpected error code: ", readInt6));
                    }
                    C4747i c4747i = C4747i.f12135c;
                    if (i11 > 0) {
                        c4747i = this.f11907h.mo5380f(i11);
                    }
                    handler.mo5186j(readInt5, enumC4436b, c4747i);
                    return true;
                case 8:
                    if (m5034s != 4) {
                        throw new IOException(C1499a.m626l("TYPE_WINDOW_UPDATE length !=4: ", m5034s));
                    }
                    int readInt7 = this.f11907h.readInt();
                    byte[] bArr5 = C4401c.f11556a;
                    long j2 = 2147483647L & readInt7;
                    if (j2 == 0) {
                        throw new IOException("windowSizeIncrement was 0");
                    }
                    handler.mo5180d(readInt2, j2);
                    return true;
                default:
                    this.f11907h.skip(m5034s);
                    return true;
            }
        } catch (EOFException unused) {
            return false;
        }
    }

    @Override // java.io.Closeable, java.lang.AutoCloseable
    public void close() {
        this.f11907h.close();
    }

    /* renamed from: d */
    public final void m5188d(@NotNull b handler) {
        Intrinsics.checkParameterIsNotNull(handler, "handler");
        if (this.f11908i) {
            if (!m5187b(true, handler)) {
                throw new IOException("Required SETTINGS preface not received");
            }
            return;
        }
        InterfaceC4746h interfaceC4746h = this.f11907h;
        C4747i c4747i = C4439e.f11813a;
        C4747i mo5380f = interfaceC4746h.mo5380f(c4747i.mo5400c());
        Logger logger = f11903c;
        if (logger.isLoggable(Level.FINE)) {
            StringBuilder m586H = C1499a.m586H("<< CONNECTION ");
            m586H.append(mo5380f.mo5401d());
            logger.fine(C4401c.m5024i(m586H.toString(), new Object[0]));
        }
        if (!Intrinsics.areEqual(c4747i, mo5380f)) {
            StringBuilder m586H2 = C1499a.m586H("Expected a connection header but was ");
            m586H2.append(mo5380f.m5407j());
            throw new IOException(m586H2.toString());
        }
    }

    /* JADX WARN: Removed duplicated region for block: B:63:0x004c A[SYNTHETIC] */
    /* JADX WARN: Removed duplicated region for block: B:77:0x0040 A[SYNTHETIC] */
    /* renamed from: e */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public final java.util.List<p458k.p459p0.p465i.C4437c> m5189e(int r2, int r3, int r4, int r5) {
        /*
            Method dump skipped, instructions count: 326
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: p458k.p459p0.p465i.C4448n.m5189e(int, int, int, int):java.util.List");
    }

    /* renamed from: k */
    public final void m5190k(b bVar, int i2) {
        int readInt = this.f11907h.readInt();
        boolean z = (readInt & ((int) IjkMediaMeta.AV_CH_WIDE_LEFT)) != 0;
        byte readByte = this.f11907h.readByte();
        byte[] bArr = C4401c.f11556a;
        bVar.mo5183g(i2, readInt & Integer.MAX_VALUE, (readByte & 255) + 1, z);
    }
}
