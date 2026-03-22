package p005b.p199l.p200a.p201a.p202a1;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2344d0;

/* renamed from: b.l.a.a.a1.l */
/* loaded from: classes.dex */
public interface InterfaceC1920l {

    /* renamed from: a */
    public static final ByteBuffer f3076a = ByteBuffer.allocateDirect(0).order(ByteOrder.nativeOrder());

    /* renamed from: b.l.a.a.a1.l$a */
    public static final class a {

        /* renamed from: a */
        public static final a f3077a = new a(-1, -1, -1);

        /* renamed from: b */
        public final int f3078b;

        /* renamed from: c */
        public final int f3079c;

        /* renamed from: d */
        public final int f3080d;

        /* renamed from: e */
        public final int f3081e;

        public a(int i2, int i3, int i4) {
            this.f3078b = i2;
            this.f3079c = i3;
            this.f3080d = i4;
            this.f3081e = C2344d0.m2346x(i4) ? C2344d0.m2337o(i4, i3) : -1;
        }

        public String toString() {
            StringBuilder m586H = C1499a.m586H("AudioFormat[sampleRate=");
            m586H.append(this.f3078b);
            m586H.append(", channelCount=");
            m586H.append(this.f3079c);
            m586H.append(", encoding=");
            return C1499a.m579A(m586H, this.f3080d, ']');
        }
    }

    /* renamed from: b.l.a.a.a1.l$b */
    public static final class b extends Exception {
        public b(a aVar) {
            super("Unhandled format: " + aVar);
        }
    }

    /* renamed from: b */
    boolean mo1253b();

    /* renamed from: c */
    boolean mo1254c();

    /* renamed from: d */
    ByteBuffer mo1255d();

    /* renamed from: e */
    void mo1256e(ByteBuffer byteBuffer);

    /* renamed from: f */
    a mo1257f(a aVar);

    void flush();

    /* renamed from: g */
    void mo1258g();

    void reset();
}
