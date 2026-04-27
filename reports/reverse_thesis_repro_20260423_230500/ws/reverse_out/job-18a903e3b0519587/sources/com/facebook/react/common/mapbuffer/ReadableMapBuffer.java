package com.facebook.react.common.mapbuffer;

import com.facebook.jni.HybridClassBase;
import com.facebook.react.common.mapbuffer.ReadableMapBuffer;
import com.facebook.react.common.mapbuffer.a;
import h2.C0562h;
import h2.p;
import i2.x;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Iterator;
import kotlin.jvm.internal.DefaultConstructorMarker;
import s2.l;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class ReadableMapBuffer extends HybridClassBase implements com.facebook.react.common.mapbuffer.a {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final a f6650e = new a(null);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final ByteBuffer f6651b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f6652c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private int f6653d;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    private final class b implements a.c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private final int f6654a;

        public b(int i3) {
            this.f6654a = i3;
        }

        private final void g(a.b bVar) {
            a.b type = getType();
            if (bVar == type) {
                return;
            }
            throw new IllegalStateException(("Expected " + bVar + " for key: " + getKey() + " found " + type + " instead.").toString());
        }

        @Override // com.facebook.react.common.mapbuffer.a.c
        public long a() {
            g(a.b.f6675g);
            return ReadableMapBuffer.this.C(this.f6654a + 4);
        }

        @Override // com.facebook.react.common.mapbuffer.a.c
        public String b() {
            g(a.b.f6673e);
            return ReadableMapBuffer.this.E(this.f6654a + 4);
        }

        @Override // com.facebook.react.common.mapbuffer.a.c
        public int c() {
            g(a.b.f6671c);
            return ReadableMapBuffer.this.B(this.f6654a + 4);
        }

        @Override // com.facebook.react.common.mapbuffer.a.c
        public com.facebook.react.common.mapbuffer.a d() {
            g(a.b.f6674f);
            return ReadableMapBuffer.this.D(this.f6654a + 4);
        }

        @Override // com.facebook.react.common.mapbuffer.a.c
        public double e() {
            g(a.b.f6672d);
            return ReadableMapBuffer.this.z(this.f6654a + 4);
        }

        @Override // com.facebook.react.common.mapbuffer.a.c
        public boolean f() {
            g(a.b.f6670b);
            return ReadableMapBuffer.this.x(this.f6654a + 4);
        }

        @Override // com.facebook.react.common.mapbuffer.a.c
        public int getKey() {
            return ReadableMapBuffer.this.F(this.f6654a) & 65535;
        }

        @Override // com.facebook.react.common.mapbuffer.a.c
        public a.b getType() {
            return a.b.values()[ReadableMapBuffer.this.F(this.f6654a + 2) & 65535];
        }
    }

    public /* synthetic */ class c {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        public static final /* synthetic */ int[] f6656a;

        static {
            int[] iArr = new int[a.b.values().length];
            try {
                iArr[a.b.f6670b.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                iArr[a.b.f6671c.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                iArr[a.b.f6675g.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
            try {
                iArr[a.b.f6672d.ordinal()] = 4;
            } catch (NoSuchFieldError unused4) {
            }
            try {
                iArr[a.b.f6673e.ordinal()] = 5;
            } catch (NoSuchFieldError unused5) {
            }
            try {
                iArr[a.b.f6674f.ordinal()] = 6;
            } catch (NoSuchFieldError unused6) {
            }
            f6656a = iArr;
        }
    }

    public static final class d implements Iterator {

        /* JADX INFO: renamed from: a, reason: collision with root package name */
        private int f6657a;

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        private final int f6658b;

        d() {
            this.f6658b = ReadableMapBuffer.this.getCount() - 1;
        }

        @Override // java.util.Iterator
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public a.c next() {
            ReadableMapBuffer readableMapBuffer = ReadableMapBuffer.this;
            int i3 = this.f6657a;
            this.f6657a = i3 + 1;
            return readableMapBuffer.new b(readableMapBuffer.t(i3));
        }

        @Override // java.util.Iterator
        public boolean hasNext() {
            return this.f6657a <= this.f6658b;
        }

        @Override // java.util.Iterator
        public void remove() {
            throw new UnsupportedOperationException("Operation is not supported for read-only collection");
        }
    }

    private ReadableMapBuffer(ByteBuffer byteBuffer, int i3) {
        this.f6651b = byteBuffer;
        this.f6652c = i3;
        A();
    }

    private final void A() {
        if (this.f6651b.getShort() != 254) {
            this.f6651b.order(ByteOrder.LITTLE_ENDIAN);
        }
        this.f6653d = F(this.f6651b.position()) & 65535;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final int B(int i3) {
        return this.f6651b.getInt(i3);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final long C(int i3) {
        return this.f6651b.getLong(i3);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final ReadableMapBuffer D(int i3) {
        return r(v() + this.f6651b.getInt(i3) + 4);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final String E(int i3) {
        int iV = v() + this.f6651b.getInt(i3);
        int i4 = this.f6651b.getInt(iV);
        byte[] bArr = new byte[i4];
        this.f6651b.position(iV + 4);
        this.f6651b.get(bArr, 0, i4);
        return new String(bArr, z2.d.f10544b);
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final short F(int i3) {
        return p.a(this.f6651b.getShort(i3));
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static final CharSequence G(a.c cVar) {
        j.f(cVar, "entry");
        StringBuilder sb = new StringBuilder();
        sb.append(cVar.getKey());
        sb.append('=');
        switch (c.f6656a[cVar.getType().ordinal()]) {
            case 1:
                sb.append(cVar.f());
                return sb;
            case 2:
                sb.append(cVar.c());
                return sb;
            case 3:
                sb.append(cVar.a());
                return sb;
            case 4:
                sb.append(cVar.e());
                return sb;
            case 5:
                sb.append('\"');
                sb.append(cVar.b());
                sb.append('\"');
                return sb;
            case 6:
                sb.append(cVar.d().toString());
                return sb;
            default:
                throw new C0562h();
        }
    }

    private final ReadableMapBuffer r(int i3) {
        ByteBuffer byteBufferDuplicate = this.f6651b.duplicate();
        byteBufferDuplicate.position(i3);
        j.e(byteBufferDuplicate, "apply(...)");
        return new ReadableMapBuffer(byteBufferDuplicate, i3);
    }

    private final int s(int i3) {
        w2.c cVarA = com.facebook.react.common.mapbuffer.a.f6667a.a();
        int iA = cVarA.a();
        if (i3 <= cVarA.b() && iA <= i3) {
            short sA = p.a((short) i3);
            int count = getCount() - 1;
            int i4 = 0;
            while (i4 <= count) {
                int i5 = (i4 + count) >>> 1;
                int iF = F(t(i5)) & 65535;
                int i6 = 65535 & sA;
                if (j.g(iF, i6) < 0) {
                    i4 = i5 + 1;
                } else {
                    if (j.g(iF, i6) <= 0) {
                        return i5;
                    }
                    count = i5 - 1;
                }
            }
        }
        return -1;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final int t(int i3) {
        return this.f6652c + 8 + (i3 * 12);
    }

    private final int v() {
        return t(getCount());
    }

    private final int w(int i3, a.b bVar) {
        int iS = s(i3);
        if (iS == -1) {
            throw new IllegalArgumentException(("Key not found: " + i3).toString());
        }
        a.b bVarY = y(iS);
        if (bVarY == bVar) {
            return t(iS) + 4;
        }
        throw new IllegalStateException(("Expected " + bVar + " for key: " + i3 + ", found " + bVarY + " instead.").toString());
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final boolean x(int i3) {
        return B(i3) == 1;
    }

    private final a.b y(int i3) {
        return a.b.values()[F(t(i3) + 2) & 65535];
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final double z(int i3) {
        return this.f6651b.getDouble(i3);
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof ReadableMapBuffer)) {
            return false;
        }
        ByteBuffer byteBuffer = this.f6651b;
        ByteBuffer byteBuffer2 = ((ReadableMapBuffer) obj).f6651b;
        if (byteBuffer == byteBuffer2) {
            return true;
        }
        byteBuffer.rewind();
        byteBuffer2.rewind();
        return j.b(byteBuffer, byteBuffer2);
    }

    @Override // com.facebook.react.common.mapbuffer.a
    public boolean g(int i3) {
        return s(i3) != -1;
    }

    @Override // com.facebook.react.common.mapbuffer.a
    public boolean getBoolean(int i3) {
        return x(w(i3, a.b.f6670b));
    }

    @Override // com.facebook.react.common.mapbuffer.a
    public int getCount() {
        return this.f6653d;
    }

    @Override // com.facebook.react.common.mapbuffer.a
    public double getDouble(int i3) {
        return z(w(i3, a.b.f6672d));
    }

    @Override // com.facebook.react.common.mapbuffer.a
    public int getInt(int i3) {
        return B(w(i3, a.b.f6671c));
    }

    @Override // com.facebook.react.common.mapbuffer.a
    public String getString(int i3) {
        return E(w(i3, a.b.f6673e));
    }

    public int hashCode() {
        this.f6651b.rewind();
        return this.f6651b.hashCode();
    }

    @Override // java.lang.Iterable
    public Iterator iterator() {
        return new d();
    }

    public String toString() throws IOException {
        StringBuilder sb = new StringBuilder("{");
        x.G(this, sb, (124 & 2) != 0 ? ", " : null, (124 & 4) != 0 ? "" : null, (124 & 8) == 0 ? null : "", (124 & 16) != 0 ? -1 : 0, (124 & 32) != 0 ? "..." : null, (124 & 64) != 0 ? null : new l() { // from class: g1.a
            @Override // s2.l
            public final Object d(Object obj) {
                return ReadableMapBuffer.G((a.c) obj);
            }
        });
        sb.append('}');
        String string = sb.toString();
        j.e(string, "toString(...)");
        return string;
    }

    @Override // com.facebook.react.common.mapbuffer.a
    /* JADX INFO: renamed from: u, reason: merged with bridge method [inline-methods] */
    public ReadableMapBuffer d(int i3) {
        return D(w(i3, a.b.f6674f));
    }
}
