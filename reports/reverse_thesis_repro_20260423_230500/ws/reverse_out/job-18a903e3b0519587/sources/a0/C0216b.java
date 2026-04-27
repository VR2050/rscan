package a0;

import java.nio.ByteBuffer;

/* JADX INFO: renamed from: a0.b, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public class C0216b implements q.e {

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    public static final C0216b f2913a = new C0216b();

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private static int f2914b = 16384;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private static final ThreadLocal f2915c = new a();

    /* JADX INFO: renamed from: a0.b$a */
    class a extends ThreadLocal {
        a() {
        }

        /* JADX INFO: Access modifiers changed from: protected */
        @Override // java.lang.ThreadLocal
        /* JADX INFO: renamed from: a, reason: merged with bridge method [inline-methods] */
        public ByteBuffer initialValue() {
            return ByteBuffer.allocate(C0216b.f2914b);
        }
    }

    public static int e() {
        return f2914b;
    }

    @Override // q.e
    /* JADX INFO: renamed from: d, reason: merged with bridge method [inline-methods] */
    public ByteBuffer b() {
        return (ByteBuffer) f2915c.get();
    }

    @Override // q.e
    /* JADX INFO: renamed from: f, reason: merged with bridge method [inline-methods] */
    public boolean a(ByteBuffer byteBuffer) {
        return true;
    }
}
