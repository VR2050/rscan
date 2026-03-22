package p005b.p199l.p200a.p201a.p204c1;

import androidx.annotation.Nullable;
import java.nio.ByteBuffer;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.checkerframework.checker.nullness.qual.EnsuresNonNull;

/* renamed from: b.l.a.a.c1.e */
/* loaded from: classes.dex */
public class C1945e extends AbstractC1941a {

    /* renamed from: c */
    public final C1942b f3305c = new C1942b();

    /* renamed from: e */
    @Nullable
    public ByteBuffer f3306e;

    /* renamed from: f */
    public long f3307f;

    /* renamed from: g */
    @Nullable
    public ByteBuffer f3308g;

    /* renamed from: h */
    public final int f3309h;

    public C1945e(int i2) {
        this.f3309h = i2;
    }

    @Override // p005b.p199l.p200a.p201a.p204c1.AbstractC1941a
    public void clear() {
        super.clear();
        ByteBuffer byteBuffer = this.f3306e;
        if (byteBuffer != null) {
            byteBuffer.clear();
        }
        ByteBuffer byteBuffer2 = this.f3308g;
        if (byteBuffer2 != null) {
            byteBuffer2.clear();
        }
    }

    /* renamed from: e */
    public final ByteBuffer m1380e(int i2) {
        int i3 = this.f3309h;
        if (i3 == 1) {
            return ByteBuffer.allocate(i2);
        }
        if (i3 == 2) {
            return ByteBuffer.allocateDirect(i2);
        }
        ByteBuffer byteBuffer = this.f3306e;
        throw new IllegalStateException("Buffer too small (" + (byteBuffer == null ? 0 : byteBuffer.capacity()) + " < " + i2 + ChineseToPinyinResource.Field.RIGHT_BRACKET);
    }

    @EnsuresNonNull({"data"})
    /* renamed from: f */
    public void m1381f(int i2) {
        ByteBuffer byteBuffer = this.f3306e;
        if (byteBuffer == null) {
            this.f3306e = m1380e(i2);
            return;
        }
        int capacity = byteBuffer.capacity();
        int position = this.f3306e.position();
        int i3 = i2 + position;
        if (capacity >= i3) {
            return;
        }
        ByteBuffer m1380e = m1380e(i3);
        if (position > 0) {
            this.f3306e.flip();
            m1380e.put(this.f3306e);
        }
        this.f3306e = m1380e;
    }

    /* renamed from: g */
    public final void m1382g() {
        this.f3306e.flip();
        ByteBuffer byteBuffer = this.f3308g;
        if (byteBuffer != null) {
            byteBuffer.flip();
        }
    }
}
