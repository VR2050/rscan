package p005b.p143g.p144a.p147m.p156v.p158d;

import androidx.annotation.NonNull;
import java.nio.ByteBuffer;
import p005b.p143g.p144a.p147m.p148s.InterfaceC1591e;

/* renamed from: b.g.a.m.v.d.a */
/* loaded from: classes.dex */
public class C1722a implements InterfaceC1591e<ByteBuffer> {

    /* renamed from: a */
    public final ByteBuffer f2550a;

    /* renamed from: b.g.a.m.v.d.a$a */
    public static class a implements InterfaceC1591e.a<ByteBuffer> {
        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1591e.a
        @NonNull
        /* renamed from: a */
        public Class<ByteBuffer> mo843a() {
            return ByteBuffer.class;
        }

        @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1591e.a
        @NonNull
        /* renamed from: b */
        public InterfaceC1591e<ByteBuffer> mo844b(ByteBuffer byteBuffer) {
            return new C1722a(byteBuffer);
        }
    }

    public C1722a(ByteBuffer byteBuffer) {
        this.f2550a = byteBuffer;
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1591e
    @NonNull
    /* renamed from: a */
    public ByteBuffer mo841a() {
        this.f2550a.position(0);
        return this.f2550a;
    }

    @Override // p005b.p143g.p144a.p147m.p148s.InterfaceC1591e
    /* renamed from: b */
    public void mo842b() {
    }
}
