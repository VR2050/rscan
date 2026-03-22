package p005b.p199l.p200a.p201a.p220h1.p221g;

import com.google.android.exoplayer2.metadata.Metadata;
import com.google.android.exoplayer2.metadata.emsg.EventMessage;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;
import p005b.p199l.p200a.p201a.p220h1.C2081d;
import p005b.p199l.p200a.p201a.p220h1.InterfaceC2079b;
import p005b.p199l.p200a.p201a.p250p1.C2360t;

/* renamed from: b.l.a.a.h1.g.a */
/* loaded from: classes.dex */
public final class C2084a implements InterfaceC2079b {
    @Override // p005b.p199l.p200a.p201a.p220h1.InterfaceC2079b
    /* renamed from: a */
    public Metadata mo1705a(C2081d c2081d) {
        ByteBuffer byteBuffer = c2081d.f3306e;
        Objects.requireNonNull(byteBuffer);
        return new Metadata(m1709b(new C2360t(byteBuffer.array(), byteBuffer.limit())));
    }

    /* renamed from: b */
    public EventMessage m1709b(C2360t c2360t) {
        String m2580l = c2360t.m2580l();
        Objects.requireNonNull(m2580l);
        String m2580l2 = c2360t.m2580l();
        Objects.requireNonNull(m2580l2);
        return new EventMessage(m2580l, m2580l2, c2360t.m2586r(), c2360t.m2586r(), Arrays.copyOfRange(c2360t.f6133a, c2360t.f6134b, c2360t.f6135c));
    }
}
