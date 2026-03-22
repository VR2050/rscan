package p005b.p113c0.p114a.p129k;

import androidx.annotation.NonNull;
import java.util.Objects;
import p005b.p113c0.p114a.InterfaceC1413e;
import p005b.p113c0.p114a.InterfaceC1414f;
import p005b.p113c0.p114a.p129k.AbstractC1487c.a;
import p476m.p477a.p485b.p488j0.p489h.C4820a;
import p476m.p477a.p485b.p488j0.p489h.InterfaceC4822c;

/* renamed from: b.c0.a.k.c */
/* loaded from: classes2.dex */
public abstract class AbstractC1487c<T extends a> implements InterfaceC1414f {

    /* renamed from: a */
    public final int f1483a;

    /* renamed from: b */
    public final int f1484b;

    /* renamed from: c */
    public final InterfaceC1414f.a f1485c;

    /* renamed from: d */
    public C4820a f1486d;

    /* renamed from: e */
    public boolean f1487e;

    /* renamed from: b.c0.a.k.c$a */
    public static abstract class a<T extends a, S extends AbstractC1487c> {

        /* renamed from: a */
        public int f1488a;

        /* renamed from: b */
        public int f1489b;

        /* renamed from: c */
        public InterfaceC1414f.a f1490c;
    }

    /* renamed from: b.c0.a.k.c$b */
    public static final class b implements InterfaceC4822c {
        public b(@NonNull InterfaceC1413e interfaceC1413e) {
        }
    }

    public AbstractC1487c(T t) {
        Objects.requireNonNull(t);
        this.f1483a = t.f1488a;
        this.f1484b = t.f1489b;
        this.f1485c = t.f1490c;
    }
}
