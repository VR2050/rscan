package p005b.p199l.p258c.p260c0.p261a0;

import java.sql.Time;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.C2493w;
import p005b.p199l.p258c.InterfaceC2415a0;
import p005b.p199l.p258c.p264d0.C2470a;
import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.C2474c;
import p005b.p199l.p258c.p265e0.EnumC2473b;

/* renamed from: b.l.c.c0.a0.l */
/* loaded from: classes2.dex */
public final class C2432l extends AbstractC2496z<Time> {

    /* renamed from: a */
    public static final InterfaceC2415a0 f6504a = new a();

    /* renamed from: b */
    public final DateFormat f6505b = new SimpleDateFormat("hh:mm:ss a");

    /* renamed from: b.l.c.c0.a0.l$a */
    public static class a implements InterfaceC2415a0 {
        @Override // p005b.p199l.p258c.InterfaceC2415a0
        /* renamed from: a */
        public <T> AbstractC2496z<T> mo2753a(C2480j c2480j, C2470a<T> c2470a) {
            if (c2470a.getRawType() == Time.class) {
                return new C2432l();
            }
            return null;
        }
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: b */
    public Time mo2766b(C2472a c2472a) {
        synchronized (this) {
            if (c2472a.mo2777Z() == EnumC2473b.NULL) {
                c2472a.mo2775V();
                return null;
            }
            try {
                return new Time(this.f6505b.parse(c2472a.mo2776X()).getTime());
            } catch (ParseException e2) {
                throw new C2493w(e2);
            }
        }
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: c */
    public void mo2767c(C2474c c2474c, Time time) {
        Time time2 = time;
        synchronized (this) {
            c2474c.mo2791V(time2 == null ? null : this.f6505b.format((Date) time2));
        }
    }
}
