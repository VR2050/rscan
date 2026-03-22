package p005b.p199l.p258c.p260c0.p261a0;

import java.sql.Date;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.C2493w;
import p005b.p199l.p258c.InterfaceC2415a0;
import p005b.p199l.p258c.p264d0.C2470a;
import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.C2474c;
import p005b.p199l.p258c.p265e0.EnumC2473b;

/* renamed from: b.l.c.c0.a0.k */
/* loaded from: classes2.dex */
public final class C2431k extends AbstractC2496z<Date> {

    /* renamed from: a */
    public static final InterfaceC2415a0 f6502a = new a();

    /* renamed from: b */
    public final DateFormat f6503b = new SimpleDateFormat("MMM d, yyyy");

    /* renamed from: b.l.c.c0.a0.k$a */
    public static class a implements InterfaceC2415a0 {
        @Override // p005b.p199l.p258c.InterfaceC2415a0
        /* renamed from: a */
        public <T> AbstractC2496z<T> mo2753a(C2480j c2480j, C2470a<T> c2470a) {
            if (c2470a.getRawType() == Date.class) {
                return new C2431k();
            }
            return null;
        }
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: b */
    public Date mo2766b(C2472a c2472a) {
        Date date;
        synchronized (this) {
            if (c2472a.mo2777Z() == EnumC2473b.NULL) {
                c2472a.mo2775V();
                date = null;
            } else {
                try {
                    date = new Date(this.f6503b.parse(c2472a.mo2776X()).getTime());
                } catch (ParseException e2) {
                    throw new C2493w(e2);
                }
            }
        }
        return date;
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: c */
    public void mo2767c(C2474c c2474c, Date date) {
        Date date2 = date;
        synchronized (this) {
            c2474c.mo2791V(date2 == null ? null : this.f6503b.format((java.util.Date) date2));
        }
    }
}
