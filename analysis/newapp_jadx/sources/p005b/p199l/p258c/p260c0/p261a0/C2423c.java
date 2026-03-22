package p005b.p199l.p258c.p260c0.p261a0;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.ParsePosition;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p199l.p258c.AbstractC2496z;
import p005b.p199l.p258c.C2480j;
import p005b.p199l.p258c.C2493w;
import p005b.p199l.p258c.InterfaceC2415a0;
import p005b.p199l.p258c.p260c0.C2458p;
import p005b.p199l.p258c.p260c0.p261a0.p262t.C2440a;
import p005b.p199l.p258c.p264d0.C2470a;
import p005b.p199l.p258c.p265e0.C2472a;
import p005b.p199l.p258c.p265e0.C2474c;
import p005b.p199l.p258c.p265e0.EnumC2473b;

/* renamed from: b.l.c.c0.a0.c */
/* loaded from: classes2.dex */
public final class C2423c extends AbstractC2496z<Date> {

    /* renamed from: a */
    public static final InterfaceC2415a0 f6465a = new a();

    /* renamed from: b */
    public final List<DateFormat> f6466b;

    /* renamed from: b.l.c.c0.a0.c$a */
    public static class a implements InterfaceC2415a0 {
        @Override // p005b.p199l.p258c.InterfaceC2415a0
        /* renamed from: a */
        public <T> AbstractC2496z<T> mo2753a(C2480j c2480j, C2470a<T> c2470a) {
            if (c2470a.getRawType() == Date.class) {
                return new C2423c();
            }
            return null;
        }
    }

    public C2423c() {
        ArrayList arrayList = new ArrayList();
        this.f6466b = arrayList;
        Locale locale = Locale.US;
        arrayList.add(DateFormat.getDateTimeInstance(2, 2, locale));
        if (!Locale.getDefault().equals(locale)) {
            arrayList.add(DateFormat.getDateTimeInstance(2, 2));
        }
        if (C2458p.f6607a >= 9) {
            arrayList.add(C2354n.m2507q0(2, 2));
        }
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: b */
    public Date mo2766b(C2472a c2472a) {
        if (c2472a.mo2777Z() == EnumC2473b.NULL) {
            c2472a.mo2775V();
            return null;
        }
        String mo2776X = c2472a.mo2776X();
        synchronized (this) {
            Iterator<DateFormat> it = this.f6466b.iterator();
            while (it.hasNext()) {
                try {
                    return it.next().parse(mo2776X);
                } catch (ParseException unused) {
                }
            }
            try {
                return C2440a.m2808b(mo2776X, new ParsePosition(0));
            } catch (ParseException e2) {
                throw new C2493w(mo2776X, e2);
            }
        }
    }

    @Override // p005b.p199l.p258c.AbstractC2496z
    /* renamed from: c */
    public void mo2767c(C2474c c2474c, Date date) {
        Date date2 = date;
        synchronized (this) {
            if (date2 == null) {
                c2474c.mo2800v();
            } else {
                c2474c.mo2791V(this.f6466b.get(0).format(date2));
            }
        }
    }
}
