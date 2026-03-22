package p005b.p143g.p144a.p147m.p150t;

import androidx.annotation.Nullable;
import java.io.IOException;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p143g.p144a.p147m.EnumC1569a;
import p005b.p143g.p144a.p147m.InterfaceC1579k;

/* renamed from: b.g.a.m.t.r */
/* loaded from: classes.dex */
public final class C1650r extends Exception {

    /* renamed from: c */
    public static final StackTraceElement[] f2300c = new StackTraceElement[0];
    private static final long serialVersionUID = 1;

    /* renamed from: e */
    public final List<Throwable> f2301e;

    /* renamed from: f */
    public InterfaceC1579k f2302f;

    /* renamed from: g */
    public EnumC1569a f2303g;

    /* renamed from: h */
    public Class<?> f2304h;

    /* renamed from: i */
    public String f2305i;

    public C1650r(String str) {
        List<Throwable> emptyList = Collections.emptyList();
        this.f2305i = str;
        setStackTrace(f2300c);
        this.f2301e = emptyList;
    }

    /* renamed from: b */
    public static void m950b(List<Throwable> list, Appendable appendable) {
        try {
            m951c(list, appendable);
        } catch (IOException e2) {
            throw new RuntimeException(e2);
        }
    }

    /* renamed from: c */
    public static void m951c(List<Throwable> list, Appendable appendable) {
        int size = list.size();
        int i2 = 0;
        while (i2 < size) {
            int i3 = i2 + 1;
            appendable.append("Cause (").append(String.valueOf(i3)).append(" of ").append(String.valueOf(size)).append("): ");
            Throwable th = list.get(i2);
            if (th instanceof C1650r) {
                ((C1650r) th).m954e(appendable);
            } else {
                m952d(th, appendable);
            }
            i2 = i3;
        }
    }

    /* renamed from: d */
    public static void m952d(Throwable th, Appendable appendable) {
        try {
            appendable.append(th.getClass().toString()).append(": ").append(th.getMessage()).append('\n');
        } catch (IOException unused) {
            throw new RuntimeException(th);
        }
    }

    /* renamed from: a */
    public final void m953a(Throwable th, List<Throwable> list) {
        if (!(th instanceof C1650r)) {
            list.add(th);
            return;
        }
        Iterator<Throwable> it = ((C1650r) th).f2301e.iterator();
        while (it.hasNext()) {
            m953a(it.next(), list);
        }
    }

    /* renamed from: e */
    public final void m954e(Appendable appendable) {
        m952d(this, appendable);
        m950b(this.f2301e, new a(appendable));
    }

    @Override // java.lang.Throwable
    public Throwable fillInStackTrace() {
        return this;
    }

    @Override // java.lang.Throwable
    public String getMessage() {
        String str;
        String str2;
        StringBuilder sb = new StringBuilder(71);
        sb.append(this.f2305i);
        String str3 = "";
        if (this.f2304h != null) {
            StringBuilder m586H = C1499a.m586H(", ");
            m586H.append(this.f2304h);
            str = m586H.toString();
        } else {
            str = "";
        }
        sb.append(str);
        if (this.f2303g != null) {
            StringBuilder m586H2 = C1499a.m586H(", ");
            m586H2.append(this.f2303g);
            str2 = m586H2.toString();
        } else {
            str2 = "";
        }
        sb.append(str2);
        if (this.f2302f != null) {
            StringBuilder m586H3 = C1499a.m586H(", ");
            m586H3.append(this.f2302f);
            str3 = m586H3.toString();
        }
        sb.append(str3);
        ArrayList arrayList = new ArrayList();
        m953a(this, arrayList);
        if (arrayList.isEmpty()) {
            return sb.toString();
        }
        if (arrayList.size() == 1) {
            sb.append("\nThere was 1 cause:");
        } else {
            sb.append("\nThere were ");
            sb.append(arrayList.size());
            sb.append(" causes:");
        }
        Iterator it = arrayList.iterator();
        while (it.hasNext()) {
            Throwable th = (Throwable) it.next();
            sb.append('\n');
            sb.append(th.getClass().getName());
            sb.append('(');
            sb.append(th.getMessage());
            sb.append(')');
        }
        sb.append("\n call GlideException#logRootCauses(String) for more detail");
        return sb.toString();
    }

    @Override // java.lang.Throwable
    public void printStackTrace() {
        m954e(System.err);
    }

    @Override // java.lang.Throwable
    public void printStackTrace(PrintStream printStream) {
        m954e(printStream);
    }

    @Override // java.lang.Throwable
    public void printStackTrace(PrintWriter printWriter) {
        m954e(printWriter);
    }

    /* renamed from: b.g.a.m.t.r$a */
    public static final class a implements Appendable {

        /* renamed from: c */
        public final Appendable f2306c;

        /* renamed from: e */
        public boolean f2307e = true;

        public a(Appendable appendable) {
            this.f2306c = appendable;
        }

        @Override // java.lang.Appendable
        public Appendable append(char c2) {
            if (this.f2307e) {
                this.f2307e = false;
                this.f2306c.append("  ");
            }
            this.f2307e = c2 == '\n';
            this.f2306c.append(c2);
            return this;
        }

        @Override // java.lang.Appendable
        public Appendable append(@Nullable CharSequence charSequence) {
            if (charSequence == null) {
                charSequence = "";
            }
            append(charSequence, 0, charSequence.length());
            return this;
        }

        @Override // java.lang.Appendable
        public Appendable append(@Nullable CharSequence charSequence, int i2, int i3) {
            if (charSequence == null) {
                charSequence = "";
            }
            boolean z = false;
            if (this.f2307e) {
                this.f2307e = false;
                this.f2306c.append("  ");
            }
            if (charSequence.length() > 0 && charSequence.charAt(i3 - 1) == '\n') {
                z = true;
            }
            this.f2307e = z;
            this.f2306c.append(charSequence, i2, i3);
            return this;
        }
    }

    public C1650r(String str, Throwable th) {
        List<Throwable> singletonList = Collections.singletonList(th);
        this.f2305i = str;
        setStackTrace(f2300c);
        this.f2301e = singletonList;
    }

    public C1650r(String str, List<Throwable> list) {
        this.f2305i = str;
        setStackTrace(f2300c);
        this.f2301e = list;
    }
}
