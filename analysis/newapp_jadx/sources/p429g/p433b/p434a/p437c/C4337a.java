package p429g.p433b.p434a.p437c;

import java.io.PrintStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;

/* renamed from: g.b.a.c.a */
/* loaded from: classes2.dex */
public final class C4337a extends RuntimeException {
    private static final long serialVersionUID = 3026362227162912146L;

    /* renamed from: c */
    public final List<Throwable> f11189c;

    /* renamed from: e */
    public final String f11190e;

    /* renamed from: f */
    public Throwable f11191f;

    /* renamed from: g.b.a.c.a$a */
    public static final class a extends RuntimeException {
        private static final long serialVersionUID = 3875212506787802066L;

        public a(String str) {
            super(str);
        }

        @Override // java.lang.Throwable
        public synchronized Throwable fillInStackTrace() {
            return this;
        }
    }

    /* renamed from: g.b.a.c.a$b */
    public static abstract class b {
        /* renamed from: a */
        public abstract void mo4913a(Object obj);
    }

    /* renamed from: g.b.a.c.a$c */
    public static final class c extends b {

        /* renamed from: a */
        public final PrintStream f11192a;

        public c(PrintStream printStream) {
            this.f11192a = printStream;
        }

        @Override // p429g.p433b.p434a.p437c.C4337a.b
        /* renamed from: a */
        public void mo4913a(Object obj) {
            this.f11192a.println(obj);
        }
    }

    /* renamed from: g.b.a.c.a$d */
    public static final class d extends b {

        /* renamed from: a */
        public final PrintWriter f11193a;

        public d(PrintWriter printWriter) {
            this.f11193a = printWriter;
        }

        @Override // p429g.p433b.p434a.p437c.C4337a.b
        /* renamed from: a */
        public void mo4913a(Object obj) {
            this.f11193a.println(obj);
        }
    }

    public C4337a(Throwable... thArr) {
        List<Throwable> asList = Arrays.asList(thArr);
        LinkedHashSet linkedHashSet = new LinkedHashSet();
        if (asList != null) {
            for (Throwable th : asList) {
                if (th instanceof C4337a) {
                    linkedHashSet.addAll(((C4337a) th).f11189c);
                } else if (th != null) {
                    linkedHashSet.add(th);
                } else {
                    linkedHashSet.add(new NullPointerException("Throwable was null!"));
                }
            }
        } else {
            linkedHashSet.add(new NullPointerException("errors was null"));
        }
        if (linkedHashSet.isEmpty()) {
            throw new IllegalArgumentException("errors is empty");
        }
        List<Throwable> unmodifiableList = Collections.unmodifiableList(new ArrayList(linkedHashSet));
        this.f11189c = unmodifiableList;
        this.f11190e = unmodifiableList.size() + " exceptions occurred. ";
    }

    /* renamed from: a */
    public final void m4911a(StringBuilder sb, Throwable th, String str) {
        sb.append(str);
        sb.append(th);
        sb.append('\n');
        for (StackTraceElement stackTraceElement : th.getStackTrace()) {
            sb.append("\t\tat ");
            sb.append(stackTraceElement);
            sb.append('\n');
        }
        if (th.getCause() != null) {
            sb.append("\tCaused by: ");
            m4911a(sb, th.getCause(), "");
        }
    }

    /* renamed from: b */
    public final void m4912b(b bVar) {
        StringBuilder sb = new StringBuilder(128);
        sb.append(this);
        sb.append('\n');
        for (StackTraceElement stackTraceElement : getStackTrace()) {
            sb.append("\tat ");
            sb.append(stackTraceElement);
            sb.append('\n');
        }
        int i2 = 1;
        for (Throwable th : this.f11189c) {
            sb.append("  ComposedException ");
            sb.append(i2);
            sb.append(" :\n");
            m4911a(sb, th, "\t");
            i2++;
        }
        bVar.mo4913a(sb.toString());
    }

    @Override // java.lang.Throwable
    public synchronized Throwable getCause() {
        int i2;
        if (this.f11191f == null) {
            String property = System.getProperty("line.separator");
            if (this.f11189c.size() > 1) {
                IdentityHashMap identityHashMap = new IdentityHashMap();
                StringBuilder sb = new StringBuilder();
                sb.append("Multiple exceptions (");
                sb.append(this.f11189c.size());
                sb.append(ChineseToPinyinResource.Field.RIGHT_BRACKET);
                sb.append(property);
                for (Throwable th : this.f11189c) {
                    int i3 = 0;
                    while (true) {
                        if (th != null) {
                            for (int i4 = 0; i4 < i3; i4++) {
                                sb.append("  ");
                            }
                            sb.append("|-- ");
                            sb.append(th.getClass().getCanonicalName());
                            sb.append(": ");
                            String message = th.getMessage();
                            if (message == null || !message.contains(property)) {
                                sb.append(message);
                                sb.append(property);
                            } else {
                                sb.append(property);
                                for (String str : message.split(property)) {
                                    for (int i5 = 0; i5 < i3 + 2; i5++) {
                                        sb.append("  ");
                                    }
                                    sb.append(str);
                                    sb.append(property);
                                }
                            }
                            int i6 = 0;
                            while (true) {
                                i2 = i3 + 2;
                                if (i6 >= i2) {
                                    break;
                                }
                                sb.append("  ");
                                i6++;
                            }
                            StackTraceElement[] stackTrace = th.getStackTrace();
                            if (stackTrace.length > 0) {
                                sb.append("at ");
                                sb.append(stackTrace[0]);
                                sb.append(property);
                            }
                            if (identityHashMap.containsKey(th)) {
                                Throwable cause = th.getCause();
                                if (cause != null) {
                                    for (int i7 = 0; i7 < i2; i7++) {
                                        sb.append("  ");
                                    }
                                    sb.append("|-- ");
                                    sb.append("(cause not expanded again) ");
                                    sb.append(cause.getClass().getCanonicalName());
                                    sb.append(": ");
                                    sb.append(cause.getMessage());
                                    sb.append(property);
                                }
                            } else {
                                identityHashMap.put(th, Boolean.TRUE);
                                th = th.getCause();
                                i3++;
                            }
                        }
                    }
                }
                this.f11191f = new a(sb.toString().trim());
            } else {
                this.f11191f = this.f11189c.get(0);
            }
        }
        return this.f11191f;
    }

    @Override // java.lang.Throwable
    public String getMessage() {
        return this.f11190e;
    }

    @Override // java.lang.Throwable
    public void printStackTrace() {
        printStackTrace(System.err);
    }

    @Override // java.lang.Throwable
    public void printStackTrace(PrintStream printStream) {
        m4912b(new c(printStream));
    }

    @Override // java.lang.Throwable
    public void printStackTrace(PrintWriter printWriter) {
        m4912b(new d(printWriter));
    }
}
