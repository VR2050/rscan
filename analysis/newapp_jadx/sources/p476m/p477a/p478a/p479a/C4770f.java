package p476m.p477a.p478a.p479a;

import java.io.PrintStream;
import java.io.PrintWriter;

/* renamed from: m.a.a.a.f */
/* loaded from: classes3.dex */
public class C4770f extends Exception {
    private static final long serialVersionUID = 8881893724388807504L;

    /* renamed from: c */
    public final Throwable f12204c;

    public C4770f(String str) {
        super(str);
        this.f12204c = null;
    }

    @Override // java.lang.Throwable
    public Throwable getCause() {
        return this.f12204c;
    }

    @Override // java.lang.Throwable
    public void printStackTrace(PrintStream printStream) {
        super.printStackTrace(printStream);
        if (this.f12204c != null) {
            printStream.println("Caused by:");
            this.f12204c.printStackTrace(printStream);
        }
    }

    public C4770f(String str, Throwable th) {
        super(str);
        this.f12204c = th;
    }

    @Override // java.lang.Throwable
    public void printStackTrace(PrintWriter printWriter) {
        super.printStackTrace(printWriter);
        if (this.f12204c != null) {
            printWriter.println("Caused by:");
            this.f12204c.printStackTrace(printWriter);
        }
    }
}
