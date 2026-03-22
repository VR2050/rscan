package p429g.p433b.p434a.p437c;

/* renamed from: g.b.a.c.b */
/* loaded from: classes2.dex */
public final class C4338b extends RuntimeException {
    private static final long serialVersionUID = -6298857009889503852L;

    public C4338b(Throwable th) {
        super("The exception was not handled due to missing onError handler in the subscribe() method call. Further reading: https://github.com/ReactiveX/RxJava/wiki/Error-Handling | " + th, th == null ? new NullPointerException() : th);
    }
}
