package com.facebook.react.bridge;

import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public final class ReactIgnorableMountingException extends RuntimeException {
    public static final Companion Companion = new Companion(null);

    public static final class Companion {
        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final boolean isIgnorable(Throwable th) {
            t2.j.f(th, "e");
            while (th != null) {
                if (th instanceof ReactIgnorableMountingException) {
                    return true;
                }
                th = th.getCause();
            }
            return false;
        }

        private Companion() {
        }
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReactIgnorableMountingException(String str) {
        super(str);
        t2.j.f(str, "m");
    }

    public static final boolean isIgnorable(Throwable th) {
        return Companion.isIgnorable(th);
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReactIgnorableMountingException(Throwable th) {
        super(th);
        t2.j.f(th, "e");
    }

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ReactIgnorableMountingException(String str, Throwable th) {
        super(str, th);
        t2.j.f(str, "m");
        t2.j.f(th, "e");
    }
}
