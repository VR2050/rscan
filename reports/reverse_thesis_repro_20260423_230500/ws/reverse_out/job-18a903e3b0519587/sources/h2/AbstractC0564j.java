package h2;

import java.io.Serializable;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: renamed from: h2.j, reason: case insensitive filesystem */
/* JADX INFO: loaded from: classes.dex */
public abstract class AbstractC0564j implements Serializable {

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    public static final a f9276b = new a(null);

    /* JADX INFO: renamed from: h2.j$a */
    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    /* JADX INFO: renamed from: h2.j$b */
    public static final class b implements Serializable {

        /* JADX INFO: renamed from: b, reason: collision with root package name */
        public final Throwable f9277b;

        public b(Throwable th) {
            t2.j.f(th, "exception");
            this.f9277b = th;
        }

        public boolean equals(Object obj) {
            return (obj instanceof b) && t2.j.b(this.f9277b, ((b) obj).f9277b);
        }

        public int hashCode() {
            return this.f9277b.hashCode();
        }

        public String toString() {
            return "Failure(" + this.f9277b + ')';
        }
    }

    public static final boolean b(Object obj) {
        return obj instanceof b;
    }

    public static Object a(Object obj) {
        return obj;
    }
}
