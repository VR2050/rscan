package C0;

import kotlin.jvm.internal.DefaultConstructorMarker;
import t2.j;

/* JADX INFO: loaded from: classes.dex */
public final class c {

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    public static final a f564c = new a(null);

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    public static final c f565d = new c("UNKNOWN", null);

    /* JADX INFO: renamed from: a, reason: collision with root package name */
    private final String f566a;

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final String f567b;

    public static final class a {
        public /* synthetic */ a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        private a() {
        }
    }

    public interface b {
        int a();

        c b(byte[] bArr, int i3);
    }

    public c(String str, String str2) {
        j.f(str, "name");
        this.f566a = str;
        this.f567b = str2;
    }

    public final String a() {
        return this.f566a;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof c)) {
            return false;
        }
        c cVar = (c) obj;
        return j.b(this.f566a, cVar.f566a) && j.b(this.f567b, cVar.f567b);
    }

    public int hashCode() {
        int iHashCode = this.f566a.hashCode() * 31;
        String str = this.f567b;
        return iHashCode + (str == null ? 0 : str.hashCode());
    }

    public String toString() {
        return this.f566a;
    }
}
