package w2;

import i2.C;
import kotlin.jvm.internal.DefaultConstructorMarker;

/* JADX INFO: loaded from: classes.dex */
public class a implements Iterable {

    /* JADX INFO: renamed from: e, reason: collision with root package name */
    public static final C0155a f10297e = new C0155a(null);

    /* JADX INFO: renamed from: b, reason: collision with root package name */
    private final int f10298b;

    /* JADX INFO: renamed from: c, reason: collision with root package name */
    private final int f10299c;

    /* JADX INFO: renamed from: d, reason: collision with root package name */
    private final int f10300d;

    /* JADX INFO: renamed from: w2.a$a, reason: collision with other inner class name */
    public static final class C0155a {
        public /* synthetic */ C0155a(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public final a a(int i3, int i4, int i5) {
            return new a(i3, i4, i5);
        }

        private C0155a() {
        }
    }

    public a(int i3, int i4, int i5) {
        if (i5 == 0) {
            throw new IllegalArgumentException("Step must be non-zero.");
        }
        if (i5 == Integer.MIN_VALUE) {
            throw new IllegalArgumentException("Step must be greater than Int.MIN_VALUE to avoid overflow on negation.");
        }
        this.f10298b = i3;
        this.f10299c = n2.c.b(i3, i4, i5);
        this.f10300d = i5;
    }

    public final int a() {
        return this.f10298b;
    }

    public final int b() {
        return this.f10299c;
    }

    public final int c() {
        return this.f10300d;
    }

    @Override // java.lang.Iterable
    /* JADX INFO: renamed from: e, reason: merged with bridge method [inline-methods] */
    public C iterator() {
        return new b(this.f10298b, this.f10299c, this.f10300d);
    }

    public boolean equals(Object obj) {
        if (obj instanceof a) {
            if (!isEmpty() || !((a) obj).isEmpty()) {
                a aVar = (a) obj;
                if (this.f10298b != aVar.f10298b || this.f10299c != aVar.f10299c || this.f10300d != aVar.f10300d) {
                }
            }
            return true;
        }
        return false;
    }

    public int hashCode() {
        if (isEmpty()) {
            return -1;
        }
        return (((this.f10298b * 31) + this.f10299c) * 31) + this.f10300d;
    }

    public boolean isEmpty() {
        if (this.f10300d > 0) {
            if (this.f10298b <= this.f10299c) {
                return false;
            }
        } else if (this.f10298b >= this.f10299c) {
            return false;
        }
        return true;
    }

    public String toString() {
        StringBuilder sb;
        int i3;
        if (this.f10300d > 0) {
            sb = new StringBuilder();
            sb.append(this.f10298b);
            sb.append("..");
            sb.append(this.f10299c);
            sb.append(" step ");
            i3 = this.f10300d;
        } else {
            sb = new StringBuilder();
            sb.append(this.f10298b);
            sb.append(" downTo ");
            sb.append(this.f10299c);
            sb.append(" step ");
            i3 = -this.f10300d;
        }
        sb.append(i3);
        return sb.toString();
    }
}
