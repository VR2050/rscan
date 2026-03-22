package p379c.p380a;

import java.util.concurrent.atomic.AtomicIntegerFieldUpdater;
import kotlin.jvm.JvmField;
import org.jetbrains.annotations.NotNull;

/* renamed from: c.a.w */
/* loaded from: classes2.dex */
public class C3108w {

    /* renamed from: a */
    public static final AtomicIntegerFieldUpdater f8469a = AtomicIntegerFieldUpdater.newUpdater(C3108w.class, "_handled");
    public volatile int _handled;

    /* renamed from: b */
    @JvmField
    @NotNull
    public final Throwable f8470b;

    public C3108w(@NotNull Throwable th, boolean z) {
        this.f8470b = th;
        this._handled = z ? 1 : 0;
    }

    @NotNull
    public String toString() {
        return getClass().getSimpleName() + '[' + this.f8470b + ']';
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r2v1, types: [int] */
    /* JADX WARN: Type inference failed for: r2v2 */
    /* JADX WARN: Type inference failed for: r2v3 */
    public C3108w(Throwable th, boolean z, int i2) {
        ?? r2 = (i2 & 2) != 0 ? 0 : z;
        this.f8470b = th;
        this._handled = r2;
    }
}
