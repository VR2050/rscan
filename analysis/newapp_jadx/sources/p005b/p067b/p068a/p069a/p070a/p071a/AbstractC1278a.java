package p005b.p067b.p068a.p069a.p070a.p071a;

import androidx.annotation.LayoutRes;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import java.util.ArrayList;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.LazyThreadSafetyMode;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;

/* renamed from: b.b.a.a.a.a.a */
/* loaded from: classes.dex */
public abstract class AbstractC1278a<T> {

    /* renamed from: a */
    @NotNull
    public final Lazy f986a;

    /* renamed from: b */
    @NotNull
    public final Lazy f987b;

    /* renamed from: b.b.a.a.a.a.a$a */
    public static final class a extends Lambda implements Function0<ArrayList<Integer>> {

        /* renamed from: c */
        public static final a f988c = new a(0);

        /* renamed from: e */
        public static final a f989e = new a(1);

        /* renamed from: f */
        public final /* synthetic */ int f990f;

        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
        public a(int i2) {
            super(0);
            this.f990f = i2;
        }

        @Override // kotlin.jvm.functions.Function0
        public final ArrayList<Integer> invoke() {
            int i2 = this.f990f;
            if (i2 == 0) {
                return new ArrayList<>();
            }
            if (i2 == 1) {
                return new ArrayList<>();
            }
            throw null;
        }
    }

    public AbstractC1278a() {
        LazyThreadSafetyMode lazyThreadSafetyMode = LazyThreadSafetyMode.NONE;
        this.f986a = LazyKt__LazyJVMKt.lazy(lazyThreadSafetyMode, (Function0) a.f988c);
        this.f987b = LazyKt__LazyJVMKt.lazy(lazyThreadSafetyMode, (Function0) a.f989e);
    }

    /* renamed from: a */
    public abstract void m305a(@NotNull BaseViewHolder baseViewHolder, T t);

    @LayoutRes
    /* renamed from: b */
    public abstract int m306b();
}
