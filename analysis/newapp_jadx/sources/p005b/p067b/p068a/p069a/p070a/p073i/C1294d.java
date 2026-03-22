package p005b.p067b.p068a.p069a.p070a.p073i;

import androidx.annotation.RestrictTo;
import androidx.recyclerview.widget.DiffUtil;
import java.util.concurrent.Executor;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/* renamed from: b.b.a.a.a.i.d */
/* loaded from: classes.dex */
public final class C1294d<T> {

    /* renamed from: a */
    @RestrictTo({RestrictTo.Scope.LIBRARY})
    @Nullable
    public final Executor f1025a;

    /* renamed from: b */
    @NotNull
    public final Executor f1026b;

    /* renamed from: c */
    @NotNull
    public final DiffUtil.ItemCallback<T> f1027c;

    /* renamed from: b.b.a.a.a.i.d$a */
    public static final class a<T> {

        /* renamed from: a */
        @NotNull
        public static final Object f1028a = new Object();

        /* renamed from: b */
        @Nullable
        public static Executor f1029b;

        /* renamed from: c */
        @NotNull
        public final DiffUtil.ItemCallback<T> f1030c;

        /* renamed from: d */
        @Nullable
        public Executor f1031d;

        public a(@NotNull DiffUtil.ItemCallback<T> mDiffCallback) {
            Intrinsics.checkNotNullParameter(mDiffCallback, "mDiffCallback");
            this.f1030c = mDiffCallback;
        }
    }

    public C1294d(@Nullable Executor executor, @NotNull Executor backgroundThreadExecutor, @NotNull DiffUtil.ItemCallback<T> diffCallback) {
        Intrinsics.checkNotNullParameter(backgroundThreadExecutor, "backgroundThreadExecutor");
        Intrinsics.checkNotNullParameter(diffCallback, "diffCallback");
        this.f1025a = null;
        this.f1026b = backgroundThreadExecutor;
        this.f1027c = diffCallback;
    }
}
