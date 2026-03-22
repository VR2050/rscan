package p005b.p067b.p068a.p069a.p070a.p077l;

import android.view.View;
import android.view.ViewGroup;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;

/* renamed from: b.b.a.a.a.l.a */
/* loaded from: classes.dex */
public abstract class AbstractC1310a {
    /* renamed from: a */
    public void m315a(@NotNull BaseViewHolder holder, @NotNull EnumC1311b loadMoreStatus) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        Intrinsics.checkNotNullParameter(loadMoreStatus, "loadMoreStatus");
        int ordinal = loadMoreStatus.ordinal();
        if (ordinal == 0) {
            m321g(mo319e(holder), false);
            m321g(mo316b(holder), true);
            m321g(mo318d(holder), false);
            m321g(mo317c(holder), false);
            return;
        }
        if (ordinal == 1) {
            m321g(mo319e(holder), true);
            m321g(mo316b(holder), false);
            m321g(mo318d(holder), false);
            m321g(mo317c(holder), false);
            return;
        }
        if (ordinal == 2) {
            m321g(mo319e(holder), false);
            m321g(mo316b(holder), false);
            m321g(mo318d(holder), true);
            m321g(mo317c(holder), false);
            return;
        }
        if (ordinal != 3) {
            return;
        }
        m321g(mo319e(holder), false);
        m321g(mo316b(holder), false);
        m321g(mo318d(holder), false);
        m321g(mo317c(holder), true);
    }

    @NotNull
    /* renamed from: b */
    public abstract View mo316b(@NotNull BaseViewHolder baseViewHolder);

    @NotNull
    /* renamed from: c */
    public abstract View mo317c(@NotNull BaseViewHolder baseViewHolder);

    @NotNull
    /* renamed from: d */
    public abstract View mo318d(@NotNull BaseViewHolder baseViewHolder);

    @NotNull
    /* renamed from: e */
    public abstract View mo319e(@NotNull BaseViewHolder baseViewHolder);

    @NotNull
    /* renamed from: f */
    public abstract View mo320f(@NotNull ViewGroup viewGroup);

    /* renamed from: g */
    public final void m321g(View view, boolean z) {
        view.setVisibility(z ? 0 : 8);
    }
}
