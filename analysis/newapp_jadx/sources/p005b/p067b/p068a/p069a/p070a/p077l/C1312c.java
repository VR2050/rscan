package p005b.p067b.p068a.p069a.p070a.p077l;

import android.view.View;
import android.view.ViewGroup;
import com.chad.library.R$id;
import com.chad.library.R$layout;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p403d.p404a.p405a.p407b.p408a.C4195m;

/* renamed from: b.b.a.a.a.l.c */
/* loaded from: classes.dex */
public final class C1312c extends AbstractC1310a {
    @Override // p005b.p067b.p068a.p069a.p070a.p077l.AbstractC1310a
    @NotNull
    /* renamed from: b */
    public View mo316b(@NotNull BaseViewHolder holder) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        return holder.m3912b(R$id.load_more_load_complete_view);
    }

    @Override // p005b.p067b.p068a.p069a.p070a.p077l.AbstractC1310a
    @NotNull
    /* renamed from: c */
    public View mo317c(@NotNull BaseViewHolder holder) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        return holder.m3912b(R$id.load_more_load_end_view);
    }

    @Override // p005b.p067b.p068a.p069a.p070a.p077l.AbstractC1310a
    @NotNull
    /* renamed from: d */
    public View mo318d(@NotNull BaseViewHolder holder) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        return holder.m3912b(R$id.load_more_load_fail_view);
    }

    @Override // p005b.p067b.p068a.p069a.p070a.p077l.AbstractC1310a
    @NotNull
    /* renamed from: e */
    public View mo319e(@NotNull BaseViewHolder holder) {
        Intrinsics.checkNotNullParameter(holder, "holder");
        return holder.m3912b(R$id.load_more_loading_view);
    }

    @Override // p005b.p067b.p068a.p069a.p070a.p077l.AbstractC1310a
    @NotNull
    /* renamed from: f */
    public View mo320f(@NotNull ViewGroup parent) {
        Intrinsics.checkNotNullParameter(parent, "parent");
        return C4195m.m4803e0(parent, R$layout.brvah_quick_view_load_more);
    }
}
