package com.jbzd.media.movecartoons.utils;

import android.widget.ImageView;
import androidx.lifecycle.Lifecycle;
import androidx.lifecycle.LifecycleObserver;
import androidx.lifecycle.OnLifecycleEvent;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0842e;
import p005b.p006a.p007a.p008a.p009a.C0878z;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000*\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0005\u0018\u00002\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020\u00030\u00012\u00020\u0004B\u0007¢\u0006\u0004\b\u0013\u0010\fJ\u0017\u0010\b\u001a\u00020\u00072\u0006\u0010\u0006\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\b\u0010\tJ\u0017\u0010\n\u001a\u00020\u00072\u0006\u0010\u0006\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\n\u0010\tJ\u000f\u0010\u000b\u001a\u00020\u0007H\u0007¢\u0006\u0004\b\u000b\u0010\fJ\u000f\u0010\r\u001a\u00020\u0007H\u0007¢\u0006\u0004\b\r\u0010\fJ\u000f\u0010\u000e\u001a\u00020\u0007H\u0007¢\u0006\u0004\b\u000e\u0010\fR\u0018\u0010\u0012\u001a\u0004\u0018\u00010\u000f8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u0010\u0010\u0011¨\u0006\u0014"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/utils/MyAdAdapter;", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "Lcom/jbzd/media/movecartoons/bean/response/home/AdBean;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "Landroidx/lifecycle/LifecycleObserver;", "Landroidx/recyclerview/widget/RecyclerView;", "recyclerView", "", "onAttachedToRecyclerView", "(Landroidx/recyclerview/widget/RecyclerView;)V", "onDetachedFromRecyclerView", "onPause", "()V", "onStop", "onResume", "Lb/a/a/a/a/e;", "c", "Lb/a/a/a/a/e;", "autoScrollHelper", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class MyAdAdapter extends BaseQuickAdapter<AdBean, BaseViewHolder> implements LifecycleObserver {

    /* renamed from: c, reason: from kotlin metadata */
    @Nullable
    public C0842e autoScrollHelper;

    public MyAdAdapter() {
        super(R.layout.item_banner_ad, null, 2, null);
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter
    public void convert(BaseViewHolder holder, AdBean adBean) {
        AdBean item = adBean;
        Intrinsics.checkNotNullParameter(holder, "holder");
        Intrinsics.checkNotNullParameter(item, "item");
        C2354n.m2455a2(getContext()).m3298p(item.content).m3293g0(5).m757R((ImageView) holder.m3912b(R.id.iv_ad));
        holder.m3919i(R.id.tv_ad_title, item.name);
        C2354n.m2377B(holder.itemView, 0L, new C0878z(this, item), 1);
    }

    @Override // com.chad.library.adapter.base.BaseQuickAdapter, androidx.recyclerview.widget.RecyclerView.Adapter
    public void onAttachedToRecyclerView(@NotNull RecyclerView recyclerView) {
        Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
        super.onAttachedToRecyclerView(recyclerView);
        final C0842e c0842e = new C0842e(recyclerView, 1000L);
        this.autoScrollHelper = c0842e;
        if (c0842e == null) {
            return;
        }
        c0842e.f237a.addOnScrollListener(new RecyclerView.OnScrollListener() { // from class: com.jbzd.media.movecartoons.utils.AutoScrollHelper$attach$1
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrollStateChanged(@NotNull RecyclerView rv, int newState) {
                Intrinsics.checkNotNullParameter(rv, "rv");
                C0842e c0842e2 = C0842e.this;
                boolean z = newState != 0;
                c0842e2.f241e = z;
                if (z) {
                    c0842e2.m181b();
                } else {
                    c0842e2.m180a();
                }
            }
        });
        c0842e.m180a();
    }

    @Override // androidx.recyclerview.widget.RecyclerView.Adapter
    public void onDetachedFromRecyclerView(@NotNull RecyclerView recyclerView) {
        Intrinsics.checkNotNullParameter(recyclerView, "recyclerView");
        super.onDetachedFromRecyclerView(recyclerView);
        C0842e c0842e = this.autoScrollHelper;
        if (c0842e != null) {
            c0842e.m181b();
            c0842e.f237a.clearOnScrollListeners();
        }
        this.autoScrollHelper = null;
    }

    @OnLifecycleEvent(Lifecycle.Event.ON_PAUSE)
    public final void onPause() {
        C0842e c0842e = this.autoScrollHelper;
        if (c0842e == null) {
            return;
        }
        c0842e.m181b();
    }

    @OnLifecycleEvent(Lifecycle.Event.ON_RESUME)
    public final void onResume() {
        C0842e c0842e = this.autoScrollHelper;
        if (c0842e == null) {
            return;
        }
        c0842e.m180a();
    }

    @OnLifecycleEvent(Lifecycle.Event.ON_STOP)
    public final void onStop() {
        C0842e c0842e = this.autoScrollHelper;
        if (c0842e == null) {
            return;
        }
        c0842e.m181b();
    }
}
