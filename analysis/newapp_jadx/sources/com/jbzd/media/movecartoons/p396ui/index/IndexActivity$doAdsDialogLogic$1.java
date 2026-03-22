package com.jbzd.media.movecartoons.p396ui.index;

import android.graphics.drawable.Drawable;
import android.os.Handler;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.p396ui.index.IndexActivity;
import com.jbzd.media.movecartoons.p396ui.index.IndexActivity$doAdsDialogLogic$1;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p009a.InterfaceC0877y;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0019\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004*\u0001\u0000\b\n\u0018\u00002\u00020\u0001J\u000f\u0010\u0003\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0003\u0010\u0004J\u0017\u0010\u0007\u001a\u00020\u00022\u0006\u0010\u0006\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0007\u0010\b¨\u0006\t"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/index/IndexActivity$doAdsDialogLogic$1", "Lb/a/a/a/a/y;", "", "loadError", "()V", "Landroid/graphics/drawable/Drawable;", "resource", "loadReady", "(Landroid/graphics/drawable/Drawable;)V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class IndexActivity$doAdsDialogLogic$1 implements InterfaceC0877y {
    public final /* synthetic */ AdBean $adBean;
    public final /* synthetic */ IndexActivity this$0;

    public IndexActivity$doAdsDialogLogic$1(IndexActivity indexActivity, AdBean adBean) {
        this.this$0 = indexActivity;
        this.$adBean = adBean;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: loadReady$lambda-1, reason: not valid java name */
    public static final void m5811loadReady$lambda1(final IndexActivity this$0, final Drawable resource, final AdBean adBean) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(resource, "$resource");
        Intrinsics.checkNotNullParameter(adBean, "$adBean");
        new Handler().postDelayed(new Runnable() { // from class: b.a.a.a.t.g.g
            @Override // java.lang.Runnable
            public final void run() {
                IndexActivity$doAdsDialogLogic$1.m5812loadReady$lambda1$lambda0(IndexActivity.this, resource, adBean);
            }
        }, 150L);
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: loadReady$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5812loadReady$lambda1$lambda0(IndexActivity this$0, Drawable resource, AdBean adBean) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(resource, "$resource");
        Intrinsics.checkNotNullParameter(adBean, "$adBean");
        this$0.showActivityAdsDialog(resource, adBean);
    }

    @Override // p005b.p006a.p007a.p008a.p009a.InterfaceC0877y
    public void loadError() {
    }

    @Override // p005b.p006a.p007a.p008a.p009a.InterfaceC0877y
    public void loadReady(@NotNull final Drawable resource) {
        Intrinsics.checkNotNullParameter(resource, "resource");
        final IndexActivity indexActivity = this.this$0;
        final AdBean adBean = this.$adBean;
        indexActivity.runOnUiThread(new Runnable() { // from class: b.a.a.a.t.g.f
            @Override // java.lang.Runnable
            public final void run() {
                IndexActivity$doAdsDialogLogic$1.m5811loadReady$lambda1(IndexActivity.this, resource, adBean);
            }
        });
    }
}
