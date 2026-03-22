package com.jbzd.media.movecartoons.p396ui.dialog;

import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.AppItemNew;
import com.jbzd.media.movecartoons.p396ui.dialog.AppDialog;
import com.jbzd.media.movecartoons.p396ui.dialog.AppDialog$mAdapter$2;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/dialog/AppDialog$mAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/dialog/AppDialog$mAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class AppDialog$mAdapter$2 extends Lambda implements Function0<C36831> {
    public final /* synthetic */ AppDialog this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AppDialog$mAdapter$2(AppDialog appDialog) {
        super(0);
        this.this$0 = appDialog;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5768invoke$lambda1$lambda0(AppDialog this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object item = adapter.getItem(i2);
        Objects.requireNonNull(item, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.AppItemNew");
        AppItemNew appItemNew = (AppItemNew) item;
        MineViewModel.Companion companion = MineViewModel.INSTANCE;
        String str = appItemNew.f9930id;
        Intrinsics.checkNotNullExpressionValue(str, "item.id");
        String str2 = appItemNew.name;
        Intrinsics.checkNotNullExpressionValue(str2, "item.name");
        companion.systemTrack("app", str, str2);
        C0840d.a aVar = C0840d.f235a;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        String str3 = appItemNew.android_url;
        Intrinsics.checkNotNullExpressionValue(str3, "item.android_url");
        aVar.m175a(requireContext, str3);
    }

    /* JADX WARN: Can't rename method to resolve collision */
    /* JADX WARN: Type inference failed for: r0v0, types: [com.chad.library.adapter.base.BaseQuickAdapter, com.jbzd.media.movecartoons.ui.dialog.AppDialog$mAdapter$2$1] */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C36831 invoke() {
        final AppDialog appDialog = this.this$0;
        ?? r0 = new BaseQuickAdapter<AppItemNew, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.dialog.AppDialog$mAdapter$2.1
            {
                super(R.layout.item_apps, null, 2, null);
            }

            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull AppItemNew item) {
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                AppDialog appDialog2 = AppDialog.this;
                helper.m3919i(R.id.f13004tv, item.name);
                C2354n.m2463c2(appDialog2).m3298p(item.image).m3295i0().m757R((ImageView) helper.m3912b(R.id.f13001iv));
            }
        };
        final AppDialog appDialog2 = this.this$0;
        r0.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.e.d
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                AppDialog$mAdapter$2.m5768invoke$lambda1$lambda0(AppDialog.this, baseQuickAdapter, view, i2);
            }
        });
        return r0;
    }
}
