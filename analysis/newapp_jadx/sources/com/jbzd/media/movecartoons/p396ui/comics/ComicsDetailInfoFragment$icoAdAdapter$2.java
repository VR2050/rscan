package com.jbzd.media.movecartoons.p396ui.comics;

import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import android.widget.TextView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsDetailInfoFragment$icoAdAdapter$2;
import com.jbzd.media.movecartoons.p396ui.mine.MineViewModel;
import com.qnmd.adnnm.da0yzo.R;
import kotlin.Metadata;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p199l.p200a.p201a.p250p1.C2354n;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment$icoAdAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment$icoAdAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ComicsDetailInfoFragment$icoAdAdapter$2 extends Lambda implements Function0<C36701> {
    public final /* synthetic */ ComicsDetailInfoFragment this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ComicsDetailInfoFragment$icoAdAdapter$2(ComicsDetailInfoFragment comicsDetailInfoFragment) {
        super(0);
        this.this$0 = comicsDetailInfoFragment;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5762invoke$lambda1$lambda0(C36701 this_apply, ComicsDetailInfoFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
        Intrinsics.checkNotNullParameter(this_apply, "$this_apply");
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        MineViewModel.Companion companion = MineViewModel.INSTANCE;
        String str = this_apply.getData().get(i2).f10014id;
        Intrinsics.checkNotNullExpressionValue(str, "data[position].id");
        String str2 = this_apply.getData().get(i2).name;
        Intrinsics.checkNotNullExpressionValue(str2, "data[position].name");
        companion.systemTrack("ad", str, str2);
        C0840d.a aVar = C0840d.f235a;
        Context requireContext = this$0.requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        aVar.m176b(requireContext, this_apply.getData().get(i2));
    }

    /* JADX WARN: Can't rename method to resolve collision */
    /* JADX WARN: Type inference failed for: r0v0, types: [com.chad.library.adapter.base.BaseQuickAdapter, com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$icoAdAdapter$2$1] */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C36701 invoke() {
        final ComicsDetailInfoFragment comicsDetailInfoFragment = this.this$0;
        final ?? r0 = new BaseQuickAdapter<AdBean, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$icoAdAdapter$2.1
            {
                super(R.layout.item_apps, null, 2, null);
            }

            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull AdBean item) {
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                ComicsDetailInfoFragment comicsDetailInfoFragment2 = ComicsDetailInfoFragment.this;
                helper.m3919i(R.id.f13004tv, item.name);
                ((TextView) helper.m3912b(R.id.f13004tv)).setTextColor(comicsDetailInfoFragment2.getResources().getColor(R.color.black));
                C2354n.m2455a2(getContext()).m3298p(item.content).m3293g0(8).m757R((ImageView) helper.m3912b(R.id.f13001iv));
                View view = helper.m3912b(R.id.f13001iv);
                Intrinsics.checkNotNullParameter(view, "view");
                view.setOutlineProvider(new C0859m0(8.0d));
                view.setClipToOutline(true);
            }
        };
        final ComicsDetailInfoFragment comicsDetailInfoFragment2 = this.this$0;
        r0.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.d.j
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                ComicsDetailInfoFragment$icoAdAdapter$2.m5762invoke$lambda1$lambda0(ComicsDetailInfoFragment$icoAdAdapter$2.C36701.this, comicsDetailInfoFragment2, baseQuickAdapter, view, i2);
            }
        });
        return r0;
    }
}
