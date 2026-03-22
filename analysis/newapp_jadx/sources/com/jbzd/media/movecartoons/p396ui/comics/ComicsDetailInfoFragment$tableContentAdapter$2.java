package com.jbzd.media.movecartoons.p396ui.comics;

import android.content.Context;
import android.view.View;
import android.widget.ImageView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.material.imageview.ShapeableImageView;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.VideoTypeBean;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.Chapter;
import com.jbzd.media.movecartoons.bean.response.comicsinfo.ComicsDetailInfoBean;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsChapterViewActivity;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsDetailInfoFragment;
import com.jbzd.media.movecartoons.p396ui.comics.ComicsDetailInfoFragment$tableContentAdapter$2;
import com.jbzd.media.movecartoons.p396ui.dialog.BuyDialog;
import com.jbzd.media.movecartoons.p396ui.vip.BuyActivity;
import com.jbzd.media.movecartoons.p396ui.wallet.RechargeActivity;
import com.qnmd.adnnm.da0yzo.R;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.jetbrains.annotations.NotNull;
import p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d;
import p005b.p143g.p144a.C1558h;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p005b.p327w.p330b.p336c.C2851b;
import p005b.p327w.p330b.p336c.C2852c;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment$tableContentAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/comics/ComicsDetailInfoFragment$tableContentAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ComicsDetailInfoFragment$tableContentAdapter$2 extends Lambda implements Function0<C36711> {
    public final /* synthetic */ ComicsDetailInfoFragment this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public ComicsDetailInfoFragment$tableContentAdapter$2(ComicsDetailInfoFragment comicsDetailInfoFragment) {
        super(0);
        this.this$0 = comicsDetailInfoFragment;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5763invoke$lambda1$lambda0(final ComicsDetailInfoFragment this$0, BaseQuickAdapter adapter, View view, int i2) {
        ComicsDetailInfoBean mComicsDetailInfo;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object item = adapter.getItem(i2);
        Objects.requireNonNull(item, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.comicsinfo.Chapter");
        final Chapter chapter = (Chapter) item;
        if (chapter.can_view.equals("y")) {
            ComicsChapterViewActivity.Companion companion = ComicsChapterViewActivity.INSTANCE;
            Context requireContext = this$0.requireContext();
            Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
            String str = chapter.f10008id;
            Intrinsics.checkNotNullExpressionValue(str, "mChapter.id");
            mComicsDetailInfo = this$0.getMComicsDetailInfo();
            companion.startFromComicsDetaial(requireContext, str, mComicsDetailInfo);
            return;
        }
        if (!chapter.type.equals(VideoTypeBean.video_type_vip)) {
            this$0.checkMoneyForBuyChapter(chapter, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$tableContentAdapter$2$2$1$2
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(1);
                }

                @Override // kotlin.jvm.functions.Function1
                public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                    invoke(bool.booleanValue());
                    return Unit.INSTANCE;
                }

                public final void invoke(boolean z) {
                    ComicsDetailInfoBean mComicsDetailInfo2;
                    if (z) {
                        ComicsChapterViewActivity.Companion companion2 = ComicsChapterViewActivity.INSTANCE;
                        Context requireContext2 = ComicsDetailInfoFragment.this.requireContext();
                        Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
                        String str2 = chapter.f10008id;
                        Intrinsics.checkNotNullExpressionValue(str2, "mChapter.id");
                        mComicsDetailInfo2 = ComicsDetailInfoFragment.this.getMComicsDetailInfo();
                        companion2.startFromComicsDetaial(requireContext2, str2, mComicsDetailInfo2);
                        return;
                    }
                    String str3 = chapter.money;
                    Intrinsics.checkNotNullExpressionValue(str3, "mChapter.money");
                    String str4 = chapter.type;
                    Intrinsics.checkNotNullExpressionValue(str4, "mChapter.type");
                    String str5 = chapter.button_text;
                    Intrinsics.checkNotNullExpressionValue(str5, "mChapter.button_text");
                    final Chapter chapter2 = chapter;
                    final ComicsDetailInfoFragment comicsDetailInfoFragment = ComicsDetailInfoFragment.this;
                    new BuyDialog(str3, str4, str5, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$tableContentAdapter$2$2$1$2.1
                        /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                        {
                            super(1);
                        }

                        @Override // kotlin.jvm.functions.Function1
                        public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                            invoke(bool.booleanValue());
                            return Unit.INSTANCE;
                        }

                        public final void invoke(boolean z2) {
                            if (z2) {
                                if (Chapter.this.type.equals(VideoTypeBean.video_type_vip)) {
                                    BuyActivity.Companion companion3 = BuyActivity.INSTANCE;
                                    Context requireContext3 = comicsDetailInfoFragment.requireContext();
                                    Intrinsics.checkNotNullExpressionValue(requireContext3, "requireContext()");
                                    companion3.start(requireContext3);
                                    return;
                                }
                                RechargeActivity.Companion companion4 = RechargeActivity.INSTANCE;
                                Context requireContext4 = comicsDetailInfoFragment.requireContext();
                                Intrinsics.checkNotNullExpressionValue(requireContext4, "requireContext()");
                                companion4.start(requireContext4);
                            }
                        }
                    }).show(ComicsDetailInfoFragment.this.getChildFragmentManager(), "buyDialog");
                }
            });
            return;
        }
        MyApp myApp = MyApp.f9891f;
        if (MyApp.f9892g.isVipUser()) {
            return;
        }
        String str2 = chapter.money;
        Intrinsics.checkNotNullExpressionValue(str2, "mChapter.money");
        String str3 = chapter.type;
        Intrinsics.checkNotNullExpressionValue(str3, "mChapter.type");
        new BuyDialog(str2, str3, "需要开通VIP才可以看哦~.~", new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$tableContentAdapter$2$2$1$1
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Boolean bool) {
                invoke(bool.booleanValue());
                return Unit.INSTANCE;
            }

            public final void invoke(boolean z) {
                if (z) {
                    if (Chapter.this.type.equals(VideoTypeBean.video_type_vip)) {
                        BuyActivity.Companion companion2 = BuyActivity.INSTANCE;
                        Context requireContext2 = this$0.requireContext();
                        Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
                        companion2.start(requireContext2);
                        return;
                    }
                    RechargeActivity.Companion companion3 = RechargeActivity.INSTANCE;
                    Context requireContext3 = this$0.requireContext();
                    Intrinsics.checkNotNullExpressionValue(requireContext3, "requireContext()");
                    companion3.start(requireContext3);
                }
            }
        }).show(this$0.getChildFragmentManager(), "vipDialog");
    }

    /* JADX WARN: Can't rename method to resolve collision */
    /* JADX WARN: Type inference failed for: r0v0, types: [com.chad.library.adapter.base.BaseQuickAdapter, com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$tableContentAdapter$2$1] */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C36711 invoke() {
        final ComicsDetailInfoFragment comicsDetailInfoFragment = this.this$0;
        ?? r0 = new BaseQuickAdapter<Chapter, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.comics.ComicsDetailInfoFragment$tableContentAdapter$2.1
            {
                super(R.layout.item_comicsdetail_tabcontent, null, 2, null);
            }

            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull Chapter item) {
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                C2852c m2463c2 = C2354n.m2463c2(ComicsDetailInfoFragment.this);
                String str = item.img;
                if (str == null) {
                    str = "";
                }
                C1558h mo770c = m2463c2.mo770c();
                mo770c.mo763X(str);
                ((C2851b) mo770c).m3295i0().m757R((ImageView) helper.m3912b(R.id.iv_chapter_cover));
                ((ShapeableImageView) helper.m3912b(R.id.iv_chapter_cover)).setVisibility(0);
                helper.m3919i(R.id.tv_chapter_name, item.name);
                if (item.can_view.equals("y")) {
                    helper.m3916f(R.id.tv_tablecontent_watch, false);
                    helper.m3919i(R.id.tv_tablecontent_watch, item.button_text);
                    helper.m3916f(R.id.tv_tablecontent_vip, true);
                    helper.m3916f(R.id.tv_tablecontent_coin, true);
                    return;
                }
                if (item.type.equals(VideoTypeBean.video_type_vip)) {
                    helper.m3916f(R.id.tv_tablecontent_watch, true);
                    helper.m3916f(R.id.tv_tablecontent_vip, false);
                    helper.m3916f(R.id.tv_tablecontent_coin, true);
                } else {
                    helper.m3916f(R.id.tv_tablecontent_watch, true);
                    helper.m3916f(R.id.tv_tablecontent_vip, true);
                    helper.m3916f(R.id.tv_tablecontent_coin, false);
                    helper.m3919i(R.id.tv_tablecontent_coin, item.money);
                }
            }
        };
        final ComicsDetailInfoFragment comicsDetailInfoFragment2 = this.this$0;
        r0.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.d.l
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                ComicsDetailInfoFragment$tableContentAdapter$2.m5763invoke$lambda1$lambda0(ComicsDetailInfoFragment.this, baseQuickAdapter, view, i2);
            }
        });
        return r0;
    }
}
