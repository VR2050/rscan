package com.jbzd.media.movecartoons.p396ui.novel;

import android.view.View;
import android.widget.ImageView;
import com.chad.library.adapter.base.BaseQuickAdapter;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.bean.response.VideoTypeBean;
import com.jbzd.media.movecartoons.bean.response.novel.NovelChapter;
import com.jbzd.media.movecartoons.bean.response.novel.NovelDetailInfoBean;
import com.jbzd.media.movecartoons.p396ui.dialog.BuyDialog;
import com.jbzd.media.movecartoons.p396ui.novel.AudioPlayerActivity;
import com.jbzd.media.movecartoons.p396ui.novel.NovelChapterViewActivity;
import com.jbzd.media.movecartoons.p396ui.novel.NovelTableContentAllActivity;
import com.jbzd.media.movecartoons.p396ui.novel.NovelTableContentAllActivity$tableContentAdapter$2;
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

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0007\n\u0002\b\u0003*\u0001\u0000\u0010\u0001\u001a\u00020\u0000H\n¢\u0006\u0004\b\u0001\u0010\u0002"}, m5311d2 = {"com/jbzd/media/movecartoons/ui/novel/NovelTableContentAllActivity$tableContentAdapter$2$1", "<anonymous>", "()Lcom/jbzd/media/movecartoons/ui/novel/NovelTableContentAllActivity$tableContentAdapter$2$1;"}, m5312k = 3, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class NovelTableContentAllActivity$tableContentAdapter$2 extends Lambda implements Function0<C38401> {
    public final /* synthetic */ NovelTableContentAllActivity this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public NovelTableContentAllActivity$tableContentAdapter$2(NovelTableContentAllActivity novelTableContentAllActivity) {
        super(0);
        this.this$0 = novelTableContentAllActivity;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: invoke$lambda-1$lambda-0, reason: not valid java name */
    public static final void m5927invoke$lambda1$lambda0(final NovelTableContentAllActivity this$0, BaseQuickAdapter adapter, View view, int i2) {
        NovelDetailInfoBean mNovelDetailInfoBean;
        NovelDetailInfoBean mNovelDetailInfoBean2;
        NovelDetailInfoBean mNovelDetailInfoBean3;
        Intrinsics.checkNotNullParameter(this$0, "this$0");
        Intrinsics.checkNotNullParameter(adapter, "adapter");
        Intrinsics.checkNotNullParameter(view, "view");
        Object item = adapter.getItem(i2);
        Objects.requireNonNull(item, "null cannot be cast to non-null type com.jbzd.media.movecartoons.bean.response.novel.NovelChapter");
        final NovelChapter novelChapter = (NovelChapter) item;
        if (novelChapter.can_view.equals("y")) {
            mNovelDetailInfoBean = this$0.getMNovelDetailInfoBean();
            if (mNovelDetailInfoBean.ico.equals("audio")) {
                AudioPlayerActivity.Companion companion = AudioPlayerActivity.INSTANCE;
                String str = novelChapter.f10026id;
                Intrinsics.checkNotNullExpressionValue(str, "mChapter.id");
                mNovelDetailInfoBean3 = this$0.getMNovelDetailInfoBean();
                companion.start(this$0, str, mNovelDetailInfoBean3);
                return;
            }
            NovelChapterViewActivity.Companion companion2 = NovelChapterViewActivity.INSTANCE;
            String str2 = novelChapter.f10026id;
            Intrinsics.checkNotNullExpressionValue(str2, "mChapter.id");
            mNovelDetailInfoBean2 = this$0.getMNovelDetailInfoBean();
            companion2.start(this$0, str2, mNovelDetailInfoBean2);
            return;
        }
        if (!novelChapter.type.equals(VideoTypeBean.video_type_vip)) {
            this$0.checkMoneyForBuyChapter(novelChapter, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelTableContentAllActivity$tableContentAdapter$2$2$1$2
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
                        return;
                    }
                    String str3 = NovelChapter.this.money;
                    Intrinsics.checkNotNullExpressionValue(str3, "mChapter.money");
                    String str4 = NovelChapter.this.type;
                    Intrinsics.checkNotNullExpressionValue(str4, "mChapter.type");
                    String str5 = NovelChapter.this.button_text;
                    Intrinsics.checkNotNullExpressionValue(str5, "mChapter.button_text");
                    final NovelChapter novelChapter2 = NovelChapter.this;
                    final NovelTableContentAllActivity novelTableContentAllActivity = this$0;
                    new BuyDialog(str3, str4, str5, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelTableContentAllActivity$tableContentAdapter$2$2$1$2.1
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
                                if (NovelChapter.this.type.equals(VideoTypeBean.video_type_vip)) {
                                    BuyActivity.INSTANCE.start(novelTableContentAllActivity);
                                } else {
                                    RechargeActivity.INSTANCE.start(novelTableContentAllActivity);
                                }
                            }
                        }
                    }).show(this$0.getSupportFragmentManager(), "buyDialog");
                }
            });
            return;
        }
        MyApp myApp = MyApp.f9891f;
        if (MyApp.f9892g.isVipUser()) {
            return;
        }
        String str3 = novelChapter.money;
        Intrinsics.checkNotNullExpressionValue(str3, "mChapter.money");
        String str4 = novelChapter.type;
        Intrinsics.checkNotNullExpressionValue(str4, "mChapter.type");
        String str5 = novelChapter.button_text;
        Intrinsics.checkNotNullExpressionValue(str5, "mChapter.button_text");
        new BuyDialog(str3, str4, str5, new Function1<Boolean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelTableContentAllActivity$tableContentAdapter$2$2$1$1
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
                    if (NovelChapter.this.type.equals(VideoTypeBean.video_type_vip)) {
                        BuyActivity.INSTANCE.start(this$0);
                    } else {
                        RechargeActivity.INSTANCE.start(this$0);
                    }
                }
            }
        }).show(this$0.getSupportFragmentManager(), "vipDialog");
    }

    /* JADX WARN: Can't rename method to resolve collision */
    /* JADX WARN: Type inference failed for: r0v0, types: [com.chad.library.adapter.base.BaseQuickAdapter, com.jbzd.media.movecartoons.ui.novel.NovelTableContentAllActivity$tableContentAdapter$2$1] */
    @Override // kotlin.jvm.functions.Function0
    @NotNull
    public final C38401 invoke() {
        final NovelTableContentAllActivity novelTableContentAllActivity = this.this$0;
        ?? r0 = new BaseQuickAdapter<NovelChapter, BaseViewHolder>() { // from class: com.jbzd.media.movecartoons.ui.novel.NovelTableContentAllActivity$tableContentAdapter$2.1
            {
                super(R.layout.item_comicsdetail_tabcontent, null, 2, null);
            }

            @Override // com.chad.library.adapter.base.BaseQuickAdapter
            public void convert(@NotNull BaseViewHolder helper, @NotNull NovelChapter item) {
                Intrinsics.checkNotNullParameter(helper, "helper");
                Intrinsics.checkNotNullParameter(item, "item");
                C2852c m2467d2 = C2354n.m2467d2(NovelTableContentAllActivity.this);
                String str = item.img;
                if (str == null) {
                    str = "";
                }
                C1558h mo770c = m2467d2.mo770c();
                mo770c.mo763X(str);
                ((C2851b) mo770c).m3295i0().m757R((ImageView) helper.m3912b(R.id.iv_chapter_cover));
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
        final NovelTableContentAllActivity novelTableContentAllActivity2 = this.this$0;
        r0.setOnItemClickListener(new InterfaceC1304d() { // from class: b.a.a.a.t.j.s
            @Override // p005b.p067b.p068a.p069a.p070a.p076k.InterfaceC1304d
            public final void onItemClick(BaseQuickAdapter baseQuickAdapter, View view, int i2) {
                NovelTableContentAllActivity$tableContentAdapter$2.m5927invoke$lambda1$lambda0(NovelTableContentAllActivity.this, baseQuickAdapter, view, i2);
            }
        });
        return r0;
    }
}
