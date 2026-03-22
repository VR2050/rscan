package com.jbzd.media.movecartoons.p396ui.index.darkplay;

import android.os.Bundle;
import android.os.Handler;
import android.util.ArrayMap;
import android.view.View;
import android.widget.ImageView;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.swiperefreshlayout.widget.SwipeRefreshLayout;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.MyApp;
import com.jbzd.media.movecartoons.R$id;
import com.jbzd.media.movecartoons.bean.response.AIPostConfigsBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.jbzd.media.movecartoons.p396ui.index.darkplay.BaseVideoItemFragment;
import com.jbzd.media.movecartoons.view.video.FullPlayerView;
import com.jbzd.media.movecartoons.view.video.MyVideoAllCallback;
import com.qnmd.adnnm.da0yzo.R;
import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import kotlin.Lazy;
import kotlin.LazyKt__LazyJVMKt;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0851i0;
import p005b.p006a.p007a.p008a.p009a.C0853j0;
import p005b.p006a.p007a.p008a.p009a.C0859m0;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p067b.p068a.p069a.p070a.p078m.C1318f;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\\\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0007\n\u0002\u0010!\n\u0002\b\u000b\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\b\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0002\b\b\u0018\u0000 92\b\u0012\u0004\u0012\u00020\u00020\u0001:\u00019B\u0007¢\u0006\u0004\b8\u0010\u0019J\u000f\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0004\u0010\u0005J\u000f\u0010\u0007\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0007\u0010\bJ\u000f\u0010\n\u001a\u00020\tH\u0016¢\u0006\u0004\b\n\u0010\u000bJ\u000f\u0010\r\u001a\u00020\fH\u0016¢\u0006\u0004\b\r\u0010\u000eJ\u0015\u0010\u0011\u001a\u00020\u00102\u0006\u0010\u000f\u001a\u00020\t¢\u0006\u0004\b\u0011\u0010\u0012J\u001f\u0010\u0016\u001a\u00020\u00102\u0006\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0015\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u0016\u0010\u0017J\u000f\u0010\u0018\u001a\u00020\u0010H\u0016¢\u0006\u0004\b\u0018\u0010\u0019J\u000f\u0010\u001a\u001a\u00020\u0010H\u0016¢\u0006\u0004\b\u001a\u0010\u0019R(\u0010\u001c\u001a\b\u0012\u0004\u0012\u00020\u00020\u001b8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u001c\u0010\u001d\u001a\u0004\b\u001e\u0010\u001f\"\u0004\b \u0010!R\"\u0010\"\u001a\u00020\u00038\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\"\u0010#\u001a\u0004\b$\u0010\u0005\"\u0004\b%\u0010&R?\u0010+\u001a\u001f\u0012\u0013\u0012\u00110\u0002¢\u0006\f\b(\u0012\b\b)\u0012\u0004\b\b(*\u0012\u0004\u0012\u00020\u0010\u0018\u00010'8\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b+\u0010,\u001a\u0004\b-\u0010.\"\u0004\b/\u00100R)\u00107\u001a\u000e\u0012\u0004\u0012\u000202\u0012\u0004\u0012\u000202018B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b3\u00104\u001a\u0004\b5\u00106¨\u0006:"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/darkplay/BaseVideoItemFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/AIPostConfigsBean$AiChangeVideoTemplateBean;", "", "getItemLayoutId", "()I", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "", "getRefreshEnable", "()Z", "Lc/a/d1;", "request", "()Lc/a/d1;", "boolean", "", "downloadFinish", "(Z)V", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/AIPostConfigsBean$AiChangeVideoTemplateBean;)V", "onPause", "()V", "onResume", "", "list", "Ljava/util/List;", "getList", "()Ljava/util/List;", "setList", "(Ljava/util/List;)V", "defaultPos", "I", "getDefaultPos", "setDefaultPos", "(I)V", "Lkotlin/Function1;", "Lkotlin/ParameterName;", "name", "bean", "callBack", "Lkotlin/jvm/functions/Function1;", "getCallBack", "()Lkotlin/jvm/functions/Function1;", "setCallBack", "(Lkotlin/jvm/functions/Function1;)V", "Landroid/util/ArrayMap;", "", "videoPlayHeader$delegate", "Lkotlin/Lazy;", "getVideoPlayHeader", "()Landroid/util/ArrayMap;", "videoPlayHeader", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class BaseVideoItemFragment extends BaseListFragment<AIPostConfigsBean.AiChangeVideoTemplateBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    /* renamed from: ID */
    @NotNull
    private static final String f10113ID = "id";

    @Nullable
    private Function1<? super AIPostConfigsBean.AiChangeVideoTemplateBean, Unit> callBack;
    private int defaultPos;

    /* renamed from: videoPlayHeader$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy videoPlayHeader = LazyKt__LazyJVMKt.lazy(new Function0<ArrayMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.BaseVideoItemFragment$videoPlayHeader$2
        /* JADX WARN: Can't rename method to resolve collision */
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final ArrayMap<String, String> invoke() {
            ArrayMap<String, String> arrayMap = new ArrayMap<>();
            MyApp myApp = MyApp.f9891f;
            arrayMap.put("referer", MyApp.m4185f().cdn_header);
            arrayMap.put("allowCrossProtocolRedirects", "true");
            return arrayMap;
        }
    });

    @NotNull
    private List<AIPostConfigsBean.AiChangeVideoTemplateBean> list = new ArrayList();

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0007\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\t\u0010\nJ\u0017\u0010\u0005\u001a\u00020\u00042\b\b\u0002\u0010\u0003\u001a\u00020\u0002¢\u0006\u0004\b\u0005\u0010\u0006R\u0016\u0010\u0007\u001a\u00020\u00028\u0002@\u0002X\u0082T¢\u0006\u0006\n\u0004\b\u0007\u0010\b¨\u0006\u000b"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/index/darkplay/BaseVideoItemFragment$Companion;", "", "", BaseVideoItemFragment.f10113ID, "Lcom/jbzd/media/movecartoons/ui/index/darkplay/BaseVideoItemFragment;", "newInstance", "(Ljava/lang/String;)Lcom/jbzd/media/movecartoons/ui/index/darkplay/BaseVideoItemFragment;", "ID", "Ljava/lang/String;", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        public static /* synthetic */ BaseVideoItemFragment newInstance$default(Companion companion, String str, int i2, Object obj) {
            if ((i2 & 1) != 0) {
                str = "";
            }
            return companion.newInstance(str);
        }

        @NotNull
        public final BaseVideoItemFragment newInstance(@NotNull String id) {
            Intrinsics.checkNotNullParameter(id, "id");
            BaseVideoItemFragment baseVideoItemFragment = new BaseVideoItemFragment();
            Bundle bundle = new Bundle();
            bundle.putString(BaseVideoItemFragment.f10113ID, id);
            Unit unit = Unit.INSTANCE;
            baseVideoItemFragment.setArguments(bundle);
            return baseVideoItemFragment;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: bindItem$lambda-4$lambda-3$lambda-2$lambda-1, reason: not valid java name */
    public static final void m5813bindItem$lambda4$lambda3$lambda2$lambda1(FullPlayerView this_run) {
        Intrinsics.checkNotNullParameter(this_run, "$this_run");
        this_run.startPlayLogic();
    }

    private final ArrayMap<String, String> getVideoPlayHeader() {
        return (ArrayMap) this.videoPlayHeader.getValue();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    public final void downloadFinish(boolean r5) {
        View view = getView();
        ((SwipeRefreshLayout) (view == null ? null : view.findViewById(R$id.swipeLayout))).setRefreshing(r5);
        C1318f loadMoreModule = getAdapter().getLoadMoreModule();
        if (loadMoreModule != null) {
            loadMoreModule.m330f();
        }
        C1318f loadMoreModule2 = getAdapter().getLoadMoreModule();
        if (loadMoreModule2 != null) {
            C1318f.m324h(loadMoreModule2, false, 1, null);
        }
        C1318f loadMoreModule3 = getAdapter().getLoadMoreModule();
        if (loadMoreModule3 != null) {
            loadMoreModule3.f1060i = r5;
        }
        C1318f loadMoreModule4 = getAdapter().getLoadMoreModule();
        if (loadMoreModule4 != null) {
            loadMoreModule4.f1056e = !r5;
        }
        C1318f loadMoreModule5 = getAdapter().getLoadMoreModule();
        if (loadMoreModule5 != null) {
            loadMoreModule5.m334k(r5);
        }
        Fragment parentFragment = getParentFragment();
        if (parentFragment != null) {
            View view2 = parentFragment.getView();
            r1 = (ImageView) (view2 != null ? view2.findViewById(R$id.iv_tag) : null);
        }
        if (r1 == null) {
            return;
        }
        r1.setVisibility(r5 ? 0 : 8);
    }

    @Nullable
    public final Function1<AIPostConfigsBean.AiChangeVideoTemplateBean, Unit> getCallBack() {
        return this.callBack;
    }

    public final int getDefaultPos() {
        return this.defaultPos;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.item_basevideo_aichangeface;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        LinearLayoutManager linearLayoutManager = new LinearLayoutManager(requireContext());
        linearLayoutManager.setOrientation(0);
        return linearLayoutManager;
    }

    @NotNull
    public final List<AIPostConfigsBean.AiChangeVideoTemplateBean> getList() {
        return this.list;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public boolean getRefreshEnable() {
        return false;
    }

    @Override // androidx.fragment.app.Fragment
    public void onPause() {
        super.onPause();
    }

    @Override // com.qunidayede.supportlibrary.core.view.BaseFragment, androidx.fragment.app.Fragment
    public void onResume() {
        super.onResume();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public InterfaceC3053d1 request() {
        getRv_content().addOnScrollListener(new RecyclerView.OnScrollListener() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.BaseVideoItemFragment$request$1
            @Override // androidx.recyclerview.widget.RecyclerView.OnScrollListener
            public void onScrolled(@NotNull RecyclerView rv, int dx, int dy) {
                Intrinsics.checkNotNullParameter(rv, "rv");
                super.onScrolled(rv, dx, dy);
                Fragment parentFragment = BaseVideoItemFragment.this.getParentFragment();
                if (parentFragment != null) {
                    View view = parentFragment.getView();
                    r4 = (ImageView) (view != null ? view.findViewById(R$id.iv_tag) : null);
                }
                if (r4 == null) {
                    return;
                }
                r4.setVisibility(rv.canScrollHorizontally(1) ? 0 : 8);
            }
        });
        return C0917a.m221e(C0917a.f372a, "post/aiConfigs", AIPostConfigsBean.class, new HashMap(), new Function1<AIPostConfigsBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.BaseVideoItemFragment$request$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(AIPostConfigsBean aIPostConfigsBean) {
                invoke2(aIPostConfigsBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable AIPostConfigsBean aIPostConfigsBean) {
                if (aIPostConfigsBean == null) {
                    return;
                }
                BaseVideoItemFragment baseVideoItemFragment = BaseVideoItemFragment.this;
                Function1<AIPostConfigsBean.AiChangeVideoTemplateBean, Unit> callBack = baseVideoItemFragment.getCallBack();
                if (callBack != null) {
                    AIPostConfigsBean.AiChangeVideoTemplateBean aiChangeVideoTemplateBean = aIPostConfigsBean.ai_change_video_template.get(0);
                    Intrinsics.checkNotNullExpressionValue(aiChangeVideoTemplateBean, "it.ai_change_video_template[0]");
                    callBack.invoke(aiChangeVideoTemplateBean);
                }
                baseVideoItemFragment.didRequestComplete(aIPostConfigsBean.ai_change_video_template);
                baseVideoItemFragment.downloadFinish(false);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.BaseVideoItemFragment$request$3
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
            }
        }, false, false, null, false, 480);
    }

    public final void setCallBack(@Nullable Function1<? super AIPostConfigsBean.AiChangeVideoTemplateBean, Unit> function1) {
        this.callBack = function1;
    }

    public final void setDefaultPos(int i2) {
        this.defaultPos = i2;
    }

    public final void setList(@NotNull List<AIPostConfigsBean.AiChangeVideoTemplateBean> list) {
        Intrinsics.checkNotNullParameter(list, "<set-?>");
        this.list = list;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull final BaseViewHolder helper, @NotNull final AIPostConfigsBean.AiChangeVideoTemplateBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        View m3912b = helper.m3912b(R.id.view_up);
        View m3912b2 = helper.m3912b(R.id.item_player);
        View m3912b3 = helper.m3912b(R.id.img_default_show);
        View m3912b4 = helper.m3912b(R.id.iv_center_playicon);
        m3912b.setSelected(getDefaultPos() == helper.getAdapterPosition());
        if (m3912b.isSelected()) {
            ImageView imageView = (ImageView) m3912b3;
            imageView.setVisibility(8);
            ImageView imageView2 = (ImageView) m3912b4;
            imageView2.setVisibility(8);
            final FullPlayerView fullPlayerView = (FullPlayerView) m3912b2;
            fullPlayerView.setVisibility(0);
            imageView.setVisibility(8);
            imageView2.setVisibility(8);
            fullPlayerView.setVisibility(0);
            fullPlayerView.playerImage.setVisibility(0);
            String str = item.image_url;
            if (str == null) {
                str = "";
            }
            fullPlayerView.loadCoverImage(str);
            fullPlayerView.getBackButton().setVisibility(8);
            fullPlayerView.setBottomShow(false);
            fullPlayerView.setUp(item.video_url, true, (File) null, (Map<String, String>) getVideoPlayHeader(), "");
            fullPlayerView.setSeekOnStart(0L);
            fullPlayerView.setVideoAllCallBack(new MyVideoAllCallback() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.BaseVideoItemFragment$bindItem$1$1$1$1
                @Override // com.jbzd.media.movecartoons.view.video.MyVideoAllCallback, p005b.p362y.p363a.p366f.InterfaceC2931g
                public void onPlayError(@Nullable String url, @NotNull Object... objects) {
                    Intrinsics.checkNotNullParameter(objects, "objects");
                    if (url == null) {
                        url = "";
                    }
                    C0853j0 c0853j0 = C0853j0.f254c;
                    C0851i0 c0851i0 = C0851i0.f252c;
                    C0917a c0917a = C0917a.f372a;
                    HashMap m596R = C1499a.m596R("type", "play_error", "data", url);
                    Unit unit = Unit.INSTANCE;
                    C0917a.m221e(c0917a, "system/event", Object.class, m596R, c0853j0, c0851i0, false, false, null, false, 416);
                }

                @Override // com.jbzd.media.movecartoons.view.video.MyVideoAllCallback, p005b.p362y.p363a.p366f.InterfaceC2931g
                public void onPrepared(@Nullable String url, @NotNull Object... objects) {
                    Intrinsics.checkNotNullParameter(objects, "objects");
                }
            });
            new Handler().postDelayed(new Runnable() { // from class: b.a.a.a.t.g.i.a
                @Override // java.lang.Runnable
                public final void run() {
                    BaseVideoItemFragment.m5813bindItem$lambda4$lambda3$lambda2$lambda1(FullPlayerView.this);
                }
            }, 500L);
        } else {
            ((ImageView) m3912b3).setVisibility(0);
            ((ImageView) m3912b4).setVisibility(0);
            ((FullPlayerView) m3912b2).setVisibility(8);
        }
        C2354n.m2455a2(requireContext()).m3298p(item.image_url).m3295i0().m757R((ImageView) helper.m3912b(R.id.img_default_show));
        View view = helper.itemView;
        Intrinsics.checkNotNullExpressionValue(view, "helper.itemView");
        Intrinsics.checkNotNullParameter(view, "view");
        view.setOutlineProvider(new C0859m0(2.5d));
        view.setClipToOutline(true);
        helper.m3918h(R.id.rv_tag_layout, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.index.darkplay.BaseVideoItemFragment$bindItem$1$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2() {
                Function1<AIPostConfigsBean.AiChangeVideoTemplateBean, Unit> callBack = BaseVideoItemFragment.this.getCallBack();
                if (callBack != null) {
                    callBack.invoke(item);
                }
                BaseVideoItemFragment.this.setDefaultPos(helper.getAdapterPosition());
                BaseVideoItemFragment.this.getAdapter().notifyDataSetChanged();
            }
        });
    }
}
