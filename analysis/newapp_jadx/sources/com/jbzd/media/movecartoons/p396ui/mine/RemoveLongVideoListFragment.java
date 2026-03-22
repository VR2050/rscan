package com.jbzd.media.movecartoons.p396ui.mine;

import android.content.Context;
import androidx.core.app.NotificationCompat;
import androidx.fragment.app.FragmentActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.bean.response.home.AdBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.VideoItemShowKt;
import com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity;
import com.qnmd.adnnm.da0yzo.R;
import java.util.HashMap;
import java.util.List;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0840d;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000:\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0002\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u000b\u0018\u0000 \u001d2\b\u0012\u0004\u0012\u00020\u00020\u0001:\u0001\u001dB\u0007¢\u0006\u0004\b\u001c\u0010\u0019J\u0017\u0010\u0006\u001a\u00020\u00052\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\u0006\u0010\u0007J\u000f\u0010\t\u001a\u00020\bH\u0016¢\u0006\u0004\b\t\u0010\nJ\u001f\u0010\u000e\u001a\u00020\u00052\u0006\u0010\f\u001a\u00020\u000b2\u0006\u0010\r\u001a\u00020\u0002H\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u0011\u0010\u0011\u001a\u0004\u0018\u00010\u0010H\u0016¢\u0006\u0004\b\u0011\u0010\u0012J\u000f\u0010\u0014\u001a\u00020\u0013H\u0016¢\u0006\u0004\b\u0014\u0010\u0015J\u000f\u0010\u0016\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0016\u0010\u0017J\u000f\u0010\u0018\u001a\u00020\u0005H\u0016¢\u0006\u0004\b\u0018\u0010\u0019R\u0018\u0010\u001a\u001a\u0004\u0018\u00010\u00108\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b\u001a\u0010\u001b¨\u0006\u001e"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/RemoveLongVideoListFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "", "ids", "", "deleteVideo", "(Ljava/lang/String;)V", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;)V", "Lc/a/d1;", "request", "()Lc/a/d1;", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getEmptyTips", "()Ljava/lang/String;", "onDestroy", "()V", "job", "Lc/a/d1;", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class RemoveLongVideoListFragment extends BaseListFragment<VideoItemBean> {
    public static Function1<? super List<? extends VideoItemBean>, Unit> callBack;

    @Nullable
    private InterfaceC3053d1 job;

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);

    @NotNull
    private static String canvas = "";

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0011\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u001b\u0010\u001cJ@\u0010\r\u001a\u00020\f2\u0006\u0010\u0003\u001a\u00020\u00022)\u0010\u000b\u001a%\u0012\u001b\u0012\u0019\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0005¢\u0006\f\b\u0007\u0012\b\b\b\u0012\u0004\b\b(\t\u0012\u0004\u0012\u00020\n0\u0004¢\u0006\u0004\b\r\u0010\u000eR\"\u0010\u000f\u001a\u00020\u00028\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b\u000f\u0010\u0010\u001a\u0004\b\u0011\u0010\u0012\"\u0004\b\u0013\u0010\u0014RE\u0010\u0015\u001a%\u0012\u001b\u0012\u0019\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0005¢\u0006\f\b\u0007\u0012\b\b\b\u0012\u0004\b\b(\t\u0012\u0004\u0012\u00020\n0\u00048\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\u0015\u0010\u0016\u001a\u0004\b\u0017\u0010\u0018\"\u0004\b\u0019\u0010\u001a¨\u0006\u001d"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/RemoveLongVideoListFragment$Companion;", "", "", "type", "Lkotlin/Function1;", "", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "Lkotlin/ParameterName;", "name", "bean", "", NotificationCompat.CATEGORY_CALL, "Lcom/jbzd/media/movecartoons/ui/mine/RemoveLongVideoListFragment;", "newInstance", "(Ljava/lang/String;Lkotlin/jvm/functions/Function1;)Lcom/jbzd/media/movecartoons/ui/mine/RemoveLongVideoListFragment;", "canvas", "Ljava/lang/String;", "getCanvas", "()Ljava/lang/String;", "setCanvas", "(Ljava/lang/String;)V", "callBack", "Lkotlin/jvm/functions/Function1;", "getCallBack", "()Lkotlin/jvm/functions/Function1;", "setCallBack", "(Lkotlin/jvm/functions/Function1;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final Function1<List<? extends VideoItemBean>, Unit> getCallBack() {
            Function1 function1 = RemoveLongVideoListFragment.callBack;
            if (function1 != null) {
                return function1;
            }
            Intrinsics.throwUninitializedPropertyAccessException("callBack");
            throw null;
        }

        @NotNull
        public final String getCanvas() {
            return RemoveLongVideoListFragment.canvas;
        }

        @NotNull
        public final RemoveLongVideoListFragment newInstance(@NotNull String type, @NotNull Function1<? super List<? extends VideoItemBean>, Unit> call) {
            Intrinsics.checkNotNullParameter(type, "type");
            Intrinsics.checkNotNullParameter(call, "call");
            RemoveLongVideoListFragment removeLongVideoListFragment = new RemoveLongVideoListFragment();
            Companion companion = RemoveLongVideoListFragment.INSTANCE;
            companion.setCallBack(call);
            companion.setCanvas(type);
            return removeLongVideoListFragment;
        }

        public final void setCallBack(@NotNull Function1<? super List<? extends VideoItemBean>, Unit> function1) {
            Intrinsics.checkNotNullParameter(function1, "<set-?>");
            RemoveLongVideoListFragment.callBack = function1;
        }

        public final void setCanvas(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            RemoveLongVideoListFragment.canvas = str;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void deleteVideo(String ids) {
        HashMap m595Q = C1499a.m595Q("ids", ids);
        Unit unit = Unit.INSTANCE;
        this.job = C0917a.m221e(C0917a.f372a, "movie/delHistory", String.class, m595Q, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.RemoveLongVideoListFragment$deleteVideo$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(String str) {
                invoke2(str);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable String str) {
                C2354n.m2409L1("删除成功");
                RemoveLongVideoListFragment.this.refresh();
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.RemoveLongVideoListFragment$deleteVideo$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                RemoveLongVideoListFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public String getEmptyTips() {
        return "当前页面暂无内容";
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.video_long_item_remove;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        return new LinearLayoutManager(requireContext(), 1, false);
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        cancelJob(this.job);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("page", String.valueOf(getCurrentPage()));
        Unit unit = Unit.INSTANCE;
        return C0917a.m222f(c0917a, "movie/history", VideoItemBean.class, hashMap, new Function1<List<? extends VideoItemBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.RemoveLongVideoListFragment$request$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends VideoItemBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends VideoItemBean> list) {
                RemoveLongVideoListFragment.this.didRequestComplete(list);
                RemoveLongVideoListFragment.INSTANCE.getCallBack().invoke(list);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.RemoveLongVideoListFragment$request$3
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(Exception exc) {
                invoke2(exc);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@NotNull Exception it) {
                Intrinsics.checkNotNullParameter(it, "it");
                RemoveLongVideoListFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull final VideoItemBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        VideoItemShowKt.showVideoItemMsg(requireContext, helper, item, (r29 & 8) != 0 ? 1.5d : ShadowDrawableWrapper.COS_45, (r29 & 16) != 0 ? false : false, (r29 & 32) != 0 ? false : true, (r29 & 64) != 0 ? false : true, (r29 & 128) != 0 ? false : false, (r29 & 256) != 0, (r29 & 512) != 0 ? false : false, (r29 & 1024) != 0 ? false : false, (r29 & 2048) != 0 ? false : true);
        String str = item.nickname;
        if (str == null) {
            str = "";
        }
        helper.m3919i(R.id.tv_creatorName, str);
        helper.m3919i(R.id.tv_hisDesc, item.progress);
        helper.m3918h(R.id.right_item, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.RemoveLongVideoListFragment$bindItem$1$1
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
                RemoveLongVideoListFragment removeLongVideoListFragment = RemoveLongVideoListFragment.this;
                String str2 = item.f10000id;
                Intrinsics.checkNotNullExpressionValue(str2, "item.id");
                removeLongVideoListFragment.deleteVideo(str2);
            }
        });
        helper.m3918h(R.id.ll_item, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.RemoveLongVideoListFragment$bindItem$1$2
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
                if (!VideoItemBean.this.getIsAd()) {
                    MovieDetailsActivity.Companion companion = MovieDetailsActivity.INSTANCE;
                    FragmentActivity requireActivity = this.requireActivity();
                    Intrinsics.checkNotNullExpressionValue(requireActivity, "requireActivity()");
                    companion.start(requireActivity, VideoItemBean.this.video_id);
                    return;
                }
                C0840d.a aVar = C0840d.f235a;
                Context requireContext2 = this.requireContext();
                Intrinsics.checkNotNullExpressionValue(requireContext2, "requireContext()");
                AdBean adBean = VideoItemBean.this.f9999ad;
                Intrinsics.checkNotNullExpressionValue(adBean, "item.ad");
                aVar.m176b(requireContext2, adBean);
            }
        });
    }
}
