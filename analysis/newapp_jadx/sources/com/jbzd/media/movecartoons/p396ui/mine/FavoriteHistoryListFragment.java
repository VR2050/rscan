package com.jbzd.media.movecartoons.p396ui.mine;

import android.content.Context;
import android.os.Bundle;
import androidx.core.app.NotificationCompat;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.p396ui.index.home.VideoItemShowKt;
import com.jbzd.media.movecartoons.p396ui.search.child.CommonLongListGridFragment;
import com.qnmd.adnnm.da0yzo.R;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
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
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.InterfaceC3053d1;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000D\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0010\b\n\u0002\b\u0007\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u000e\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0015\u0018\u0000 12\u00020\u0001:\u00011B\u0007¢\u0006\u0004\b0\u0010\u0013J%\u0010\b\u001a\u00020\u0007*\u00020\u00022\u0006\u0010\u0004\u001a\u00020\u00032\b\b\u0002\u0010\u0006\u001a\u00020\u0005H\u0002¢\u0006\u0004\b\b\u0010\tJ\u001b\u0010\n\u001a\u00020\u0007*\u00020\u00022\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\n\u0010\u000bJ\u001b\u0010\f\u001a\u00020\u0007*\u00020\u00022\u0006\u0010\u0004\u001a\u00020\u0003H\u0002¢\u0006\u0004\b\f\u0010\u000bJ\u000f\u0010\u000e\u001a\u00020\rH\u0016¢\u0006\u0004\b\u000e\u0010\u000fJ\u001f\u0010\u0011\u001a\u00020\u00072\u0006\u0010\u0010\u001a\u00020\u00022\u0006\u0010\u0004\u001a\u00020\u0003H\u0016¢\u0006\u0004\b\u0011\u0010\u000bJ\r\u0010\u0012\u001a\u00020\u0007¢\u0006\u0004\b\u0012\u0010\u0013J\r\u0010\u0014\u001a\u00020\u0007¢\u0006\u0004\b\u0014\u0010\u0013J\u0011\u0010\u0016\u001a\u0004\u0018\u00010\u0015H\u0016¢\u0006\u0004\b\u0016\u0010\u0017J\u0015\u0010\u001a\u001a\u00020\u00072\u0006\u0010\u0019\u001a\u00020\u0018¢\u0006\u0004\b\u001a\u0010\u001bR9\u0010\"\u001a\u001e\u0012\u0004\u0012\u00020\u0018\u0012\u0004\u0012\u00020\u00180\u001cj\u000e\u0012\u0004\u0012\u00020\u0018\u0012\u0004\u0012\u00020\u0018`\u001d8B@\u0002X\u0082\u0084\u0002¢\u0006\f\n\u0004\b\u001e\u0010\u001f\u001a\u0004\b \u0010!R\"\u0010#\u001a\u00020\u00058\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b#\u0010$\u001a\u0004\b%\u0010&\"\u0004\b'\u0010(R\u0018\u0010)\u001a\u0004\u0018\u00010\u00158\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b)\u0010*R2\u0010+\u001a\u001e\u0012\u0004\u0012\u00020\u0018\u0012\u0004\u0012\u00020\u00180\u001cj\u000e\u0012\u0004\u0012\u00020\u0018\u0012\u0004\u0012\u00020\u0018`\u001d8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b+\u0010,R\"\u0010-\u001a\u00020\u00058\u0006@\u0006X\u0086\u000e¢\u0006\u0012\n\u0004\b-\u0010$\u001a\u0004\b.\u0010&\"\u0004\b/\u0010(¨\u00062"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/FavoriteHistoryListFragment;", "Lcom/jbzd/media/movecartoons/ui/search/child/CommonLongListGridFragment;", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "item", "", "removeData", "", "checkBoxView", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;Z)V", "selectAllCheckBox", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;)V", "deleteAllCheckBox", "", "getItemLayoutId", "()I", "helper", "bindItem", "selectAllData", "()V", "deleteAllData", "Lc/a/d1;", "request", "()Lc/a/d1;", "", "pageType", "deleteVideo", "(Ljava/lang/String;)V", "Ljava/util/HashMap;", "Lkotlin/collections/HashMap;", "parameter$delegate", "Lkotlin/Lazy;", "getParameter", "()Ljava/util/HashMap;", "parameter", "checkBoxAll", "Z", "getCheckBoxAll", "()Z", "setCheckBoxAll", "(Z)V", "job", "Lc/a/d1;", "checkMap", "Ljava/util/HashMap;", "checkBox", "getCheckBox", "setCheckBox", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class FavoriteHistoryListFragment extends CommonLongListGridFragment {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    public static Function0<Unit> callBack;
    public static String pageType;
    private boolean checkBoxAll;

    @Nullable
    private InterfaceC3053d1 job;
    private boolean checkBox = true;

    @NotNull
    private HashMap<String, String> checkMap = new HashMap<>();

    /* renamed from: parameter$delegate, reason: from kotlin metadata */
    @NotNull
    private final Lazy parameter = LazyKt__LazyJVMKt.lazy(new Function0<HashMap<String, String>>() { // from class: com.jbzd.media.movecartoons.ui.mine.FavoriteHistoryListFragment$parameter$2
        @Override // kotlin.jvm.functions.Function0
        @NotNull
        public final HashMap<String, String> invoke() {
            return C1499a.m595Q("canvas", "long");
        }
    });

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000 \n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0011\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u0016\u0010\u0017J#\u0010\b\u001a\u00020\u00072\u0006\u0010\u0003\u001a\u00020\u00022\f\u0010\u0006\u001a\b\u0012\u0004\u0012\u00020\u00050\u0004¢\u0006\u0004\b\b\u0010\tR\"\u0010\n\u001a\u00020\u00028\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\n\u0010\u000b\u001a\u0004\b\f\u0010\r\"\u0004\b\u000e\u0010\u000fR(\u0010\u0010\u001a\b\u0012\u0004\u0012\u00020\u00050\u00048\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\u0010\u0010\u0011\u001a\u0004\b\u0012\u0010\u0013\"\u0004\b\u0014\u0010\u0015¨\u0006\u0018"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/FavoriteHistoryListFragment$Companion;", "", "", "type", "Lkotlin/Function0;", "", NotificationCompat.CATEGORY_CALL, "Lcom/jbzd/media/movecartoons/ui/mine/FavoriteHistoryListFragment;", "newInstance", "(Ljava/lang/String;Lkotlin/jvm/functions/Function0;)Lcom/jbzd/media/movecartoons/ui/mine/FavoriteHistoryListFragment;", "pageType", "Ljava/lang/String;", "getPageType", "()Ljava/lang/String;", "setPageType", "(Ljava/lang/String;)V", "callBack", "Lkotlin/jvm/functions/Function0;", "getCallBack", "()Lkotlin/jvm/functions/Function0;", "setCallBack", "(Lkotlin/jvm/functions/Function0;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final Function0<Unit> getCallBack() {
            Function0<Unit> function0 = FavoriteHistoryListFragment.callBack;
            if (function0 != null) {
                return function0;
            }
            Intrinsics.throwUninitializedPropertyAccessException("callBack");
            throw null;
        }

        @NotNull
        public final String getPageType() {
            String str = FavoriteHistoryListFragment.pageType;
            if (str != null) {
                return str;
            }
            Intrinsics.throwUninitializedPropertyAccessException("pageType");
            throw null;
        }

        @NotNull
        public final FavoriteHistoryListFragment newInstance(@NotNull String type, @NotNull Function0<Unit> call) {
            Intrinsics.checkNotNullParameter(type, "type");
            Intrinsics.checkNotNullParameter(call, "call");
            setPageType(type);
            FavoriteHistoryListFragment favoriteHistoryListFragment = new FavoriteHistoryListFragment();
            Bundle bundle = new Bundle();
            FavoriteHistoryListFragment.INSTANCE.setCallBack(call);
            Unit unit = Unit.INSTANCE;
            favoriteHistoryListFragment.setArguments(bundle);
            return favoriteHistoryListFragment;
        }

        public final void setCallBack(@NotNull Function0<Unit> function0) {
            Intrinsics.checkNotNullParameter(function0, "<set-?>");
            FavoriteHistoryListFragment.callBack = function0;
        }

        public final void setPageType(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            FavoriteHistoryListFragment.pageType = str;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void checkBoxView(BaseViewHolder baseViewHolder, VideoItemBean videoItemBean, boolean z) {
        if (this.checkMap.containsKey(videoItemBean.f10000id)) {
            if (!z) {
                baseViewHolder.m3917g(R.id.checkbox_del, R.drawable.check_icon);
                return;
            } else {
                this.checkMap.remove(videoItemBean.f10000id);
                baseViewHolder.m3917g(R.id.checkbox_del, R.drawable.uncheck_icon);
                return;
            }
        }
        if (!z) {
            baseViewHolder.m3917g(R.id.checkbox_del, R.drawable.uncheck_icon);
            return;
        }
        HashMap<String, String> hashMap = this.checkMap;
        String str = videoItemBean.f10000id;
        Intrinsics.checkNotNullExpressionValue(str, "item.id");
        hashMap.put(str, "1");
        baseViewHolder.m3917g(R.id.checkbox_del, R.drawable.check_icon);
    }

    public static /* synthetic */ void checkBoxView$default(FavoriteHistoryListFragment favoriteHistoryListFragment, BaseViewHolder baseViewHolder, VideoItemBean videoItemBean, boolean z, int i2, Object obj) {
        if ((i2 & 2) != 0) {
            z = false;
        }
        favoriteHistoryListFragment.checkBoxView(baseViewHolder, videoItemBean, z);
    }

    private final void deleteAllCheckBox(BaseViewHolder baseViewHolder, VideoItemBean videoItemBean) {
        this.checkMap.remove(videoItemBean.f10000id);
        baseViewHolder.m3917g(R.id.checkbox_del, R.drawable.uncheck_icon);
    }

    private final HashMap<String, String> getParameter() {
        return (HashMap) this.parameter.getValue();
    }

    private final void selectAllCheckBox(BaseViewHolder baseViewHolder, VideoItemBean videoItemBean) {
        HashMap<String, String> hashMap = this.checkMap;
        String str = videoItemBean.f10000id;
        Intrinsics.checkNotNullExpressionValue(str, "item.id");
        hashMap.put(str, "1");
        baseViewHolder.m3917g(R.id.checkbox_del, R.drawable.check_icon);
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonLongListGridFragment, com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment, com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    public final void deleteAllData() {
        int size = getAdapter().getData().size();
        if (size <= 0) {
            return;
        }
        int i2 = 0;
        while (true) {
            int i3 = i2 + 1;
            this.checkMap.remove(getAdapter().getData().get(i2).f10000id);
            if (i3 >= size) {
                return;
            } else {
                i2 = i3;
            }
        }
    }

    public final void deleteVideo(@NotNull String pageType2) {
        Intrinsics.checkNotNullParameter(pageType2, "pageType");
        if (this.checkMap.isEmpty()) {
            return;
        }
        StringBuffer stringBuffer = new StringBuffer();
        for (Map.Entry<String, String> entry : this.checkMap.entrySet()) {
            Objects.requireNonNull(entry, "null cannot be cast to non-null type kotlin.collections.Map.Entry<*, *>");
            String key = entry.getKey();
            StringBuilder sb = new StringBuilder();
            sb.append((Object) key);
            sb.append(',');
            stringBuffer.append(sb.toString());
        }
        String stringBuffer2 = stringBuffer.deleteCharAt(stringBuffer.length() - 1).toString();
        Intrinsics.checkNotNullExpressionValue(stringBuffer2, "buffer.deleteCharAt(buffer.length - 1).toString()");
        String str = Intrinsics.areEqual(pageType2, "favorite") ? "movie/delFavorite" : "movie/delHistory";
        HashMap m595Q = C1499a.m595Q("ids", stringBuffer2);
        Unit unit = Unit.INSTANCE;
        this.job = C0917a.m221e(C0917a.f372a, str, VideoItemBean.class, m595Q, new Function1<VideoItemBean, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.FavoriteHistoryListFragment$deleteVideo$2
            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(VideoItemBean videoItemBean) {
                invoke2(videoItemBean);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable VideoItemBean videoItemBean) {
                HashMap hashMap;
                hashMap = FavoriteHistoryListFragment.this.checkMap;
                hashMap.clear();
                FavoriteHistoryListFragment.this.refresh();
                C2354n.m2409L1("删除成功");
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.FavoriteHistoryListFragment$deleteVideo$3
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
                FavoriteHistoryListFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    public final boolean getCheckBox() {
        return this.checkBox;
    }

    public final boolean getCheckBoxAll() {
        return this.checkBoxAll;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonLongListGridFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.video_long_item_fav;
    }

    @Override // com.jbzd.media.movecartoons.p396ui.search.child.BaseCommonVideoListFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        C0917a c0917a = C0917a.f372a;
        String str = Intrinsics.areEqual(INSTANCE.getPageType(), "favorite") ? "movie/favorite" : "movie/history";
        HashMap<String, String> parameter = getParameter();
        parameter.put("page", String.valueOf(getCurrentPage()));
        Unit unit = Unit.INSTANCE;
        return C0917a.m222f(c0917a, str, VideoItemBean.class, parameter, new Function1<List<? extends VideoItemBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.FavoriteHistoryListFragment$request$2
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
                FavoriteHistoryListFragment.this.didRequestComplete(list);
                FavoriteHistoryListFragment.INSTANCE.getCallBack().invoke();
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.FavoriteHistoryListFragment$request$3
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
                FavoriteHistoryListFragment.this.didRequestError();
                FavoriteHistoryListFragment.INSTANCE.getCallBack().invoke();
            }
        }, false, false, null, false, 480);
    }

    public final void selectAllData() {
        int size = getAdapter().getData().size();
        if (size <= 0) {
            return;
        }
        int i2 = 0;
        while (true) {
            int i3 = i2 + 1;
            HashMap<String, String> hashMap = this.checkMap;
            String str = getAdapter().getData().get(i2).f10000id;
            Intrinsics.checkNotNullExpressionValue(str, "adapter.data[i].id");
            hashMap.put(str, "1");
            if (i3 >= size) {
                return;
            } else {
                i2 = i3;
            }
        }
    }

    public final void setCheckBox(boolean z) {
        this.checkBox = z;
    }

    public final void setCheckBoxAll(boolean z) {
        this.checkBoxAll = z;
    }

    /* JADX WARN: Can't rename method to resolve collision */
    @Override // com.jbzd.media.movecartoons.p396ui.search.child.CommonLongListGridFragment, com.jbzd.media.movecartoons.core.BaseListFragment
    public void bindItem(@NotNull final BaseViewHolder helper, @NotNull final VideoItemBean item) {
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        VideoItemShowKt.showVideoItemMsg(requireContext, helper, item, (r29 & 8) != 0 ? 1.5d : ShadowDrawableWrapper.COS_45, (r29 & 16) != 0 ? false : false, (r29 & 32) != 0 ? false : false, (r29 & 64) != 0 ? false : false, (r29 & 128) != 0 ? false : false, (r29 & 256) != 0, (r29 & 512) != 0 ? false : false, (r29 & 1024) != 0 ? false : false, (r29 & 2048) != 0 ? false : true);
        String str = item.like;
        if (str == null) {
            str = "";
        }
        helper.m3919i(R.id.like, str);
        helper.m3918h(R.id.video_check_view, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.FavoriteHistoryListFragment$bindItem$1$1
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
                FavoriteHistoryListFragment.this.checkBoxView(helper, item, true);
            }
        });
        if (getCheckBoxAll()) {
            selectAllCheckBox(helper, item);
        } else {
            deleteAllCheckBox(helper, item);
        }
        helper.m3916f(R.id.video_check_view, getCheckBox());
    }
}
