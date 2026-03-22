package com.jbzd.media.movecartoons.p396ui.mine;

import android.content.Context;
import android.graphics.Color;
import androidx.annotation.RequiresApi;
import androidx.core.app.NotificationCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.google.android.material.shadow.ShadowDrawableWrapper;
import com.jbzd.media.movecartoons.bean.event.EventDownload;
import com.jbzd.media.movecartoons.bean.response.DownloadVideoInfo;
import com.jbzd.media.movecartoons.bean.response.VideoItemBean;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.jbzd.media.movecartoons.p396ui.index.home.VideoItemShowKt;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.jvm.functions.Function0;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.internal.DefaultConstructorMarker;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsKt;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.greenrobot.eventbus.ThreadMode;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0855k0;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p379c.p380a.InterfaceC3053d1;
import p476m.p496b.p497a.C4909c;
import p476m.p496b.p497a.InterfaceC4919m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000R\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\b\u0006\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0004\n\u0002\u0010\b\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0010\u0000\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u000f\u0018\u0000 62\b\u0012\u0004\u0012\u00020\u00020\u0001:\u00016B\u0007¢\u0006\u0004\b5\u0010\u001eJ'\u0010\u0005\u001a\n\u0012\u0004\u0012\u00020\u0002\u0018\u00010\u00032\u000e\u0010\u0004\u001a\n\u0012\u0004\u0012\u00020\u0002\u0018\u00010\u0003H\u0002¢\u0006\u0004\b\u0005\u0010\u0006J\u0017\u0010\b\u001a\u00020\u00022\u0006\u0010\u0007\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\b\u0010\tJ\u0017\u0010\r\u001a\u00020\f2\u0006\u0010\u000b\u001a\u00020\nH\u0002¢\u0006\u0004\b\r\u0010\u000eJ\u0017\u0010\u0010\u001a\u00020\f2\u0006\u0010\u000f\u001a\u00020\nH\u0002¢\u0006\u0004\b\u0010\u0010\u000eJ\u000f\u0010\u0012\u001a\u00020\u0011H\u0016¢\u0006\u0004\b\u0012\u0010\u0013J\u001f\u0010\u0017\u001a\u00020\f2\u0006\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u0016\u001a\u00020\u0002H\u0017¢\u0006\u0004\b\u0017\u0010\u0018J-\u0010\u001b\u001a\u00020\f2\u0006\u0010\u0015\u001a\u00020\u00142\u0006\u0010\u0016\u001a\u00020\u00022\f\u0010\u001a\u001a\b\u0012\u0004\u0012\u00020\u00190\u0003H\u0016¢\u0006\u0004\b\u001b\u0010\u001cJ\u000f\u0010\u001d\u001a\u00020\fH\u0016¢\u0006\u0004\b\u001d\u0010\u001eJ\u000f\u0010\u001f\u001a\u00020\fH\u0016¢\u0006\u0004\b\u001f\u0010\u001eJ\u0017\u0010\"\u001a\u00020\f2\u0006\u0010!\u001a\u00020 H\u0007¢\u0006\u0004\b\"\u0010#J\u0011\u0010%\u001a\u0004\u0018\u00010$H\u0016¢\u0006\u0004\b%\u0010&J\r\u0010'\u001a\u00020\f¢\u0006\u0004\b'\u0010\u001eJ\u000f\u0010)\u001a\u00020(H\u0016¢\u0006\u0004\b)\u0010*J\u000f\u0010+\u001a\u00020\nH\u0016¢\u0006\u0004\b+\u0010,J\u000f\u0010-\u001a\u00020\fH\u0016¢\u0006\u0004\b-\u0010\u001eR\u001c\u0010.\u001a\u00020\u00118\u0006@\u0006X\u0086D¢\u0006\f\n\u0004\b.\u0010/\u001a\u0004\b0\u0010\u0013R\u0018\u00101\u001a\u0004\u0018\u00010$8\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\b1\u00102R\u001c\u00103\u001a\u00020\u00118\u0006@\u0006X\u0086D¢\u0006\f\n\u0004\b3\u0010/\u001a\u0004\b4\u0010\u0013¨\u00067"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/RemoveShortVideoCacheListFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "", "data", "paperData", "(Ljava/util/List;)Ljava/util/List;", "videoBean", "findDownloadInfo", "(Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;)Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "", "task_id", "", "reDownload", "(Ljava/lang/String;)V", "ids", "deleteVideo", "", "getItemLayoutId", "()I", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;)V", "", "payloads", "bindConvert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;Ljava/util/List;)V", "onStart", "()V", "onStop", "Lcom/jbzd/media/movecartoons/bean/event/EventDownload;", "eventDownload", "onEventDownload", "(Lcom/jbzd/media/movecartoons/bean/event/EventDownload;)V", "Lc/a/d1;", "request", "()Lc/a/d1;", "clearAll", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getEmptyTips", "()Ljava/lang/String;", "onDestroy", "TOTAL", "I", "getTOTAL", "job", "Lc/a/d1;", "SELECTED", "getSELECTED", "<init>", "Companion", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class RemoveShortVideoCacheListFragment extends BaseListFragment<VideoItemBean> {

    /* renamed from: Companion, reason: from kotlin metadata */
    @NotNull
    public static final Companion INSTANCE = new Companion(null);
    public static Function1<? super List<? extends VideoItemBean>, Unit> callBack;
    public static String canvas;

    @Nullable
    private InterfaceC3053d1 job;
    private final int TOTAL = 105;
    private final int SELECTED = 104;

    @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u00000\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010 \n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0011\b\u0086\u0003\u0018\u00002\u00020\u0001B\t\b\u0002¢\u0006\u0004\b\u001b\u0010\u001cJ@\u0010\r\u001a\u00020\f2\u0006\u0010\u0003\u001a\u00020\u00022)\u0010\u000b\u001a%\u0012\u001b\u0012\u0019\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0005¢\u0006\f\b\u0007\u0012\b\b\b\u0012\u0004\b\b(\t\u0012\u0004\u0012\u00020\n0\u0004¢\u0006\u0004\b\r\u0010\u000eRE\u0010\u000f\u001a%\u0012\u001b\u0012\u0019\u0012\u0004\u0012\u00020\u0006\u0018\u00010\u0005¢\u0006\f\b\u0007\u0012\b\b\b\u0012\u0004\b\b(\t\u0012\u0004\u0012\u00020\n0\u00048\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\u000f\u0010\u0010\u001a\u0004\b\u0011\u0010\u0012\"\u0004\b\u0013\u0010\u0014R\"\u0010\u0015\u001a\u00020\u00028\u0006@\u0006X\u0086.¢\u0006\u0012\n\u0004\b\u0015\u0010\u0016\u001a\u0004\b\u0017\u0010\u0018\"\u0004\b\u0019\u0010\u001a¨\u0006\u001d"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/mine/RemoveShortVideoCacheListFragment$Companion;", "", "", "type", "Lkotlin/Function1;", "", "Lcom/jbzd/media/movecartoons/bean/response/VideoItemBean;", "Lkotlin/ParameterName;", "name", "bean", "", NotificationCompat.CATEGORY_CALL, "Lcom/jbzd/media/movecartoons/ui/mine/RemoveShortVideoCacheListFragment;", "newInstance", "(Ljava/lang/String;Lkotlin/jvm/functions/Function1;)Lcom/jbzd/media/movecartoons/ui/mine/RemoveShortVideoCacheListFragment;", "callBack", "Lkotlin/jvm/functions/Function1;", "getCallBack", "()Lkotlin/jvm/functions/Function1;", "setCallBack", "(Lkotlin/jvm/functions/Function1;)V", "canvas", "Ljava/lang/String;", "getCanvas", "()Ljava/lang/String;", "setCanvas", "(Ljava/lang/String;)V", "<init>", "()V", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
    public static final class Companion {
        private Companion() {
        }

        public /* synthetic */ Companion(DefaultConstructorMarker defaultConstructorMarker) {
            this();
        }

        @NotNull
        public final Function1<List<? extends VideoItemBean>, Unit> getCallBack() {
            Function1 function1 = RemoveShortVideoCacheListFragment.callBack;
            if (function1 != null) {
                return function1;
            }
            Intrinsics.throwUninitializedPropertyAccessException("callBack");
            throw null;
        }

        @NotNull
        public final String getCanvas() {
            String str = RemoveShortVideoCacheListFragment.canvas;
            if (str != null) {
                return str;
            }
            Intrinsics.throwUninitializedPropertyAccessException("canvas");
            throw null;
        }

        @NotNull
        public final RemoveShortVideoCacheListFragment newInstance(@NotNull String type, @NotNull Function1<? super List<? extends VideoItemBean>, Unit> call) {
            Intrinsics.checkNotNullParameter(type, "type");
            Intrinsics.checkNotNullParameter(call, "call");
            RemoveShortVideoCacheListFragment removeShortVideoCacheListFragment = new RemoveShortVideoCacheListFragment();
            Companion companion = RemoveShortVideoCacheListFragment.INSTANCE;
            companion.setCallBack(call);
            companion.setCanvas(type);
            return removeShortVideoCacheListFragment;
        }

        public final void setCallBack(@NotNull Function1<? super List<? extends VideoItemBean>, Unit> function1) {
            Intrinsics.checkNotNullParameter(function1, "<set-?>");
            RemoveShortVideoCacheListFragment.callBack = function1;
        }

        public final void setCanvas(@NotNull String str) {
            Intrinsics.checkNotNullParameter(str, "<set-?>");
            RemoveShortVideoCacheListFragment.canvas = str;
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void deleteVideo(final String ids) {
        HashMap m595Q = C1499a.m595Q("ids", ids);
        Unit unit = Unit.INSTANCE;
        this.job = C0917a.m221e(C0917a.f372a, "movie/delDownload", String.class, m595Q, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment$deleteVideo$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
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
                for (String str2 : StringsKt__StringsKt.split$default((CharSequence) ids, new String[]{ChineseToPinyinResource.Field.COMMA}, false, 0, 6, (Object) null)) {
                    Objects.requireNonNull(C0855k0.f257a);
                    C0855k0.f258b.m187c(str2);
                }
                this.refresh();
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment$deleteVideo$3
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
                RemoveShortVideoCacheListFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    private final VideoItemBean findDownloadInfo(VideoItemBean videoBean) {
        C0855k0.c cVar = C0855k0.f257a;
        Objects.requireNonNull(cVar);
        C0855k0 c0855k0 = C0855k0.f258b;
        String str = videoBean.f10000id;
        Intrinsics.checkNotNullExpressionValue(str, "videoBean.id");
        DownloadVideoInfo m189e = c0855k0.m189e(str);
        Objects.requireNonNull(cVar);
        String str2 = videoBean.f10000id;
        Intrinsics.checkNotNullExpressionValue(str2, "videoBean.id");
        boolean m191g = c0855k0.m191g(str2);
        if (m189e != null) {
            videoBean.downloadStatus = m189e.status;
            videoBean.downloadSuccessCount = m189e.successCount;
            videoBean.downloadTotal = m189e.files.size();
        } else if (m191g) {
            videoBean.downloadStatus = "wait";
        } else {
            videoBean.downloadStatus = "unknow";
        }
        return videoBean;
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* JADX WARN: Multi-variable type inference failed */
    public final List<VideoItemBean> paperData(List<? extends VideoItemBean> data) {
        if (data == 0) {
            return data;
        }
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(data, 10));
        Iterator it = data.iterator();
        while (it.hasNext()) {
            arrayList.add(findDownloadInfo((VideoItemBean) it.next()));
        }
        return arrayList;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public final void reDownload(String task_id) {
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("task_id", task_id);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "video/redownload", DownloadVideoInfo.class, m595Q, new Function1<DownloadVideoInfo, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment$reDownload$2
            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(DownloadVideoInfo downloadVideoInfo) {
                invoke2(downloadVideoInfo);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable DownloadVideoInfo downloadVideoInfo) {
                if (downloadVideoInfo == null) {
                    return;
                }
                Objects.requireNonNull(C0855k0.f257a);
                C0855k0.f258b.m185a(downloadVideoInfo);
            }
        }, null, false, false, null, false, 496);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.jbzd.media.movecartoons.core.MyThemeFragment, com.qunidayede.supportlibrary.core.view.BaseThemeFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void _$_clearFindViewByIdCache() {
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public /* bridge */ /* synthetic */ void bindConvert(BaseViewHolder baseViewHolder, VideoItemBean videoItemBean, List list) {
        bindConvert2(baseViewHolder, videoItemBean, (List<? extends Object>) list);
    }

    public final void clearAll() {
        List<VideoItemBean> data = getAdapter().getData();
        if (data == null || data.isEmpty()) {
            return;
        }
        List<VideoItemBean> data2 = getAdapter().getData();
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(data2, 10));
        Iterator<T> it = data2.iterator();
        while (it.hasNext()) {
            arrayList.add(((VideoItemBean) it.next()).f10000id);
        }
        deleteVideo(CollectionsKt___CollectionsKt.joinToString$default(arrayList, ChineseToPinyinResource.Field.COMMA, null, null, 0, null, null, 62, null));
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public String getEmptyTips() {
        return "当前页面暂无内容";
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.video_short_item_remove_cache;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        return new LinearLayoutManager(requireContext(), 1, false);
    }

    public final int getSELECTED() {
        return this.SELECTED;
    }

    public final int getTOTAL() {
        return this.TOTAL;
    }

    @Override // androidx.fragment.app.Fragment
    public void onDestroy() {
        super.onDestroy();
        cancelJob(this.job);
    }

    @InterfaceC4919m(threadMode = ThreadMode.MAIN)
    public final void onEventDownload(@NotNull EventDownload eventDownload) {
        Intrinsics.checkNotNullParameter(eventDownload, "eventDownload");
        DownloadVideoInfo downloadVideoInfo = eventDownload.getDownloadVideoInfo();
        Iterator<VideoItemBean> it = getAdapter().getData().iterator();
        int i2 = 0;
        while (it.hasNext()) {
            int i3 = i2 + 1;
            if (Intrinsics.areEqual(it.next().f10000id, downloadVideoInfo.f9947id)) {
                VideoItemBean videoItemBean = getAdapter().getData().get(i2);
                videoItemBean.downloadStatus = downloadVideoInfo.status;
                videoItemBean.downloadSuccessCount = downloadVideoInfo.successCount;
                videoItemBean.downloadTotal = downloadVideoInfo.files.size();
                getAdapter().notifyItemChanged(i2, Integer.valueOf(this.TOTAL));
                return;
            }
            i2 = i3;
        }
    }

    @Override // androidx.fragment.app.Fragment
    public void onStart() {
        super.onStart();
        C4909c.m5569b().m5578k(this);
    }

    @Override // androidx.fragment.app.Fragment
    public void onStop() {
        super.onStop();
        C4909c.m5569b().m5580m(this);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @Nullable
    public InterfaceC3053d1 request() {
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("canvas", INSTANCE.getCanvas());
        hashMap.put("page", String.valueOf(getCurrentPage()));
        Unit unit = Unit.INSTANCE;
        return C0917a.m222f(c0917a, "video/downloadList", VideoItemBean.class, hashMap, new Function1<List<? extends VideoItemBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment$request$2
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
                List<? extends VideoItemBean> paperData;
                paperData = RemoveShortVideoCacheListFragment.this.paperData(list);
                RemoveShortVideoCacheListFragment.this.didRequestComplete(paperData);
                RemoveShortVideoCacheListFragment.INSTANCE.getCallBack().invoke(paperData);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment$request$3
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
                RemoveShortVideoCacheListFragment.this.didRequestError();
            }
        }, false, false, null, false, 480);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
     */
    /* renamed from: bindConvert, reason: avoid collision after fix types in other method */
    public void bindConvert2(@NotNull BaseViewHolder helper, @NotNull VideoItemBean item, @NotNull List<? extends Object> payloads) {
        String str;
        String str2;
        String str3;
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        Intrinsics.checkNotNullParameter(payloads, "payloads");
        super.bindConvert(helper, (BaseViewHolder) item, payloads);
        Iterator<? extends Object> it = payloads.iterator();
        while (it.hasNext()) {
            if (((Integer) it.next()).intValue() == getTOTAL()) {
                String str4 = item.downloadStatus;
                String str5 = "#ff000000";
                int i2 = R.drawable.mine_rect_bg_gold_5;
                String str6 = "";
                if (str4 != null) {
                    switch (str4.hashCode()) {
                        case -1402931637:
                            if (str4.equals("completed")) {
                                str3 = "播放";
                                str = "下载完成";
                                break;
                            }
                            break;
                        case 3641717:
                            if (str4.equals("wait")) {
                                str = "等待下载";
                                str2 = "继续";
                                i2 = R.drawable.btn_gray_download;
                                str3 = str2;
                                str5 = "#ffffff";
                                break;
                            }
                            break;
                        case 95763319:
                            if (str4.equals("doing")) {
                                StringBuilder m586H = C1499a.m586H("缓存中（");
                                m586H.append((Object) getPercentFormat(item.downloadSuccessCount / item.downloadTotal, 2, 1));
                                m586H.append((char) 65289);
                                str6 = m586H.toString();
                                str = "下载中";
                                str2 = "暂停";
                                i2 = R.drawable.mine_rect_bg_blue;
                                str3 = str2;
                                str5 = "#ffffff";
                                break;
                            }
                            break;
                        case 96784904:
                            if (str4.equals("error")) {
                                str = "下载失败";
                                str3 = "下载";
                                break;
                            }
                            break;
                    }
                    helper.m3919i(R.id.tvDownload, str);
                    helper.m3919i(R.id.tvDownload_speed, str6);
                    helper.m3919i(R.id.btn, str3);
                    helper.m3915e(R.id.btn, i2);
                    helper.m3920j(R.id.btn, Color.parseColor(str5));
                }
                str = "重新下载";
                str2 = "未知";
                str3 = str2;
                str5 = "#ffffff";
                helper.m3919i(R.id.tvDownload, str);
                helper.m3919i(R.id.tvDownload_speed, str6);
                helper.m3919i(R.id.btn, str3);
                helper.m3915e(R.id.btn, i2);
                helper.m3920j(R.id.btn, Color.parseColor(str5));
            } else {
                getSELECTED();
            }
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
     */
    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @RequiresApi(23)
    public void bindItem(@NotNull BaseViewHolder helper, @NotNull final VideoItemBean item) {
        String str;
        String str2;
        String str3;
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        Context requireContext = requireContext();
        Intrinsics.checkNotNullExpressionValue(requireContext, "requireContext()");
        VideoItemShowKt.showVideoItemMsg(requireContext, helper, item, (r29 & 8) != 0 ? 1.5d : ShadowDrawableWrapper.COS_45, (r29 & 16) != 0 ? false : false, (r29 & 32) != 0 ? false : true, (r29 & 64) != 0 ? false : true, (r29 & 128) != 0 ? false : false, (r29 & 256) != 0, (r29 & 512) != 0 ? false : false, (r29 & 1024) != 0 ? false : false, (r29 & 2048) != 0 ? false : true);
        String str4 = item.downloadStatus;
        String str5 = "#ff000000";
        int i2 = R.drawable.mine_rect_bg_gold_5;
        String str6 = "";
        if (str4 != null) {
            switch (str4.hashCode()) {
                case -1402931637:
                    if (str4.equals("completed")) {
                        str3 = "播放";
                        str = "下载完成";
                        break;
                    }
                    break;
                case 3641717:
                    if (str4.equals("wait")) {
                        str = "等待下载";
                        str2 = "继续";
                        i2 = R.drawable.btn_gray_download;
                        str3 = str2;
                        str5 = "#ffffff";
                        break;
                    }
                    break;
                case 95763319:
                    if (str4.equals("doing")) {
                        StringBuilder m586H = C1499a.m586H("缓存中（");
                        m586H.append((Object) getPercentFormat(item.downloadSuccessCount / item.downloadTotal, 2, 1));
                        m586H.append((char) 65289);
                        str6 = m586H.toString();
                        str = "下载中";
                        str2 = "暂停";
                        i2 = R.drawable.mine_rect_bg_blue;
                        str3 = str2;
                        str5 = "#ffffff";
                        break;
                    }
                    break;
                case 96784904:
                    if (str4.equals("error")) {
                        str = "下载失败";
                        str3 = "下载";
                        break;
                    }
                    break;
            }
            helper.m3919i(R.id.tvDownload, str);
            helper.m3919i(R.id.tvDownload_speed, str6);
            helper.m3919i(R.id.btn, str3);
            helper.m3915e(R.id.btn, i2);
            helper.m3920j(R.id.btn, Color.parseColor(str5));
            helper.m3918h(R.id.right_item, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment$bindItem$1$1
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
                    RemoveShortVideoCacheListFragment removeShortVideoCacheListFragment = RemoveShortVideoCacheListFragment.this;
                    String str7 = item.f10000id;
                    Intrinsics.checkNotNullExpressionValue(str7, "item.id");
                    removeShortVideoCacheListFragment.deleteVideo(str7);
                }
            });
            helper.m3918h(R.id.ll_item, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment$bindItem$1$2
                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                {
                    super(0);
                }

                @Override // kotlin.jvm.functions.Function0
                public /* bridge */ /* synthetic */ Unit invoke() {
                    invoke2();
                    return Unit.INSTANCE;
                }

                /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
                /* JADX WARN: Code restructure failed: missing block: B:11:0x003a, code lost:
                
                    if (r0.equals("error") == false) goto L28;
                 */
                /* JADX WARN: Code restructure failed: missing block: B:12:0x0073, code lost:
                
                    r0 = r2;
                    r1 = r1.f10000id;
                    kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, "item.id");
                    r0.reDownload(r1);
                 */
                /* JADX WARN: Code restructure failed: missing block: B:15:0x0044, code lost:
                
                    if (r0.equals("doing") == false) goto L28;
                 */
                /* JADX WARN: Code restructure failed: missing block: B:16:0x0051, code lost:
                
                    r2 = com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListActivity.INSTANCE;
                    r3 = r2.requireActivity();
                    kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, "requireActivity()");
                    r2.start(r3, (r13 & 2) != 0 ? null : r1.f10000id, (r13 & 4) != 0 ? null : null, (r13 & 8) != 0 ? null : null, (r13 & 16) != 0 ? false : true);
                 */
                /* JADX WARN: Code restructure failed: missing block: B:19:0x004e, code lost:
                
                    if (r0.equals("wait") == false) goto L28;
                 */
                /* JADX WARN: Code restructure failed: missing block: B:21:0x0070, code lost:
                
                    if (r0.equals("unknow") == false) goto L28;
                 */
                /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
                java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
                	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
                	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
                	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
                	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
                 */
                /* renamed from: invoke, reason: avoid collision after fix types in other method */
                /*
                    Code decompiled incorrectly, please refer to instructions dump.
                    To view partially-correct add '--show-bad-code' argument
                */
                public final void invoke2() {
                    /*
                        r10 = this;
                        com.jbzd.media.movecartoons.bean.response.VideoItemBean r0 = com.jbzd.media.movecartoons.bean.response.VideoItemBean.this
                        boolean r0 = r0.getIsAd()
                        if (r0 == 0) goto L23
                        b.a.a.a.a.d$a r0 = p005b.p006a.p007a.p008a.p009a.C0840d.f235a
                        com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment r1 = r2
                        android.content.Context r1 = r1.requireContext()
                        java.lang.String r2 = "requireContext()"
                        kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r2)
                        com.jbzd.media.movecartoons.bean.response.VideoItemBean r2 = com.jbzd.media.movecartoons.bean.response.VideoItemBean.this
                        com.jbzd.media.movecartoons.bean.response.home.AdBean r2 = r2.f9999ad
                        java.lang.String r3 = "item.ad"
                        kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r3)
                        r0.m176b(r1, r2)
                        goto Ld5
                    L23:
                        com.jbzd.media.movecartoons.bean.response.VideoItemBean r0 = com.jbzd.media.movecartoons.bean.response.VideoItemBean.this
                        java.lang.String r0 = r0.downloadStatus
                        java.lang.String r1 = "requireActivity()"
                        if (r0 == 0) goto Lbd
                        int r2 = r0.hashCode()
                        switch(r2) {
                            case -1402931637: goto L82;
                            case -840472412: goto L6a;
                            case 3641717: goto L48;
                            case 95763319: goto L3e;
                            case 96784904: goto L34;
                            default: goto L32;
                        }
                    L32:
                        goto Lbd
                    L34:
                        java.lang.String r2 = "error"
                        boolean r0 = r0.equals(r2)
                        if (r0 != 0) goto L73
                        goto Lbd
                    L3e:
                        java.lang.String r2 = "doing"
                        boolean r0 = r0.equals(r2)
                        if (r0 != 0) goto L51
                        goto Lbd
                    L48:
                        java.lang.String r2 = "wait"
                        boolean r0 = r0.equals(r2)
                        if (r0 != 0) goto L51
                        goto Lbd
                    L51:
                        com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$Companion r2 = com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListActivity.INSTANCE
                        com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment r0 = r2
                        androidx.fragment.app.FragmentActivity r3 = r0.requireActivity()
                        kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r1)
                        com.jbzd.media.movecartoons.bean.response.VideoItemBean r0 = com.jbzd.media.movecartoons.bean.response.VideoItemBean.this
                        java.lang.String r4 = r0.f10000id
                        r5 = 0
                        r6 = 0
                        r7 = 1
                        r8 = 12
                        r9 = 0
                        com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListActivity.Companion.start$default(r2, r3, r4, r5, r6, r7, r8, r9)
                        goto Ld5
                    L6a:
                        java.lang.String r2 = "unknow"
                        boolean r0 = r0.equals(r2)
                        if (r0 != 0) goto L73
                        goto Lbd
                    L73:
                        com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment r0 = r2
                        com.jbzd.media.movecartoons.bean.response.VideoItemBean r1 = com.jbzd.media.movecartoons.bean.response.VideoItemBean.this
                        java.lang.String r1 = r1.f10000id
                        java.lang.String r2 = "item.id"
                        kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r2)
                        com.jbzd.media.movecartoons.p396ui.mine.RemoveShortVideoCacheListFragment.access$reDownload(r0, r1)
                        goto Ld5
                    L82:
                        java.lang.String r2 = "completed"
                        boolean r0 = r0.equals(r2)
                        if (r0 != 0) goto L8b
                        goto Lbd
                    L8b:
                        java.io.File r0 = new java.io.File
                        com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment r1 = r2
                        android.content.Context r1 = r1.requireContext()
                        java.io.File r1 = r1.getExternalCacheDir()
                        java.lang.StringBuilder r2 = new java.lang.StringBuilder
                        r2.<init>()
                        com.jbzd.media.movecartoons.bean.response.VideoItemBean r3 = com.jbzd.media.movecartoons.bean.response.VideoItemBean.this
                        java.lang.String r3 = r3.f10000id
                        r2.append(r3)
                        java.lang.String r3 = java.io.File.separator
                        r2.append(r3)
                        java.lang.String r3 = "index.m3u8"
                        r2.append(r3)
                        java.lang.String r2 = r2.toString()
                        r0.<init>(r1, r2)
                        com.jbzd.media.movecartoons.bean.response.VideoItemBean r1 = com.jbzd.media.movecartoons.bean.response.VideoItemBean.this
                        java.lang.String r0 = r0.toString()
                        r1.localUrl = r0
                        goto Ld5
                    Lbd:
                        com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$Companion r2 = com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListActivity.INSTANCE
                        com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment r0 = r2
                        androidx.fragment.app.FragmentActivity r3 = r0.requireActivity()
                        kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r1)
                        com.jbzd.media.movecartoons.bean.response.VideoItemBean r0 = com.jbzd.media.movecartoons.bean.response.VideoItemBean.this
                        java.lang.String r4 = r0.f10000id
                        r5 = 0
                        r6 = 0
                        r7 = 1
                        r8 = 12
                        r9 = 0
                        com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListActivity.Companion.start$default(r2, r3, r4, r5, r6, r7, r8, r9)
                    Ld5:
                        return
                    */
                    throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.mine.RemoveShortVideoCacheListFragment$bindItem$1$2.invoke2():void");
                }
            });
        }
        str = "重新下载";
        str2 = "未知";
        str3 = str2;
        str5 = "#ffffff";
        helper.m3919i(R.id.tvDownload, str);
        helper.m3919i(R.id.tvDownload_speed, str6);
        helper.m3919i(R.id.btn, str3);
        helper.m3915e(R.id.btn, i2);
        helper.m3920j(R.id.btn, Color.parseColor(str5));
        helper.m3918h(R.id.right_item, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment$bindItem$1$1
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
                RemoveShortVideoCacheListFragment removeShortVideoCacheListFragment = RemoveShortVideoCacheListFragment.this;
                String str7 = item.f10000id;
                Intrinsics.checkNotNullExpressionValue(str7, "item.id");
                removeShortVideoCacheListFragment.deleteVideo(str7);
            }
        });
        helper.m3918h(R.id.ll_item, new Function0<Unit>() { // from class: com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment$bindItem$1$2
            /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
            {
                super(0);
            }

            @Override // kotlin.jvm.functions.Function0
            public /* bridge */ /* synthetic */ Unit invoke() {
                invoke2();
                return Unit.INSTANCE;
            }

            /* renamed from: invoke */
            public final void invoke2() {
                /*
                    this = this;
                    com.jbzd.media.movecartoons.bean.response.VideoItemBean r0 = com.jbzd.media.movecartoons.bean.response.VideoItemBean.this
                    boolean r0 = r0.getIsAd()
                    if (r0 == 0) goto L23
                    b.a.a.a.a.d$a r0 = p005b.p006a.p007a.p008a.p009a.C0840d.f235a
                    com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment r1 = r2
                    android.content.Context r1 = r1.requireContext()
                    java.lang.String r2 = "requireContext()"
                    kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r2)
                    com.jbzd.media.movecartoons.bean.response.VideoItemBean r2 = com.jbzd.media.movecartoons.bean.response.VideoItemBean.this
                    com.jbzd.media.movecartoons.bean.response.home.AdBean r2 = r2.f9999ad
                    java.lang.String r3 = "item.ad"
                    kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r2, r3)
                    r0.m176b(r1, r2)
                    goto Ld5
                L23:
                    com.jbzd.media.movecartoons.bean.response.VideoItemBean r0 = com.jbzd.media.movecartoons.bean.response.VideoItemBean.this
                    java.lang.String r0 = r0.downloadStatus
                    java.lang.String r1 = "requireActivity()"
                    if (r0 == 0) goto Lbd
                    int r2 = r0.hashCode()
                    switch(r2) {
                        case -1402931637: goto L82;
                        case -840472412: goto L6a;
                        case 3641717: goto L48;
                        case 95763319: goto L3e;
                        case 96784904: goto L34;
                        default: goto L32;
                    }
                L32:
                    goto Lbd
                L34:
                    java.lang.String r2 = "error"
                    boolean r0 = r0.equals(r2)
                    if (r0 != 0) goto L73
                    goto Lbd
                L3e:
                    java.lang.String r2 = "doing"
                    boolean r0 = r0.equals(r2)
                    if (r0 != 0) goto L51
                    goto Lbd
                L48:
                    java.lang.String r2 = "wait"
                    boolean r0 = r0.equals(r2)
                    if (r0 != 0) goto L51
                    goto Lbd
                L51:
                    com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$Companion r2 = com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListActivity.INSTANCE
                    com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment r0 = r2
                    androidx.fragment.app.FragmentActivity r3 = r0.requireActivity()
                    kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r1)
                    com.jbzd.media.movecartoons.bean.response.VideoItemBean r0 = com.jbzd.media.movecartoons.bean.response.VideoItemBean.this
                    java.lang.String r4 = r0.f10000id
                    r5 = 0
                    r6 = 0
                    r7 = 1
                    r8 = 12
                    r9 = 0
                    com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListActivity.Companion.start$default(r2, r3, r4, r5, r6, r7, r8, r9)
                    goto Ld5
                L6a:
                    java.lang.String r2 = "unknow"
                    boolean r0 = r0.equals(r2)
                    if (r0 != 0) goto L73
                    goto Lbd
                L73:
                    com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment r0 = r2
                    com.jbzd.media.movecartoons.bean.response.VideoItemBean r1 = com.jbzd.media.movecartoons.bean.response.VideoItemBean.this
                    java.lang.String r1 = r1.f10000id
                    java.lang.String r2 = "item.id"
                    kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r1, r2)
                    com.jbzd.media.movecartoons.p396ui.mine.RemoveShortVideoCacheListFragment.access$reDownload(r0, r1)
                    goto Ld5
                L82:
                    java.lang.String r2 = "completed"
                    boolean r0 = r0.equals(r2)
                    if (r0 != 0) goto L8b
                    goto Lbd
                L8b:
                    java.io.File r0 = new java.io.File
                    com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment r1 = r2
                    android.content.Context r1 = r1.requireContext()
                    java.io.File r1 = r1.getExternalCacheDir()
                    java.lang.StringBuilder r2 = new java.lang.StringBuilder
                    r2.<init>()
                    com.jbzd.media.movecartoons.bean.response.VideoItemBean r3 = com.jbzd.media.movecartoons.bean.response.VideoItemBean.this
                    java.lang.String r3 = r3.f10000id
                    r2.append(r3)
                    java.lang.String r3 = java.io.File.separator
                    r2.append(r3)
                    java.lang.String r3 = "index.m3u8"
                    r2.append(r3)
                    java.lang.String r2 = r2.toString()
                    r0.<init>(r1, r2)
                    com.jbzd.media.movecartoons.bean.response.VideoItemBean r1 = com.jbzd.media.movecartoons.bean.response.VideoItemBean.this
                    java.lang.String r0 = r0.toString()
                    r1.localUrl = r0
                    goto Ld5
                Lbd:
                    com.jbzd.media.movecartoons.ui.index.selected.child.PlayListActivity$Companion r2 = com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListActivity.INSTANCE
                    com.jbzd.media.movecartoons.ui.mine.RemoveShortVideoCacheListFragment r0 = r2
                    androidx.fragment.app.FragmentActivity r3 = r0.requireActivity()
                    kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r3, r1)
                    com.jbzd.media.movecartoons.bean.response.VideoItemBean r0 = com.jbzd.media.movecartoons.bean.response.VideoItemBean.this
                    java.lang.String r4 = r0.f10000id
                    r5 = 0
                    r6 = 0
                    r7 = 1
                    r8 = 12
                    r9 = 0
                    com.jbzd.media.movecartoons.p396ui.index.selected.child.PlayListActivity.Companion.start$default(r2, r3, r4, r5, r6, r7, r8, r9)
                Ld5:
                    return
                */
                throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.mine.RemoveShortVideoCacheListFragment$bindItem$1$2.invoke2():void");
            }
        });
    }
}
