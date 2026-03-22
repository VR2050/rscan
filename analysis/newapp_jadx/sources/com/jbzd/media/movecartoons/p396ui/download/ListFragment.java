package com.jbzd.media.movecartoons.p396ui.download;

import android.graphics.Color;
import android.widget.ImageView;
import android.widget.ProgressBar;
import androidx.recyclerview.widget.RecyclerView;
import com.chad.library.adapter.base.viewholder.BaseViewHolder;
import com.jbzd.media.movecartoons.bean.event.EventDownload;
import com.jbzd.media.movecartoons.bean.response.DownloadListBean;
import com.jbzd.media.movecartoons.bean.response.DownloadVideoInfo;
import com.jbzd.media.movecartoons.core.BaseListFragment;
import com.jbzd.media.movecartoons.view.XDividerItemDecoration;
import com.qnmd.adnnm.da0yzo.R;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;
import kotlin.Metadata;
import kotlin.ResultKt;
import kotlin.Unit;
import kotlin.collections.ArraysKt___ArraysKt;
import kotlin.collections.CollectionsKt__IterablesKt;
import kotlin.collections.CollectionsKt___CollectionsKt;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt__IntrinsicsKt;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlin.coroutines.jvm.internal.SuspendLambda;
import kotlin.jvm.functions.Function1;
import kotlin.jvm.functions.Function2;
import kotlin.jvm.internal.Intrinsics;
import kotlin.text.StringsKt__StringsJVMKt;
import kotlin.text.StringsKt__StringsKt;
import net.sourceforge.pinyin4j.ChineseToPinyinResource;
import org.greenrobot.eventbus.ThreadMode;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import p005b.p006a.p007a.p008a.p009a.C0855k0;
import p005b.p006a.p007a.p008a.p017r.C0917a;
import p005b.p131d.p132a.p133a.C1499a;
import p005b.p199l.p200a.p201a.p250p1.C2354n;
import p379c.p380a.AbstractC3077l1;
import p379c.p380a.C3079m0;
import p379c.p380a.C3109w0;
import p379c.p380a.InterfaceC3053d1;
import p379c.p380a.InterfaceC3055e0;
import p379c.p380a.p381a.C2964m;
import p476m.p496b.p497a.C4909c;
import p476m.p496b.p497a.InterfaceC4919m;

@Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000t\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0010\u0011\n\u0002\u0010\u000e\n\u0000\n\u0002\u0010\u0002\n\u0002\b\u0005\n\u0002\u0010 \n\u0002\b\u0006\n\u0002\u0010\u000b\n\u0002\b\u0007\n\u0002\u0010\b\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0002\b\u0003\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0000\n\u0002\b\u0006\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0004\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0002\b\u000f\u0018\u00002\b\u0012\u0004\u0012\u00020\u00020\u0001B\u0007¢\u0006\u0004\bK\u0010\u0018J#\u0010\u0007\u001a\u00020\u00062\u0012\u0010\u0005\u001a\n\u0012\u0006\b\u0001\u0012\u00020\u00040\u0003\"\u00020\u0004H\u0002¢\u0006\u0004\b\u0007\u0010\bJ\u0017\u0010\n\u001a\u00020\u00062\u0006\u0010\t\u001a\u00020\u0004H\u0002¢\u0006\u0004\b\n\u0010\u000bJ'\u0010\u000e\u001a\n\u0012\u0004\u0012\u00020\u0002\u0018\u00010\f2\u000e\u0010\r\u001a\n\u0012\u0004\u0012\u00020\u0002\u0018\u00010\fH\u0002¢\u0006\u0004\b\u000e\u0010\u000fJ\u0017\u0010\u0011\u001a\u00020\u00022\u0006\u0010\u0010\u001a\u00020\u0002H\u0002¢\u0006\u0004\b\u0011\u0010\u0012J\u0015\u0010\u0015\u001a\u00020\u00062\u0006\u0010\u0014\u001a\u00020\u0013¢\u0006\u0004\b\u0015\u0010\u0016J\u000f\u0010\u0017\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u0017\u0010\u0018J\u0015\u0010\u0019\u001a\u00020\u00062\u0006\u0010\u0014\u001a\u00020\u0013¢\u0006\u0004\b\u0019\u0010\u0016J\r\u0010\u001a\u001a\u00020\u0006¢\u0006\u0004\b\u001a\u0010\u0018J\u000f\u0010\u001c\u001a\u00020\u001bH\u0016¢\u0006\u0004\b\u001c\u0010\u001dJ\u000f\u0010\u001e\u001a\u00020\u0006H\u0016¢\u0006\u0004\b\u001e\u0010\u0018J\u000f\u0010\u001f\u001a\u00020\u0004H\u0016¢\u0006\u0004\b\u001f\u0010 J\u000f\u0010!\u001a\u00020\u0006H\u0016¢\u0006\u0004\b!\u0010\u0018J\u0017\u0010$\u001a\u00020\u00062\u0006\u0010#\u001a\u00020\"H\u0007¢\u0006\u0004\b$\u0010%J-\u0010+\u001a\u00020\u00062\u0006\u0010'\u001a\u00020&2\u0006\u0010(\u001a\u00020\u00022\f\u0010*\u001a\b\u0012\u0004\u0012\u00020)0\fH\u0016¢\u0006\u0004\b+\u0010,J\u001f\u0010-\u001a\u00020\u00062\u0006\u0010'\u001a\u00020&2\u0006\u0010(\u001a\u00020\u0002H\u0016¢\u0006\u0004\b-\u0010.J\u000f\u0010/\u001a\u00020\u0006H\u0016¢\u0006\u0004\b/\u0010\u0018J3\u00105\u001a\u00020\u00062\u0012\u00101\u001a\u000e\u0012\u0004\u0012\u00020\u0002\u0012\u0004\u0012\u00020&002\u0006\u00103\u001a\u0002022\u0006\u00104\u001a\u00020\u001bH\u0016¢\u0006\u0004\b5\u00106J\u000f\u00108\u001a\u000207H\u0016¢\u0006\u0004\b8\u00109J\u000f\u0010;\u001a\u00020:H\u0016¢\u0006\u0004\b;\u0010<J\u000f\u0010>\u001a\u00020=H\u0016¢\u0006\u0004\b>\u0010?J\u000f\u0010@\u001a\u00020\u001bH\u0016¢\u0006\u0004\b@\u0010\u001dJ\u000f\u0010A\u001a\u00020\u001bH\u0016¢\u0006\u0004\bA\u0010\u001dJ\u000f\u0010B\u001a\u00020\u001bH\u0016¢\u0006\u0004\bB\u0010\u001dJ\u000f\u0010C\u001a\u00020\u001bH\u0016¢\u0006\u0004\bC\u0010\u001dR\u0016\u0010D\u001a\u00020\u00138\u0002@\u0002X\u0082\u000e¢\u0006\u0006\n\u0004\bD\u0010ER\u001c\u0010F\u001a\u00020\u001b8\u0006@\u0006X\u0086D¢\u0006\f\n\u0004\bF\u0010G\u001a\u0004\bH\u0010\u001dR\u001c\u0010I\u001a\u00020\u001b8\u0006@\u0006X\u0086D¢\u0006\f\n\u0004\bI\u0010G\u001a\u0004\bJ\u0010\u001d¨\u0006L"}, m5311d2 = {"Lcom/jbzd/media/movecartoons/ui/download/ListFragment;", "Lcom/jbzd/media/movecartoons/core/BaseListFragment;", "Lcom/jbzd/media/movecartoons/bean/response/DownloadListBean;", "", "", "id", "", "deleteRequest", "([Ljava/lang/String;)V", "task_id", "reDownload", "(Ljava/lang/String;)V", "", "data", "paperData", "(Ljava/util/List;)Ljava/util/List;", "videoBean", "findDownloadInfo", "(Lcom/jbzd/media/movecartoons/bean/response/DownloadListBean;)Lcom/jbzd/media/movecartoons/bean/response/DownloadListBean;", "", "value", "openEdit", "(Z)V", "initViews", "()V", "select", "clearAll", "", "getItemLayoutId", "()I", "onStart", "getEmptyTips", "()Ljava/lang/String;", "onStop", "Lcom/jbzd/media/movecartoons/bean/event/EventDownload;", "eventDownload", "onEventDownload", "(Lcom/jbzd/media/movecartoons/bean/event/EventDownload;)V", "Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;", "helper", "item", "", "payloads", "bindConvert", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/DownloadListBean;Ljava/util/List;)V", "bindItem", "(Lcom/chad/library/adapter/base/viewholder/BaseViewHolder;Lcom/jbzd/media/movecartoons/bean/response/DownloadListBean;)V", "registerItemChildEvent", "Lcom/chad/library/adapter/base/BaseQuickAdapter;", "adapter", "Landroid/view/View;", "view", "position", "onItemClick", "(Lcom/chad/library/adapter/base/BaseQuickAdapter;Landroid/view/View;I)V", "Lc/a/d1;", "request", "()Lc/a/d1;", "Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "getLayoutManager", "()Landroidx/recyclerview/widget/RecyclerView$LayoutManager;", "Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getItemDecoration", "()Landroidx/recyclerview/widget/RecyclerView$ItemDecoration;", "getLeftPadding", "getRightPadding", "getBottomPadding", "getTopPadding", "isEdit", "Z", "TOTAL", "I", "getTOTAL", "SELECTED", "getSELECTED", "<init>", "app_release"}, m5312k = 1, m5313mv = {1, 5, 1})
/* loaded from: classes2.dex */
public final class ListFragment extends BaseListFragment<DownloadListBean> {
    private boolean isEdit;
    private final int TOTAL = 105;
    private final int SELECTED = 104;

    /* JADX INFO: Access modifiers changed from: private */
    public final void deleteRequest(final String... id) {
        C0917a c0917a = C0917a.f372a;
        HashMap hashMap = new HashMap();
        hashMap.put("ids", ArraysKt___ArraysKt.joinToString$default(id, ChineseToPinyinResource.Field.COMMA, (CharSequence) null, (CharSequence) null, 0, (CharSequence) null, (Function1) null, 62, (Object) null));
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "movie/delDownload", String.class, hashMap, new Function1<String, Unit>() { // from class: com.jbzd.media.movecartoons.ui.download.ListFragment$deleteRequest$2
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
                Objects.requireNonNull(C0855k0.f257a);
                C0855k0 c0855k0 = C0855k0.f258b;
                String[] strArr = id;
                c0855k0.m187c((String[]) Arrays.copyOf(strArr, strArr.length));
                this.refresh();
            }
        }, null, false, false, null, false, 496);
    }

    private final DownloadListBean findDownloadInfo(DownloadListBean videoBean) {
        C0855k0.c cVar = C0855k0.f257a;
        Objects.requireNonNull(cVar);
        C0855k0 c0855k0 = C0855k0.f258b;
        String str = videoBean.f9946id;
        Intrinsics.checkNotNullExpressionValue(str, "videoBean.id");
        DownloadVideoInfo m189e = c0855k0.m189e(str);
        Objects.requireNonNull(cVar);
        String str2 = videoBean.f9946id;
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
    public final List<DownloadListBean> paperData(List<? extends DownloadListBean> data) {
        if (data == 0) {
            return data;
        }
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(data, 10));
        Iterator it = data.iterator();
        while (it.hasNext()) {
            arrayList.add(findDownloadInfo((DownloadListBean) it.next()));
        }
        return arrayList;
    }

    private final void reDownload(String task_id) {
        C0917a c0917a = C0917a.f372a;
        HashMap m595Q = C1499a.m595Q("ids", task_id);
        Unit unit = Unit.INSTANCE;
        C0917a.m221e(c0917a, "movie/delDownload", DownloadVideoInfo.class, m595Q, new Function1<DownloadVideoInfo, Unit>() { // from class: com.jbzd.media.movecartoons.ui.download.ListFragment$reDownload$2
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
    public /* bridge */ /* synthetic */ void bindConvert(BaseViewHolder baseViewHolder, DownloadListBean downloadListBean, List list) {
        bindConvert2(baseViewHolder, downloadListBean, (List<? extends Object>) list);
    }

    public final void clearAll() {
        List<DownloadListBean> data = getAdapter().getData();
        if (data == null || data.isEmpty()) {
            return;
        }
        String[] strArr = new String[1];
        List<DownloadListBean> data2 = getAdapter().getData();
        ArrayList arrayList = new ArrayList();
        for (Object obj : data2) {
            if (((DownloadListBean) obj).isSelect) {
                arrayList.add(obj);
            }
        }
        ArrayList arrayList2 = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(arrayList, 10));
        Iterator it = arrayList.iterator();
        while (it.hasNext()) {
            arrayList2.add(((DownloadListBean) it.next()).f9946id);
        }
        strArr[0] = CollectionsKt___CollectionsKt.joinToString$default(arrayList2, ChineseToPinyinResource.Field.COMMA, null, null, 0, null, null, 62, null);
        deleteRequest(strArr);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getBottomPadding() {
        return C2354n.m2425R(requireContext(), 12.0f);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public String getEmptyTips() {
        return "还没有下载影片哦～";
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.ItemDecoration getItemDecoration() {
        XDividerItemDecoration xDividerItemDecoration = new XDividerItemDecoration(getContext(), 1);
        xDividerItemDecoration.setDrawable(getResources().getDrawable(R.drawable.divider_line));
        return xDividerItemDecoration;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getItemLayoutId() {
        return R.layout.home_video_downloading;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public RecyclerView.LayoutManager getLayoutManager() {
        return super.getLayoutManager();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getLeftPadding() {
        return C2354n.m2425R(requireContext(), 12.0f);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getRightPadding() {
        return C2354n.m2425R(requireContext(), 12.0f);
    }

    public final int getSELECTED() {
        return this.SELECTED;
    }

    public final int getTOTAL() {
        return this.TOTAL;
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public int getTopPadding() {
        return C2354n.m2425R(requireContext(), 2.0f);
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment, com.qunidayede.supportlibrary.core.view.BaseFragment
    public void initViews() {
        super.initViews();
        getAdapter();
        new DownloadAdapterCall();
    }

    @InterfaceC4919m(threadMode = ThreadMode.MAIN)
    public final void onEventDownload(@NotNull EventDownload eventDownload) {
        Intrinsics.checkNotNullParameter(eventDownload, "eventDownload");
        DownloadVideoInfo downloadVideoInfo = eventDownload.getDownloadVideoInfo();
        Iterator<DownloadListBean> it = getAdapter().getData().iterator();
        int i2 = 0;
        while (it.hasNext()) {
            int i3 = i2 + 1;
            if (Intrinsics.areEqual(it.next().f9946id, downloadVideoInfo.f9947id)) {
                DownloadListBean downloadListBean = getAdapter().getData().get(i2);
                downloadListBean.downloadStatus = downloadVideoInfo.status;
                downloadListBean.downloadSuccessCount = downloadVideoInfo.successCount;
                downloadListBean.downloadTotal = downloadVideoInfo.files.size();
                getAdapter().notifyItemChanged(i2, Integer.valueOf(this.TOTAL));
                return;
            }
            i2 = i3;
        }
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    /* JADX WARN: Code restructure failed: missing block: B:11:0x0043, code lost:
    
        if (r4.equals("error") == false) goto L28;
     */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x0071, code lost:
    
        r4 = r5.f9946id;
        kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r4, "itemBean.id");
        reDownload(r4);
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x004d, code lost:
    
        if (r4.equals("doing") == false) goto L28;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x0059, code lost:
    
        r4 = com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity.INSTANCE;
        r0 = requireContext();
        kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, "requireContext()");
        r4.start(r0, r5.f9946id);
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x0056, code lost:
    
        if (r4.equals("wait") == false) goto L28;
     */
    /* JADX WARN: Code restructure failed: missing block: B:21:0x006e, code lost:
    
        if (r4.equals("unknow") == false) goto L28;
     */
    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
     */
    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void onItemClick(@org.jetbrains.annotations.NotNull com.chad.library.adapter.base.BaseQuickAdapter<com.jbzd.media.movecartoons.bean.response.DownloadListBean, com.chad.library.adapter.base.viewholder.BaseViewHolder> r4, @org.jetbrains.annotations.NotNull android.view.View r5, int r6) {
        /*
            r3 = this;
            java.lang.String r0 = "adapter"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r4, r0)
            java.lang.String r0 = "view"
            kotlin.jvm.internal.Intrinsics.checkNotNullParameter(r5, r0)
            super.onItemClick(r4, r5, r6)
            java.lang.Object r5 = r4.getItem(r6)
            com.jbzd.media.movecartoons.bean.response.DownloadListBean r5 = (com.jbzd.media.movecartoons.bean.response.DownloadListBean) r5
            boolean r0 = r3.isEdit
            if (r0 == 0) goto L2e
            java.lang.Object r5 = r4.getItem(r6)
            com.jbzd.media.movecartoons.bean.response.DownloadListBean r5 = (com.jbzd.media.movecartoons.bean.response.DownloadListBean) r5
            boolean r0 = r5.isSelect
            r0 = r0 ^ 1
            r5.isSelect = r0
            int r5 = r3.SELECTED
            java.lang.Integer r5 = java.lang.Integer.valueOf(r5)
            r4.notifyItemChanged(r6, r5)
            goto Lcb
        L2e:
            java.lang.String r4 = r5.downloadStatus
            java.lang.String r6 = "requireContext()"
            if (r4 == 0) goto Lbd
            int r0 = r4.hashCode()
            switch(r0) {
                case -1402931637: goto L7c;
                case -840472412: goto L68;
                case 3641717: goto L50;
                case 95763319: goto L47;
                case 96784904: goto L3d;
                default: goto L3b;
            }
        L3b:
            goto Lbd
        L3d:
            java.lang.String r0 = "error"
            boolean r4 = r4.equals(r0)
            if (r4 != 0) goto L71
            goto Lbd
        L47:
            java.lang.String r0 = "doing"
            boolean r4 = r4.equals(r0)
            if (r4 != 0) goto L59
            goto Lbd
        L50:
            java.lang.String r0 = "wait"
            boolean r4 = r4.equals(r0)
            if (r4 != 0) goto L59
            goto Lbd
        L59:
            com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$Companion r4 = com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity.INSTANCE
            android.content.Context r0 = r3.requireContext()
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r6)
            java.lang.String r5 = r5.f9946id
            r4.start(r0, r5)
            goto Lcb
        L68:
            java.lang.String r0 = "unknow"
            boolean r4 = r4.equals(r0)
            if (r4 != 0) goto L71
            goto Lbd
        L71:
            java.lang.String r4 = r5.f9946id
            java.lang.String r5 = "itemBean.id"
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r4, r5)
            r3.reDownload(r4)
            goto Lcb
        L7c:
            java.lang.String r0 = "completed"
            boolean r4 = r4.equals(r0)
            if (r4 != 0) goto L85
            goto Lbd
        L85:
            java.io.File r4 = new java.io.File
            android.content.Context r0 = r3.requireContext()
            java.io.File r0 = r0.getExternalCacheDir()
            java.lang.StringBuilder r1 = new java.lang.StringBuilder
            r1.<init>()
            java.lang.String r2 = r5.f9946id
            r1.append(r2)
            java.lang.String r2 = java.io.File.separator
            r1.append(r2)
            java.lang.String r2 = "index.m3u8"
            r1.append(r2)
            java.lang.String r1 = r1.toString()
            r4.<init>(r0, r1)
            java.lang.String r4 = r4.toString()
            r5.localUrl = r4
            com.jbzd.media.movecartoons.ui.download.LocalPlayerActivity$Companion r4 = com.jbzd.media.movecartoons.p396ui.download.LocalPlayerActivity.INSTANCE
            android.content.Context r0 = r3.requireContext()
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r6)
            r4.start(r0, r5)
            goto Lcb
        Lbd:
            com.jbzd.media.movecartoons.ui.movie.MovieDetailsActivity$Companion r4 = com.jbzd.media.movecartoons.p396ui.movie.MovieDetailsActivity.INSTANCE
            android.content.Context r0 = r3.requireContext()
            kotlin.jvm.internal.Intrinsics.checkNotNullExpressionValue(r0, r6)
            java.lang.String r5 = r5.f9946id
            r4.start(r0, r5)
        Lcb:
            return
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.download.ListFragment.onItemClick(com.chad.library.adapter.base.BaseQuickAdapter, android.view.View, int):void");
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

    public final void openEdit(boolean value) {
        this.isEdit = value;
        getAdapter().notifyDataSetChanged();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    public void registerItemChildEvent() {
        super.registerItemChildEvent();
    }

    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    @NotNull
    public InterfaceC3053d1 request() {
        HashMap hashMap = new HashMap();
        hashMap.put("page", String.valueOf(getCurrentPage()));
        return C0917a.m222f(C0917a.f372a, "movie/download", DownloadListBean.class, hashMap, new Function1<List<? extends DownloadListBean>, Unit>() { // from class: com.jbzd.media.movecartoons.ui.download.ListFragment$request$2

            @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
            @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.download.ListFragment$request$2$1", m5320f = "DownloadActivity.kt", m5321i = {}, m5322l = {443}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
            /* renamed from: com.jbzd.media.movecartoons.ui.download.ListFragment$request$2$1 */
            public static final class C37521 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
                public final /* synthetic */ List<DownloadListBean> $it;
                public int label;
                public final /* synthetic */ ListFragment this$0;

                @Metadata(m5309bv = {1, 0, 3}, m5310d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u0010\u0002\u001a\u00020\u0001*\u00020\u0000H\u008a@¢\u0006\u0004\b\u0002\u0010\u0003"}, m5311d2 = {"Lc/a/e0;", "", "<anonymous>", "(Lc/a/e0;)V"}, m5312k = 3, m5313mv = {1, 5, 1})
                @DebugMetadata(m5319c = "com.jbzd.media.movecartoons.ui.download.ListFragment$request$2$1$1", m5320f = "DownloadActivity.kt", m5321i = {}, m5322l = {}, m5323m = "invokeSuspend", m5324n = {}, m5325s = {})
                /* renamed from: com.jbzd.media.movecartoons.ui.download.ListFragment$request$2$1$1, reason: invalid class name */
                public static final class AnonymousClass1 extends SuspendLambda implements Function2<InterfaceC3055e0, Continuation<? super Unit>, Object> {
                    public final /* synthetic */ List<DownloadListBean> $list;
                    public int label;
                    public final /* synthetic */ ListFragment this$0;

                    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                    /* JADX WARN: Multi-variable type inference failed */
                    public AnonymousClass1(ListFragment listFragment, List<? extends DownloadListBean> list, Continuation<? super AnonymousClass1> continuation) {
                        super(2, continuation);
                        this.this$0 = listFragment;
                        this.$list = list;
                    }

                    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                    @NotNull
                    public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
                        return new AnonymousClass1(this.this$0, this.$list, continuation);
                    }

                    @Override // kotlin.jvm.functions.Function2
                    @Nullable
                    public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
                        return ((AnonymousClass1) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
                    }

                    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                    @Nullable
                    public final Object invokeSuspend(@NotNull Object obj) {
                        IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
                        if (this.label != 0) {
                            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                        }
                        ResultKt.throwOnFailure(obj);
                        this.this$0.didRequestComplete(this.$list);
                        return Unit.INSTANCE;
                    }
                }

                /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
                /* JADX WARN: Multi-variable type inference failed */
                public C37521(ListFragment listFragment, List<? extends DownloadListBean> list, Continuation<? super C37521> continuation) {
                    super(2, continuation);
                    this.this$0 = listFragment;
                    this.$it = list;
                }

                @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                @NotNull
                public final Continuation<Unit> create(@Nullable Object obj, @NotNull Continuation<?> continuation) {
                    return new C37521(this.this$0, this.$it, continuation);
                }

                @Override // kotlin.jvm.functions.Function2
                @Nullable
                public final Object invoke(@NotNull InterfaceC3055e0 interfaceC3055e0, @Nullable Continuation<? super Unit> continuation) {
                    return ((C37521) create(interfaceC3055e0, continuation)).invokeSuspend(Unit.INSTANCE);
                }

                @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
                @Nullable
                public final Object invokeSuspend(@NotNull Object obj) {
                    List paperData;
                    Object coroutine_suspended = IntrinsicsKt__IntrinsicsKt.getCOROUTINE_SUSPENDED();
                    int i2 = this.label;
                    if (i2 == 0) {
                        ResultKt.throwOnFailure(obj);
                        paperData = this.this$0.paperData(this.$it);
                        C3079m0 c3079m0 = C3079m0.f8432c;
                        AbstractC3077l1 abstractC3077l1 = C2964m.f8127b;
                        AnonymousClass1 anonymousClass1 = new AnonymousClass1(this.this$0, paperData, null);
                        this.label = 1;
                        if (C2354n.m2471e2(abstractC3077l1, anonymousClass1, this) == coroutine_suspended) {
                            return coroutine_suspended;
                        }
                    } else {
                        if (i2 != 1) {
                            throw new IllegalStateException("call to 'resume' before 'invoke' with coroutine");
                        }
                        ResultKt.throwOnFailure(obj);
                    }
                    return Unit.INSTANCE;
                }
            }

            {
                super(1);
            }

            @Override // kotlin.jvm.functions.Function1
            public /* bridge */ /* synthetic */ Unit invoke(List<? extends DownloadListBean> list) {
                invoke2(list);
                return Unit.INSTANCE;
            }

            /* renamed from: invoke, reason: avoid collision after fix types in other method */
            public final void invoke2(@Nullable List<? extends DownloadListBean> list) {
                C3109w0 c3109w0 = C3109w0.f8471c;
                C3079m0 c3079m0 = C3079m0.f8432c;
                C2354n.m2435U0(c3109w0, C3079m0.f8431b, 0, new C37521(ListFragment.this, list, null), 2, null);
            }
        }, new Function1<Exception, Unit>() { // from class: com.jbzd.media.movecartoons.ui.download.ListFragment$request$3
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
                ListFragment.this.didRequestError();
            }
        }, true, false, null, false, 448);
    }

    public final void select(boolean value) {
        List<DownloadListBean> data = getAdapter().getData();
        ArrayList arrayList = new ArrayList(CollectionsKt__IterablesKt.collectionSizeOrDefault(data, 10));
        for (DownloadListBean downloadListBean : data) {
            downloadListBean.isSelect = value;
            arrayList.add(downloadListBean);
        }
        getAdapter().notifyDataSetChanged();
    }

    /* JADX WARN: Failed to restore switch over string. Please report as a decompilation issue
    java.lang.NullPointerException: Cannot invoke "java.util.List.iterator()" because the return value of "jadx.core.dex.visitors.regions.SwitchOverStringVisitor$SwitchData.getNewCases()" is null
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.restoreSwitchOverString(SwitchOverStringVisitor.java:109)
    	at jadx.core.dex.visitors.regions.SwitchOverStringVisitor.visitRegion(SwitchOverStringVisitor.java:66)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:77)
    	at jadx.core.dex.visitors.regions.DepthRegionTraversal.traverseIterativeStepInternal(DepthRegionTraversal.java:82)
     */
    /* renamed from: bindConvert, reason: avoid collision after fix types in other method */
    public void bindConvert2(@NotNull BaseViewHolder helper, @NotNull DownloadListBean item, @NotNull List<? extends Object> payloads) {
        String replace$default;
        Intrinsics.checkNotNullParameter(helper, "helper");
        Intrinsics.checkNotNullParameter(item, "item");
        Intrinsics.checkNotNullParameter(payloads, "payloads");
        super.bindConvert(helper, (BaseViewHolder) item, payloads);
        Iterator<? extends Object> it = payloads.iterator();
        while (it.hasNext()) {
            int intValue = ((Integer) it.next()).intValue();
            if (intValue == getTOTAL()) {
                int i2 = R.drawable.btn_pink_download;
                String str = item.downloadStatus;
                String str2 = "重新下载";
                String str3 = "#ffffff";
                if (str != null) {
                    switch (str.hashCode()) {
                        case -1402931637:
                            if (str.equals("completed")) {
                                i2 = R.drawable.btn_white_download;
                                str2 = "立即播放";
                                str3 = "#ffff005a";
                                break;
                            }
                            break;
                        case 3641717:
                            if (str.equals("wait")) {
                                str2 = "等待中...";
                                i2 = R.drawable.btn_gray_download;
                                break;
                            }
                            break;
                        case 95763319:
                            if (str.equals("doing")) {
                                str2 = Intrinsics.stringPlus("下载进度", getPercentFormat(item.downloadSuccessCount / item.downloadTotal, 2, 1));
                                i2 = R.drawable.btn_gray_download;
                                break;
                            }
                            break;
                        case 96784904:
                            str.equals("error");
                            break;
                    }
                }
                helper.m3919i(R.id.btn_status_left, str2);
                helper.m3915e(R.id.btn_status_left, i2);
                helper.m3919i(R.id.tvDownload, str2);
                String percentFormat = getPercentFormat(item.downloadSuccessCount / item.downloadTotal, 2, 1);
                String obj = (percentFormat == null || (replace$default = StringsKt__StringsJVMKt.replace$default(percentFormat, "%", " ", false, 4, (Object) null)) == null) ? null : StringsKt__StringsKt.trim((CharSequence) replace$default).toString();
                Integer valueOf = obj != null ? Integer.valueOf((int) Float.parseFloat(obj)) : null;
                if (valueOf != null) {
                    ((ProgressBar) helper.m3912b(R.id.pb_progress_download)).setProgress(valueOf.intValue());
                }
                helper.m3920j(R.id.btn_status_left, Color.parseColor(str3));
            } else if (intValue == getSELECTED()) {
                ((ImageView) helper.m3912b(R.id.iv_edit)).setSelected(item.isSelect);
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
    /* JADX WARN: Removed duplicated region for block: B:25:0x012b  */
    /* JADX WARN: Removed duplicated region for block: B:28:? A[RETURN, SYNTHETIC] */
    @Override // com.jbzd.media.movecartoons.core.BaseListFragment
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct add '--show-bad-code' argument
    */
    public void bindItem(@org.jetbrains.annotations.NotNull com.chad.library.adapter.base.viewholder.BaseViewHolder r13, @org.jetbrains.annotations.NotNull final com.jbzd.media.movecartoons.bean.response.DownloadListBean r14) {
        /*
            Method dump skipped, instructions count: 330
            To view this dump add '--comments-level debug' option
        */
        throw new UnsupportedOperationException("Method not decompiled: com.jbzd.media.movecartoons.p396ui.download.ListFragment.bindItem(com.chad.library.adapter.base.viewholder.BaseViewHolder, com.jbzd.media.movecartoons.bean.response.DownloadListBean):void");
    }
}
